from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from .config import ScanConfig
from .db import DatabaseManager
from .models import HostMetadata, PortRecord
from .nmap_runner import NmapRunner

logger = logging.getLogger(__name__)


class AutoscanManager:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.database = DatabaseManager(config.db_path)
        self.nmap = NmapRunner(
            speed_profile=config.speed_profile,
            use_ping=config.use_ping,
            report_dir=config.report_base,
            include_default_scripts=config.include_default_scripts,
            vulners_level=config.vulners_level,
        )

    def run(self) -> None:
        try:
            pending = self.database.filter_pending_targets(self.config.targets, self.config.force_rescan)
            if not pending:
                logger.info("No hay hosts pendientes de escanear.")
                return

            logger.info("Hosts pendientes: %s", ", ".join(pending))
            workers = max(self.config.workers, 1)

            if workers == 1:
                for target in pending:
                    self._scan_wrapper(target)
            else:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {pool.submit(self._scan_wrapper, target): target for target in pending}
                    for future in as_completed(futures):
                        target = futures[future]
                        try:
                            future.result()
                        except Exception as exc:
                            logger.error("Error no controlado en %s: %s", target, exc)
        finally:
            self.database.close()

    def _scan_wrapper(self, target: str) -> None:
        if self._should_stop():
            logger.info("Senal de parada recibida. Saltando %s", target)
            return

        host_id = self.database.ensure_host(target)
        self.database.mark_host_started(host_id)
        metadata: Optional[HostMetadata] = None

        try:
            alive = None
            if self.config.use_ping:
                alive = self.nmap.ping_scan(target)
                self.database.update_host_alive(host_id, alive)
                if alive is False:
                    logger.info("[%s] Host inalcanzable. Registrado y omitido.", target)
                    self.database.mark_host_done(host_id, success=False, error="Host inalcanzable")
                    return

            if self._should_stop():
                logger.info("Cancelacion tras verificacion de %s", target)
                return

            open_ports = self._run_initial_scan(target)
            open_ports = self._apply_firewall_heuristic(target, open_ports)
            open_ports, top_ports_hint = self._prepare_service_plan(target, open_ports)
            if not open_ports:
                if top_ports_hint is None:
                    logger.info("[%s] Sin puertos abiertos detectados.", target)
                    self.database.replace_ports(host_id, [])
                    self.database.mark_host_done(host_id, success=True)
                    self._log_host_summary(target, metadata, [])
                    return
                else:
                    logger.info("[%s] Sin puertos concretos tras heuristicas; se usara top-%d en el escaneo de servicios.", target, top_ports_hint)

            if self._should_stop():
                logger.info("Cancelacion antes de servicio profundo en %s", target)
                return
            ports_info, metadata = self._run_service_scan(target, open_ports, host_id, top_ports_hint)

            self.database.replace_ports(host_id, ports_info)
            self.database.mark_host_done(host_id, success=True)
            self._log_host_summary(target, metadata, ports_info)
            logger.info("[%s] Escaneo completado (%d servicios analizados).", target, len(ports_info))
        except Exception as exc:
            logger.exception("[%s] Fallo el escaneo: %s", target, exc)
            self.database.mark_host_done(host_id, success=False, error=str(exc))

    def _run_initial_scan(self, target: str) -> List[int]:
        logger.info("[%s] Iniciando escaneo de puertos completos.", target)
        open_ports, outputs = self.nmap.initial_scan(target)
        try:
            if open_ports:
                if len(open_ports) > 50:
                    preview = ", ".join(str(p) for p in open_ports[:50])
                    logger.info(
                        "[%s] Puertos abiertos: %s, ... (+%d adicionales)",
                        target,
                        preview,
                        len(open_ports) - 50,
                    )
                else:
                    logger.info("[%s] Puertos abiertos: %s", target, ", ".join(map(str, open_ports)))
            else:
                logger.info("[%s] Puertos abiertos: ninguno", target)
            return open_ports
        finally:
            if self.config.report_base is None:
                self.nmap.cleanup_outputs(outputs)

    def _run_service_scan(
        self,
        target: str,
        ports: List[int],
        host_id: int,
        top_ports_hint: Optional[int],
    ) -> tuple[List[PortRecord], Optional[HostMetadata]]:
        if top_ports_hint is not None:
            logger.warning(
                "[%s] Se ejecutara escaneo detallado usando --top-ports %d debido a deteccion de puertos consecutivos.",
                target,
                top_ports_hint,
            )
        logger.info("[%s] Escaneo detallado (servicios/vulnerabilidades).", target)
        ports_info, metadata, outputs = self.nmap.service_scan(target, ports, top_ports_hint)
        try:
            if metadata:
                self.database.store_host_metadata(host_id, metadata)
            return ports_info, metadata
        finally:
            if self.config.report_base is None:
                self.nmap.cleanup_outputs(outputs)

    def _should_stop(self) -> bool:
        return self.config.stop_event is not None and self.config.stop_event.is_set()

    def _log_host_summary(
        self,
        target: str,
        metadata: Optional[HostMetadata],
        ports: List[PortRecord],
    ) -> None:
        logger.info("[%s] ===== Resumen =====", target)

        if metadata:
            os_parts: List[str] = []
            if metadata.os_name:
                os_parts.append(metadata.os_name)
            if metadata.os_vendor and metadata.os_vendor not in os_parts:
                os_parts.append(metadata.os_vendor)
            if metadata.os_accuracy is not None:
                os_parts.append(f"{metadata.os_accuracy}% confianza")
            os_description = " | ".join(os_parts) if os_parts else "Desconocido"
        else:
            os_description = "Desconocido"

        logger.info("[%s] Sistema operativo: %s", target, os_description)

        if ports:
            logger.info("[%s] Servicios detectados:", target)
            for record in ports:
                label = record.service or record.product or "desconocido"
                version_parts = [part for part in (record.product, record.version) if part]
                if not version_parts and record.banner:
                    version_parts.append(record.banner)
                version_label = " ".join(version_parts) if version_parts else "sin version"
                logger.info(
                    "[%s]   - %d/%s %s (%s)",
                    target,
                    record.port,
                    record.protocol,
                    label,
                    version_label,
                )
        else:
            logger.info("[%s] Servicios detectados: ninguno", target)

    def _apply_firewall_heuristic(self, target: str, ports: List[int]) -> List[int]:
        firewall_patterns = [
            {21, 53, 554, 1723},
            {21, 554, 1723},
        ]
        port_set = set(ports)
        for pattern in firewall_patterns:
            if pattern.issubset(port_set):
                logger.info(
                    "[%s] Patron de firewall detectado (puertos %s). Se descartaran de la fase de servicios.",
                    target,
                    ", ".join(str(p) for p in sorted(pattern)),
                )
                filtered = [port for port in ports if port not in pattern]
                if not filtered:
                    logger.info("[%s] Solo quedaron puertos filtrados; no se ejecutara escaneo de servicios.", target)
                return filtered
        return ports

    def _prepare_service_plan(self, target: str, ports: List[int]) -> tuple[List[int], Optional[int]]:
        TOP_PORT_FALLBACK = 50
        if len(ports) >= 1000:
            logger.warning(
                "[%s] Se detectaron %d puertos abiertos. Posible respuesta defensiva; se usara fallback a top-ports %d.",
                target,
                len(ports),
                TOP_PORT_FALLBACK,
            )
            return [], TOP_PORT_FALLBACK

        consecutives = set(range(1, 21))
        if consecutives.issubset(set(ports)):
            sample = ", ".join(str(p) for p in sorted(consecutives))
            logger.warning(
                "[%s] Se detecto un bloque consecutivo de puertos bajos abiertos (%s). Se usara fallback a top-ports %d.",
                target,
                sample,
                TOP_PORT_FALLBACK,
            )
            return [], TOP_PORT_FALLBACK
        return ports, None

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
            if not open_ports:
                logger.info("[%s] Sin puertos abiertos detectados.", target)
                self.database.replace_ports(host_id, [])
                self.database.mark_host_done(host_id, success=True)
                self._log_host_summary(target, metadata, [])
                return

            if self._should_stop():
                logger.info("Cancelacion antes de servicio profundo en %s", target)
                return

            ports_info, metadata = self._run_service_scan(target, open_ports, host_id)

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
            logger.info("[%s] Puertos abiertos: %s", target, ", ".join(map(str, open_ports)) or "ninguno")
            return open_ports
        finally:
            if self.config.report_base is None:
                self.nmap.cleanup_outputs(outputs)

    def _run_service_scan(
        self,
        target: str,
        ports: List[int],
        host_id: int,
    ) -> tuple[List[PortRecord], Optional[HostMetadata]]:
        logger.info("[%s] Escaneo detallado (servicios/vulnerabilidades).", target)
        ports_info, metadata, outputs = self.nmap.service_scan(target, ports)
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


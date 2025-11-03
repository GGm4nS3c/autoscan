from __future__ import annotations

import logging
import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from .config import SpeedProfile
from .parsers import extract_host_status, extract_open_ports, parse_service_scan
from .models import HostMetadata, PortRecord
from .utils import sanitize_filename

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ScanOutputs:
    base_path: Path
    xml_path: Path
    gnmap_path: Path
    nmap_path: Path


def _create_output_paths(base: Optional[Path], prefix: str) -> ScanOutputs:
    if base is None:
        temp_dir = Path(tempfile.mkdtemp(prefix="autoscan-"))
        base = temp_dir / prefix
    else:
        base.parent.mkdir(parents=True, exist_ok=True)
    return ScanOutputs(
        base_path=base,
        xml_path=base.with_suffix(".xml"),
        gnmap_path=base.with_suffix(".gnmap"),
        nmap_path=base.with_suffix(".nmap"),
    )


def _supports_syn_scan() -> bool:
    if os.name == "nt":
        return False
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


class NmapRunner:
    def __init__(
        self,
        speed_profile: SpeedProfile,
        use_ping: bool,
        report_dir: Optional[Path],
        include_default_scripts: bool,
        vulners_level: Optional[str],
    ) -> None:
        self.speed_profile = speed_profile
        self.use_ping = use_ping
        self.report_dir = report_dir
        self.include_default_scripts = include_default_scripts
        self.vulners_level = vulners_level
        self._syn_scan_supported = _supports_syn_scan()

    def _run(self, args: Sequence[str]) -> subprocess.CompletedProcess:
        command = ["nmap", *args]
        logger.info("Nmap cmd: %s", " ".join(shlex.quote(part) for part in command))
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.error("Error ejecutando nmap (%s): %s", result.returncode, result.stderr.strip())
            raise subprocess.CalledProcessError(
                result.returncode, command, output=result.stdout, stderr=result.stderr
            )
        if result.stderr:
            logger.debug("STDERR nmap: %s", result.stderr.strip())
        return result

    def _base_timing_args(self) -> List[str]:
        args = [f"-T{self.speed_profile.timing_template}"]
        if self.speed_profile.min_rate:
            args.extend(["--min-rate", str(self.speed_profile.min_rate)])
        if self.speed_profile.max_retries is not None:
            args.extend(["--max-retries", str(self.speed_profile.max_retries)])
        return args

    def ping_scan(self, target: str) -> Optional[bool]:
        safe = sanitize_filename(target)
        outputs = _create_output_paths(
            self._stage_base_dir(target, "host-discovery") if self.report_dir else None,
            f"{safe}_ping",
        )
        args = [
            "-sn",
            "-oA",
            str(outputs.base_path),
            target,
        ]
        try:
            self._run(args)
        except subprocess.CalledProcessError as exc:
            logger.warning("Ping scan falló para %s (%s)", target, exc)
            return None

        try:
            return extract_host_status(outputs.xml_path)
        finally:
            self._cleanup_temp(outputs)

    def initial_scan(self, target: str) -> tuple[List[int], ScanOutputs]:
        safe = sanitize_filename(target)
        outputs = _create_output_paths(
            self._stage_base_dir(target, "initial") if self.report_dir else None,
            f"{safe}_initial",
        )
        args = [
            "-p-",
            "-n",
            "-oA",
            str(outputs.base_path),
            *self._base_timing_args(),
        ]
        if self._syn_scan_supported:
            args.append("-sS")
        else:
            args.append("-sT")
        if not self.use_ping:
            args.append("-Pn")
        args.append(target)

        try:
            self._run(args)
        except subprocess.CalledProcessError as exc:
            if self._syn_scan_supported and "requires root privileges" in (exc.stderr or ""):
                logger.info("Sin privilegios para -sS, reintentando con -sT")
                self._syn_scan_supported = False
                return self.initial_scan(target)
            raise

        open_ports = extract_open_ports(outputs.xml_path)
        return open_ports, outputs

    def service_scan(self, target: str, ports: Iterable[int]) -> tuple[List[PortRecord], Optional[HostMetadata], ScanOutputs]:
        safe = sanitize_filename(target)
        outputs = _create_output_paths(
            self._stage_base_dir(target, "service") if self.report_dir else None,
            f"{safe}_service",
        )
        port_arg = ",".join(str(p) for p in sorted(set(ports)))
        args: List[str] = [
            "-sV",
            "-O",
            "-n",
            "-p",
            port_arg,
            "-oA",
            str(outputs.base_path),
            *self._base_timing_args(),
            "-Pn",
        ]

        scripts: List[str] = []
        script_args: List[str] = []

        if self.include_default_scripts:
            scripts.extend(["default", "vuln"])

        if self.vulners_level:
            scripts.append("vulners")
            script_args.append(f"vulners.mincvss={self._map_vulners_level(self.vulners_level)}")

        if scripts:
            args.append(f"--script={','.join(scripts)}")
        if script_args:
            args.append(f"--script-args={','.join(script_args)}")

        args.append(target)

        try:
            self._run(args)
        except subprocess.CalledProcessError as exc:
            if "-O" in args and self._is_privilege_error(exc.stderr):
                logger.warning("Sin privilegios para deteccion de OS. Reintentando sin '-O'.")
                fallback_args = [part for part in args if part != "-O"]
                self._run(fallback_args)
            else:
                raise
        ports_info, metadata = parse_service_scan(outputs.xml_path)
        return ports_info, metadata, outputs

    def _cleanup_temp(self, outputs: ScanOutputs) -> None:
        if self.report_dir is not None:
            return
        try:
            for path in (outputs.xml_path, outputs.gnmap_path, outputs.nmap_path):
                if path.exists():
                    path.unlink()
            temp_dir = outputs.base_path.parent
            if temp_dir.exists():
                temp_dir.rmdir()
        except OSError as exc:
            logger.debug("No se pudo eliminar temporal: %s", exc)

    def cleanup_outputs(self, outputs: ScanOutputs) -> None:
        self._cleanup_temp(outputs)

    def _stage_base_dir(self, target: str, stage: str) -> Path:
        assert self.report_dir is not None
        safe_target = sanitize_filename(target)
        host_dir = self.report_dir / safe_target
        host_dir.mkdir(parents=True, exist_ok=True)
        return host_dir / stage

    @staticmethod
    def _map_vulners_level(level: str) -> str:
        mapping = {
            "high": "8.0",
            "medium": "5.0",
            "low": "1.0",
        }
        return mapping.get(level, "8.0")

    @staticmethod
    def _is_privilege_error(stderr: Optional[str]) -> bool:
        if not stderr:
            return False
        lowered = stderr.lower()
        return "requires root privileges" in lowered or "privileges are required" in lowered

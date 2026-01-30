from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Sequence

from .config import ExportConfig, ScanConfig, SpeedProfile
from .scanner import AutoscanManager
from .reporting import export_results
from .utils import (
    DEFAULT_DB_PATH,
    configure_logging,
    check_vulners_api,
    derive_report_path,
    format_exception,
    load_targets_from_file,
    print_banner,
    setup_interrupt_handling,
)
from .toml_config import load_scan_config, load_db_config
from . import __version__

logger = logging.getLogger("autoscan.cli")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autoscan",
        description="Automatiza escaneos con Nmap con reanudación y reporting.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Ejecuta escaneos sobre uno o más anfitriones.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    scan_parser.add_argument(
        "-H",
        "--host",
        dest="host",
        help="Hostname o IP objetivo.",
    )
    scan_parser.add_argument(
        "-lh",
        "--list-hosts",
        dest="list_hosts",
        help="Archivo de texto con hostnames/IP (uno por línea).",
    )
    scan_parser.add_argument(
        "--vul",
        nargs="?",
        const="high",
        choices=["high", "medium", "low"],
        default=None,
        help="Activa escaneo con vulners y establece el umbral CVSS mínimo (por defecto high).",
    )
    scan_parser.add_argument(
        "--slow",
        action="store_true",
        help="Reduce agresividad (T2).",
    )
    scan_parser.add_argument(
        "--fast",
        action="store_true",
        help="Incrementa agresividad (T5).",
    )
    scan_parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=None,
        help="Cantidad de hosts a procesar en paralelo.",
    )
    scan_parser.add_argument(
        "--report",
        nargs="?",
        const="",
        default=None,
        help=(
            "Genera carpeta de reportes (-oA). "
            "Por defecto usa el nombre del archivo de lista o del host."
        ),
    )
    scan_parser.add_argument(
        "--db-path",
        default=None,
        help="Ruta a la base SQLite donde se almacenan resultados.",
    )
    scan_parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Omite fase previa de verificacion de host vivo (usa -Pn siempre).",
    )
    scan_parser.add_argument(
        "--force",
        action="store_true",
        help="Repite escaneo aun si el host figura como completado en la base.",
    )
    scan_parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default=None,
        help="Nivel de log.",
    )
    scan_parser.add_argument(
        "--scan-config",
        default=None,
        help="Ruta a archivo scan.toml (opcional).",
    )
    scan_subparsers = scan_parser.add_subparsers(dest="scan_command")
    discovery_parser = scan_subparsers.add_parser(
        "discovery",
        help="Ejecuta descubrimiento tcp/udp/full usando defaults del scan.toml.",
    )
    discovery_parser.add_argument(
        "scan_mode",
        choices=["tcp", "udp", "full"],
        help="Tipo de escaneo a realizar.",
    )
    discovery_parser.add_argument(
        "vul_keyword",
        nargs="?",
        choices=["vul"],
        help="Activa vulners con umbral default (high).",
    )
    discovery_parser.add_argument(
        "vul_level",
        nargs="?",
        choices=["high", "medium", "low"],
        help="Nivel de CVSS minimo para vulners (high/medium/low).",
    )

    db_parser = subparsers.add_parser(
        "db",
        help="Gestiona exportaciones y operaciones de base de datos.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    db_subparsers = db_parser.add_subparsers(dest="db_command", required=True)
    db_export_parser = db_subparsers.add_parser(
        "export",
        help="Exporta resultados de la base.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    db_export_parser.add_argument(
        "--host",
        action="append",
        help="Host/IP objetivo (puede repetirse o separar por comas).",
    )
    db_export_parser.add_argument(
        "--mode",
        choices=["full", "min"],
        default=None,
        help="Modo de exportacion (full o min).",
    )
    db_export_parser.add_argument(
        "--format",
        choices=["csv", "json", "xlsx"],
        required=True,
        help="Formato de exportación.",
    )
    db_export_parser.add_argument(
        "--output",
        required=True,
        help="Archivo de salida a generar.",
    )
    db_export_parser.add_argument(
        "--db-path",
        default=None,
        help="Ruta a la base SQLite.",
    )
    db_export_parser.add_argument(
        "--db-config",
        default=None,
        help="Ruta a archivo db.toml (opcional).",
    )

    export_parser = subparsers.add_parser(
        "export",
        help="Extrae resultados de la base a CSV/JSON/XLSX (legacy).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    export_parser.add_argument(
        "--format",
        choices=["csv", "json", "xlsx"],
        required=True,
        help="Formato de exportación.",
    )
    export_parser.add_argument(
        "--output",
        required=True,
        help="Archivo de salida a generar.",
    )
    export_parser.add_argument(
        "--db-path",
        default=None,
        help="Ruta a la base SQLite.",
    )
    export_parser.add_argument(
        "--no-vul",
        action="store_true",
        help="Excluye columnas de vulnerabilidades en la exportacion.",
    )
    export_parser.add_argument(
        "--db-config",
        default=None,
        help="Ruta a archivo db.toml (opcional).",
    )

    return parser


def _choose_speed_profile(
    slow: bool,
    fast: bool,
    timing_template: int | None,
    min_rate: int | None,
    max_retries: int | None,
) -> SpeedProfile:
    if slow and fast:
        raise ValueError("Las opciones --slow y --fast son mutuamente excluyentes.")

    if fast:
        return SpeedProfile(name="fast", timing_template=5, min_rate=2000, max_retries=2)
    if slow:
        return SpeedProfile(name="slow", timing_template=2, min_rate=200, max_retries=6)
    if timing_template is None:
        timing_template = 3
    if min_rate is None:
        min_rate = 1000
    if max_retries is None:
        max_retries = 4
    return SpeedProfile(name="default", timing_template=timing_template, min_rate=min_rate, max_retries=max_retries)


def _gather_targets(host: str | None, list_path: str | None) -> Sequence[str]:
    targets: List[str] = []
    seen = set()
    if host:
        clean = host.strip()
        if clean:
            targets.append(clean)
            seen.add(clean)
    if list_path:
        for entry in load_targets_from_file(Path(list_path)):
            if entry not in seen:
                targets.append(entry)
                seen.add(entry)
    return targets


def _parse_export_targets(host_values: List[str] | None) -> List[str]:
    if not host_values:
        return []
    targets: List[str] = []
    seen = set()
    for raw in host_values:
        for part in raw.split(","):
            clean = part.strip()
            if clean and clean not in seen:
                targets.append(clean)
                seen.add(clean)
    return targets


def _confirm_stop() -> bool:
    try:
        answer = input("[?] Desea detener el escaneo? [y/N]: ").strip().lower()
    except EOFError:
        return True
    except KeyboardInterrupt:
        return True
    return answer in {"y", "yes", "s", "si"}


def run_scan(args: argparse.Namespace) -> int:
    scan_cfg = load_scan_config(Path(args.scan_config).expanduser()) if args.scan_config else load_scan_config(Path("scan.toml"))
    log_level = args.log_level or scan_cfg.get("log_level", "info")
    log_file = scan_cfg.get("log_file", "run.log")
    configure_logging(log_level, Path(log_file) if log_file else None)
    print_banner()
    logger.info("Autoscan Discovery Engine v%s", __version__)

    try:
        speed_profile = _choose_speed_profile(
            args.slow,
            args.fast,
            scan_cfg.get("speed", {}).get("timing_template"),
            scan_cfg.get("speed", {}).get("min_rate"),
            scan_cfg.get("speed", {}).get("max_retries"),
        )
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.scan_command == "discovery":
        if args.vul_keyword and not args.vul:
            default_vul = scan_cfg.get("vul_level", "high")
            args.vul = args.vul_level or default_vul

    list_path_used = args.list_hosts
    targets = _gather_targets(args.host, args.list_hosts)
    if not targets:
        default_hosts = Path("hosts.txt")
        if default_hosts.exists():
            list_path_used = str(default_hosts)
            targets = _gather_targets(None, list_path_used)
            logger.info("Usando archivo por defecto: %s", list_path_used)
        else:
            print("[!] Debe especificarse un --host o --list-hosts (o crear hosts.txt).", file=sys.stderr)
            return 2

    report_base = derive_report_path(args.report, list_path_used, args.host)
    if report_base is None:
        report_dir = scan_cfg.get("report_dir")
        if report_dir:
            report_base = Path(report_dir).expanduser()
    if report_base:
        report_base.mkdir(parents=True, exist_ok=True)

    stop_event = setup_interrupt_handling()

    if args.vul:
        ok, detail = check_vulners_api()
        if ok:
            logger.info("Vulners API accesible (%s).", detail)
        else:
            logger.error("Vulners API no responde (%s).", detail)
            logger.warning("No se obtendran resultados de vulners, pero el escaneo continuara.")

    force_rescan = args.force or (scan_cfg.get("resume") is False)
    scan_type = scan_cfg.get("scan_type", "tcp")
    if args.scan_command == "discovery":
        scan_type = args.scan_mode
    if scan_type not in {"tcp", "udp", "full"}:
        logger.warning("scan_type desconocido '%s', usando tcp.", scan_type)
        scan_type = "tcp"

    workers = args.workers if args.workers is not None else int(scan_cfg.get("workers", 1))
    use_ping = False if args.no_ping else bool(scan_cfg.get("use_ping", True))
    db_path = Path(args.db_path).expanduser() if args.db_path else Path(scan_cfg.get("db_path", DEFAULT_DB_PATH)).expanduser()

    config = ScanConfig(
        targets=targets,
        workers=max(workers, 1),
        speed_profile=speed_profile,
        vulners_level=args.vul,
        use_ping=use_ping,
        report_base=report_base,
        db_path=db_path,
        force_rescan=force_rescan,
        slow_mode=args.slow,
        fast_mode=args.fast,
        scan_type=scan_type,
        stop_event=stop_event,
    )

    while True:
        manager = AutoscanManager(config)
        try:
            manager.run()
            break
        except KeyboardInterrupt:
            if config.stop_event is None:
                print("\n[!] Interrupcion recibida. Finalizando.", file=sys.stderr)
                return 1
            if _confirm_stop():
                logger.info("Escaneo detenido a peticion del usuario.")
                break
            logger.info("Continuando escaneo tras la interrupcion.")
            config.stop_event.clear()
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[!] Error inesperado: {format_exception(exc)}", file=sys.stderr)
            return 1

    return 0


def run_export(args: argparse.Namespace) -> int:
    db_cfg = load_db_config(Path(args.db_config).expanduser()) if args.db_config else load_db_config(Path("db.toml"))
    log_file = db_cfg.get("log_file", "run.log")
    configure_logging("info", Path(log_file) if log_file else None)
    db_path = Path(args.db_path).expanduser() if args.db_path else Path(db_cfg.get("db_path", DEFAULT_DB_PATH)).expanduser()
    cfg = ExportConfig(
        db_path=db_path,
        output_path=Path(args.output).expanduser(),
        fmt=args.format,
        no_vul=args.no_vul or bool(db_cfg.get("no_vul", False)),
        mode="full",
    )
    try:
        export_results(cfg)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[!] Error exportando resultados: {format_exception(exc)}", file=sys.stderr)
        return 1
    return 0


def run_db_export(args: argparse.Namespace) -> int:
    db_cfg = load_db_config(Path(args.db_config).expanduser()) if args.db_config else load_db_config(Path("db.toml"))
    log_file = db_cfg.get("log_file", "run.log")
    configure_logging("info", Path(log_file) if log_file else None)
    db_path = Path(args.db_path).expanduser() if args.db_path else Path(db_cfg.get("db_path", DEFAULT_DB_PATH)).expanduser()
    mode = args.mode or db_cfg.get("export_mode", "full")
    if mode not in {"full", "min"}:
        print(f"[!] Modo de exportacion invalido: {mode}", file=sys.stderr)
        return 2
    targets = _parse_export_targets(args.host)
    cfg = ExportConfig(
        db_path=db_path,
        output_path=Path(args.output).expanduser(),
        fmt=args.format,
        mode=mode,
        hosts=targets or None,
    )
    try:
        export_results(cfg)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[!] Error exportando resultados: {format_exception(exc)}", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)
    if args.command == "export":
        return run_export(args)
    if args.command == "db":
        if args.db_command == "export":
            return run_db_export(args)

    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

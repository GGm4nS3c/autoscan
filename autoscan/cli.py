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
    derive_report_path,
    format_exception,
    load_targets_from_file,
    setup_interrupt_handling,
)

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
        default=1,
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
        default=str(DEFAULT_DB_PATH),
        help="Ruta a la base SQLite donde se almacenan resultados.",
    )
    scan_parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Omite fase previa de verificación de host vivo (usa -Pn siempre).",
    )
    scan_parser.add_argument(
        "--force",
        action="store_true",
        help="Repite escaneo aun si el host figura como completado en la base.",
    )
    scan_parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default="info",
        help="Nivel de log.",
    )

    export_parser = subparsers.add_parser(
        "export",
        help="Extrae resultados de la base a CSV/JSON/XLSX.",
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
        default=str(DEFAULT_DB_PATH),
        help="Ruta a la base SQLite.",
    )

    return parser


def _choose_speed_profile(slow: bool, fast: bool) -> SpeedProfile:
    if slow and fast:
        raise ValueError("Las opciones --slow y --fast son mutuamente excluyentes.")

    if fast:
        return SpeedProfile(name="fast", timing_template=5, min_rate=2000, max_retries=2)
    if slow:
        return SpeedProfile(name="slow", timing_template=2, min_rate=200, max_retries=6)
    return SpeedProfile(name="default", timing_template=3, min_rate=1000, max_retries=4)


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


def _confirm_stop() -> bool:
    try:
        answer = input("[?] Desea detener el escaneo? [y/N]: ").strip().lower()
    except EOFError:
        return True
    except KeyboardInterrupt:
        return True
    return answer in {"y", "yes", "s", "si"}


def run_scan(args: argparse.Namespace) -> int:
    configure_logging(args.log_level)

    try:
        speed_profile = _choose_speed_profile(args.slow, args.fast)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    targets = _gather_targets(args.host, args.list_hosts)
    if not targets:
        print("[!] Debe especificarse un --host o --list-hosts.", file=sys.stderr)
        return 2

    report_base = derive_report_path(args.report, args.list_hosts, args.host)
    if report_base:
        report_base.mkdir(parents=True, exist_ok=True)

    stop_event = setup_interrupt_handling()

    config = ScanConfig(
        targets=targets,
        workers=max(args.workers, 1),
        speed_profile=speed_profile,
        vulners_level=args.vul,
        use_ping=not args.no_ping,
        report_base=report_base,
        db_path=Path(args.db_path).expanduser(),
        force_rescan=args.force,
        slow_mode=args.slow,
        fast_mode=args.fast,
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
    configure_logging("info")
    cfg = ExportConfig(
        db_path=Path(args.db_path).expanduser(),
        output_path=Path(args.output).expanduser(),
        fmt=args.format,
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

    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

from __future__ import annotations

import logging
import signal
import sys
from pathlib import Path
from threading import Event, Lock
from typing import Iterable, List, Optional

DEFAULT_DB_PATH = Path("autoscan.db")

_INTERRUPT_LOCK = Lock()
_INTERRUPT_EVENT: Optional[Event] = None


class _ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\033[36m",
        logging.INFO: "\033[32m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[41m",
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str, datefmt: Optional[str], use_color: bool) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        if self.use_color and record.levelno in self.COLORS:
            color = self.COLORS[record.levelno]
            original_levelname = record.levelname
            record.levelname = f"{color}{original_levelname}{self.RESET}"
            try:
                return super().format(record)
            finally:
                record.levelname = original_levelname
        return super().format(record)


def configure_logging(level: str = "info") -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger()
    logger.setLevel(numeric_level)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    handler = logging.StreamHandler()
    formatter = _ColorFormatter(
        fmt="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        use_color=handler.stream.isatty(),
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def sanitize_filename(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in value)
    return safe.strip("._") or "host"


def derive_report_path(
    report_option: Optional[str],
    list_path: Optional[str],
    single_host: Optional[str],
) -> Optional[Path]:
    if report_option is None:
        return None

    if report_option:
        return Path(report_option).expanduser()

    # No valor explícito -> deducir nombre
    if list_path:
        base = Path(list_path)
        return base.parent / sanitize_filename(base.stem)
    if single_host:
        return Path(sanitize_filename(single_host))

    return Path("autoscan-report")


def load_targets_from_file(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo de hosts: {path}")

    targets: List[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handler:
        for raw in handler:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def _signal_handler(signum, frame):  # type: ignore[override]
    assert _INTERRUPT_EVENT is not None  # configurado en setup_interrupt_handling
    with _INTERRUPT_LOCK:
        if _INTERRUPT_EVENT.is_set():
            print("\n[!] Interrupcion repetida. Finalizando inmediatamente.", file=sys.stderr)
            raise KeyboardInterrupt

        _INTERRUPT_EVENT.set()
        print("\n[!] Interrupcion solicitada. Esperando confirmacion...", file=sys.stderr)
        raise KeyboardInterrupt


def setup_interrupt_handling() -> Event:
    global _INTERRUPT_EVENT
    if _INTERRUPT_EVENT is None:
        _INTERRUPT_EVENT = Event()
        signal.signal(signal.SIGINT, _signal_handler)
        siginterrupt = getattr(signal, "siginterrupt", None)
        if siginterrupt:
            siginterrupt(signal.SIGINT, False)
    return _INTERRUPT_EVENT


def format_exception(exc: BaseException) -> str:
    return f"{exc.__class__.__name__}: {exc}"

from __future__ import annotations

import logging
import signal
import sys
from pathlib import Path
from threading import Event, Lock
from typing import Iterable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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


def configure_logging(level: str = "info", log_file: Optional[Path] = None) -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger()
    logger.setLevel(numeric_level)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    console_handler = logging.StreamHandler()
    console_formatter = _ColorFormatter(
        fmt="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        use_color=console_handler.stream.isatty(),
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)


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


def print_banner(path: Optional[Path] = None) -> None:
    if not sys.stdout.isatty():
        return

    candidates = []
    if path is not None:
        candidates.append(path)
    candidates.extend(
        [
            Path("banner.ans"),
            Path("src") / "banner.ans",
            Path(__file__).resolve().parents[1] / "src" / "banner.ans",
        ]
    )

    banner_path = next((candidate for candidate in candidates if candidate.exists()), None)
    if banner_path is None:
        return

    try:
        data = banner_path.read_bytes()
    except OSError:
        return

    if not data:
        return

    sys.stdout.buffer.write(data)
    if not data.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")


def check_vulners_api(timeout: int = 5) -> tuple[bool, str]:
    url = "https://vulners.com/api/v3/search/lucene/"
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:  # nosec B310
            return True, f"HTTP {response.status}"
    except HTTPError as exc:
        return True, f"HTTP {exc.code}"
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        return False, str(reason)
    except Exception as exc:  # pragma: no cover - defensivo
        return False, str(exc)

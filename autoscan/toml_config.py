from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


def _load_toml(path: Path) -> Dict[str, Any]:
    if tomllib is None:
        raise RuntimeError("tomllib no disponible. Requiere Python 3.11+.")
    with path.open("rb") as handler:
        return tomllib.load(handler)


def load_scan_config(path: Optional[Path]) -> Dict[str, Any]:
    if path is None or not path.exists():
        return {}
    payload = _load_toml(path)
    return payload.get("scan", {})


def load_db_config(path: Optional[Path]) -> Dict[str, Any]:
    if path is None or not path.exists():
        return {}
    payload = _load_toml(path)
    return payload.get("db", {})


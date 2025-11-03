from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Optional, Sequence


@dataclass(slots=True)
class SpeedProfile:
    name: str
    timing_template: int
    min_rate: Optional[int]
    max_retries: Optional[int]


@dataclass(slots=True)
class ScanConfig:
    targets: Sequence[str]
    workers: int
    speed_profile: SpeedProfile
    vulners_level: Optional[str]
    use_ping: bool
    report_base: Optional[Path]
    db_path: Path
    force_rescan: bool
    slow_mode: bool
    fast_mode: bool
    include_default_scripts: bool = True
    stop_event: Optional[Event] = None  # resolved at runtime


@dataclass(slots=True)
class ExportConfig:
    db_path: Path
    output_path: Path
    fmt: str

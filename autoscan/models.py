from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(slots=True)
class VulnerabilityRecord:
    identifier: str
    severity: Optional[str]
    cvss: Optional[float]
    exploit_available: Optional[bool]
    url: Optional[str]
    summary: Optional[str] = None


@dataclass(slots=True)
class PortRecord:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    reason: Optional[str] = None
    vulnerabilities: List[VulnerabilityRecord] = field(default_factory=list)


@dataclass(slots=True)
class HostMetadata:
    os_name: Optional[str] = None
    os_accuracy: Optional[int] = None
    os_vendor: Optional[str] = None


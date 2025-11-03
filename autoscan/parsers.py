from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Tuple

from .models import HostMetadata, PortRecord, VulnerabilityRecord

logger = logging.getLogger(__name__)


def _safe_float(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _categorize_cvss(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return None


def extract_host_status(xml_path: Path) -> Optional[bool]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    host = root.find("host")
    if host is None:
        return None
    status = host.find("status")
    if status is None:
        return None
    state = status.get("state")
    if state == "up":
        return True
    if state == "down":
        return False
    return None


def extract_open_ports(xml_path: Path) -> List[int]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ports: List[int] = []
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            if not portid:
                continue
            try:
                ports.append(int(portid))
            except ValueError:
                logger.debug("Puerto no numérico en %s: %s", xml_path, portid)
    return sorted(set(ports))


def _parse_vulners_table(script_elem: ET.Element) -> List[VulnerabilityRecord]:
    records: List[VulnerabilityRecord] = []
    for container in script_elem.findall("table"):
        for entry in container.findall("table"):
            vtype = entry.findtext("elem[@key='type']") or ""
            vid = entry.findtext("elem[@key='id']") or ""
            identifier = f"{vtype}:{vid}" if vtype and vid else vid or vtype
            if not identifier:
                continue
            cvss_text = entry.findtext("elem[@key='cvss']")
            cvss = _safe_float(cvss_text)
            severity = _categorize_cvss(cvss)
            url_elem = entry.findtext("elem[@key='url']")
            if not url_elem and vtype and vid:
                url_elem = f"https://vulners.com/{vtype}/{vid}"
            exploit_flag = entry.findtext("elem[@key='is_exploit']")
            exploit_available = None
            if exploit_flag is not None:
                exploit_available = exploit_flag.lower() in {"1", "true", "yes"}
            title = entry.findtext("elem[@key='title']")
            records.append(
                VulnerabilityRecord(
                    identifier=identifier,
                    severity=severity,
                    cvss=cvss,
                    exploit_available=exploit_available,
                    url=url_elem,
                    summary=title,
                )
            )
    return records


def parse_service_scan(xml_path: Path) -> Tuple[List[PortRecord], Optional[HostMetadata]]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    port_records: List[PortRecord] = []
    host_metadata: Optional[HostMetadata] = None

    for host in root.findall("host"):
        for port in host.findall("ports/port"):
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            portid = port.get("portid")
            protocol = port.get("protocol", "tcp")
            if not portid:
                continue

            service_elem = port.find("service")
            product = service_elem.get("product") if service_elem is not None else None
            version = service_elem.get("version") if service_elem is not None else None
            name = service_elem.get("name") if service_elem is not None else None
            extrainfo = service_elem.get("extrainfo") if service_elem is not None else None
            cpe_elem = service_elem.find("cpe") if service_elem is not None else None
            cpe = cpe_elem.text if cpe_elem is not None else None

            banner_components = [part for part in (product, version, extrainfo) if part]
            banner = " ".join(banner_components) if banner_components else None

            vulnerabilities: List[VulnerabilityRecord] = []
            for script_id in ("vulners", "vulscan"):
                script_elem = port.find(f"script[@id='{script_id}']")
                if script_elem is None:
                    continue
                vulnerabilities.extend(_parse_vulners_table(script_elem))

            port_records.append(
                PortRecord(
                    port=int(portid),
                    protocol=protocol,
                    state=state_elem.get("state", ""),
                    service=name,
                    product=product,
                    version=version,
                    banner=banner,
                    cpe=cpe,
                    reason=state_elem.get("reason"),
                    vulnerabilities=vulnerabilities,
                )
            )

        if host_metadata is None:
            os_elem = host.find("os")
            if os_elem is not None:
                best_match = None
                best_accuracy = -1
                for match in os_elem.findall("osmatch"):
                    try:
                        accuracy = int(match.get("accuracy", "0"))
                    except ValueError:
                        accuracy = 0
                    if accuracy > best_accuracy:
                        best_accuracy = accuracy
                        best_match = match
                if best_match is not None:
                    osclass = best_match.find("osclass")
                    host_metadata = HostMetadata(
                        os_name=best_match.get("name"),
                        os_accuracy=int(best_match.get("accuracy", "0") or 0),
                        os_vendor=osclass.get("vendor") if osclass is not None else None,
                    )

    port_records.sort(key=lambda record: record.port)
    return port_records, host_metadata


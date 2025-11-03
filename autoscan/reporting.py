from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List
from zipfile import ZIP_DEFLATED, ZipFile

from .config import ExportConfig
from .db import DatabaseManager

logger = logging.getLogger(__name__)

HEADERS = [
    "host",
    "alive",
    "os_name",
    "os_vendor",
    "os_accuracy",
    "port",
    "protocol",
    "state",
    "service",
    "product",
    "version",
    "banner",
    "identifier",
    "severity",
    "cvss",
    "exploit_available",
    "url",
    "summary",
]


def export_results(config: ExportConfig) -> None:
    db = DatabaseManager(config.db_path)
    rows = db.fetch_export_rows()
    db.close()

    dataset = [_row_to_dict(row) for row in rows]
    output = config.output_path
    output.parent.mkdir(parents=True, exist_ok=True)

    if config.fmt == "csv":
        _write_csv(output, dataset)
    elif config.fmt == "json":
        _write_json(output, dataset)
    elif config.fmt == "xlsx":
        _write_xlsx(output, dataset)
    else:  # pragma: no cover - validaciones previas
        raise ValueError(f"Formato no soportado: {config.fmt}")

    logger.info("Reporte exportado en %s (%s filas).", output, len(dataset))


def _row_to_dict(row) -> Dict[str, str]:
    def _bool_to_str(value):
        if value is None:
            return ""
        return "yes" if int(value) else "no"

    def _format(value):
        if value is None:
            return ""
        return str(value)

    return {
        "host": _format(row["host"]),
        "alive": _bool_to_str(row["alive"]),
        "os_name": _format(row["os_name"]),
        "os_vendor": _format(row["os_vendor"]),
        "os_accuracy": _format(row["os_accuracy"]),
        "port": _format(row["port"]),
        "protocol": _format(row["protocol"]),
        "state": _format(row["state"]),
        "service": _format(row["service"]),
        "product": _format(row["product"]),
        "version": _format(row["version"]),
        "banner": _format(row["banner"]),
        "identifier": _format(row["identifier"]),
        "severity": _format(row["severity"]),
        "cvss": _format(row["cvss"]),
        "exploit_available": _bool_to_str(row["exploit_available"]),
        "url": _format(row["url"]),
        "summary": _format(row["summary"]),
    }


def _write_csv(path: Path, rows: Iterable[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handler:
        writer = csv.DictWriter(handler, fieldnames=HEADERS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_json(path: Path, rows: Iterable[Dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8") as handler:
        json.dump(list(rows), handler, ensure_ascii=False, indent=2)


def _write_xlsx(path: Path, rows: List[Dict[str, str]]) -> None:
    content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
    <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
    <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
    <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
    <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>
"""

    rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
    <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
    <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>
"""

    workbook = """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Autoscan" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>
"""

    workbook_rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>
"""

    styles = """<?xml version="1.0" encoding="UTF-8"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font></fonts>
  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>
"""

    timestamp = datetime.utcnow().isoformat()
    core = f"""<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/"
                   xmlns:dcmitype="http://purl.org/dc/dcmitype/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dcterms:created xsi:type="dcterms:W3CDTF">{timestamp}</dcterms:created>
  <dc:creator>autoscan</dc:creator>
  <cp:lastModifiedBy>autoscan</cp:lastModifiedBy>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{timestamp}</dcterms:modified>
</cp:coreProperties>
"""

    app = """<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
            xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>autoscan</Application>
  <DocSecurity>0</DocSecurity>
  <ScaleCrop>false</ScaleCrop>
  <Company></Company>
</Properties>
"""

    sheet_xml = _build_sheet_xml(rows)

    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        archive.writestr("xl/styles.xml", styles)
        archive.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        archive.writestr("docProps/core.xml", core)
        archive.writestr("docProps/app.xml", app)


def _build_sheet_xml(rows: List[Dict[str, str]]) -> str:
    def column_letter(index: int) -> str:
        result = ""
        while index:
            index, remainder = divmod(index - 1, 26)
            result = chr(65 + remainder) + result
        return result

    def escape(value: str) -> str:
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    rows_xml = []

    header_cells = []
    for idx, header in enumerate(HEADERS, start=1):
        cell_ref = f"{column_letter(idx)}1"
        header_cells.append(
            f'<c r="{cell_ref}" t="inlineStr"><is><t>{escape(header)}</t></is></c>'
        )
    rows_xml.append(f"<row r=\"1\">{''.join(header_cells)}</row>")

    for row_index, row in enumerate(rows, start=2):
        cells = []
        for col_index, header in enumerate(HEADERS, start=1):
            value = row.get(header, "") or ""
            cell_ref = f"{column_letter(col_index)}{row_index}"
            cells.append(
                f'<c r="{cell_ref}" t="inlineStr"><is><t>{escape(value)}</t></is></c>'
            )
        rows_xml.append(f'<row r="{row_index}">{"".join(cells)}</row>')

    sheet = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>"
        f"{''.join(rows_xml)}"
        "</sheetData>"
        "</worksheet>"
    )
    return sheet


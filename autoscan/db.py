from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Iterable, List, Optional, Sequence, Tuple

from .models import HostMetadata, PortRecord, VulnerabilityRecord

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._initialize_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def _transaction(self):
        with self._lock:
            cursor = self._conn.cursor()
            try:
                yield cursor
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                cursor.close()

    def _initialize_schema(self) -> None:
        with self._transaction() as cur:
            cur.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL UNIQUE,
                    alive INTEGER,
                    done INTEGER NOT NULL DEFAULT 0,
                    last_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    os_name TEXT,
                    os_vendor TEXT,
                    os_accuracy INTEGER,
                    last_error TEXT
                );

                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    service TEXT,
                    product TEXT,
                    version TEXT,
                    banner TEXT,
                    cpe TEXT,
                    reason TEXT,
                    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    port_id INTEGER NOT NULL,
                    identifier TEXT NOT NULL,
                    severity TEXT,
                    cvss REAL,
                    exploit_available INTEGER,
                    url TEXT,
                    summary TEXT,
                    FOREIGN KEY(port_id) REFERENCES ports(id) ON DELETE CASCADE
                );
                """
            )

    def ensure_host(self, target: str) -> int:
        with self._transaction() as cur:
            cur.execute("SELECT id FROM hosts WHERE target = ?", (target,))
            row = cur.fetchone()
            if row:
                return row["id"]
            cur.execute("INSERT INTO hosts(target, done) VALUES(?, 0)", (target,))
            host_id = cur.lastrowid
        logger.debug("Host insertado en DB: %s (id=%s)", target, host_id)
        return host_id

    def mark_host_started(self, host_id: int) -> None:
        with self._transaction() as cur:
            cur.execute(
                """
                UPDATE hosts
                SET done = 0,
                    last_error = NULL,
                    last_scan = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (host_id,),
            )

    def mark_host_done(self, host_id: int, success: bool = True, error: Optional[str] = None) -> None:
        with self._transaction() as cur:
            cur.execute(
                """
                UPDATE hosts
                SET done = ?, last_error = ?
                WHERE id = ?
                """,
                (1 if success else 0, error, host_id),
            )

    def update_host_alive(self, host_id: int, alive: Optional[bool]) -> None:
        with self._transaction() as cur:
            cur.execute(
                "UPDATE hosts SET alive = ? WHERE id = ?",
                (None if alive is None else int(alive), host_id),
            )

    def store_host_metadata(self, host_id: int, metadata: Optional[HostMetadata]) -> None:
        if metadata is None:
            return
        with self._transaction() as cur:
            cur.execute(
                """
                UPDATE hosts
                SET os_name = ?, os_vendor = ?, os_accuracy = ?
                WHERE id = ?
                """,
                (metadata.os_name, metadata.os_vendor, metadata.os_accuracy, host_id),
            )

    def replace_ports(self, host_id: int, ports: Iterable[PortRecord]) -> None:
        ports = list(ports)
        with self._transaction() as cur:
            cur.execute("DELETE FROM vulnerabilities WHERE port_id IN (SELECT id FROM ports WHERE host_id = ?)", (host_id,))
            cur.execute("DELETE FROM ports WHERE host_id = ?", (host_id,))
            for record in ports:
                cur.execute(
                    """
                    INSERT INTO ports (
                        host_id, port, protocol, state, service, product,
                        version, banner, cpe, reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        host_id,
                        record.port,
                        record.protocol,
                        record.state,
                        record.service,
                        record.product,
                        record.version,
                        record.banner,
                        record.cpe,
                        record.reason,
                    ),
                )
                port_id = cur.lastrowid
                for vuln in record.vulnerabilities:
                    cur.execute(
                        """
                        INSERT INTO vulnerabilities (
                            port_id, identifier, severity, cvss, exploit_available, url, summary
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            port_id,
                            vuln.identifier,
                            vuln.severity,
                            vuln.cvss,
                            None if vuln.exploit_available is None else int(vuln.exploit_available),
                            vuln.url,
                            vuln.summary,
                        ),
                    )

    def filter_pending_targets(self, targets: Sequence[str], force: bool) -> List[str]:
        if force:
            for target in targets:
                self.ensure_host(target)
            return list(targets)

        placeholders = ",".join("?" for _ in targets)
        if not placeholders:
            return []

        query = f"SELECT target, done FROM hosts WHERE target IN ({placeholders})"
        with self._transaction() as cur:
            cur.execute(query, tuple(targets))
            existing = {row["target"]: row["done"] for row in cur.fetchall()}

        pending = []
        for target in targets:
            if target not in existing:
                self.ensure_host(target)
                pending.append(target)
            elif existing[target] != 1:
                pending.append(target)
        return pending

    def fetch_export_rows(self) -> List[sqlite3.Row]:
        query = """
        SELECT
            h.target AS host,
            h.os_name,
            h.os_vendor,
            h.os_accuracy,
            h.alive,
            p.port,
            p.protocol,
            p.state,
            p.service,
            p.product,
            p.version,
            p.banner,
            v.identifier,
            v.severity,
            v.cvss,
            v.exploit_available,
            v.url,
            v.summary
        FROM hosts h
        LEFT JOIN ports p ON p.host_id = h.id
        LEFT JOIN vulnerabilities v ON v.port_id = p.id
        ORDER BY h.target, p.port
        """
        with self._transaction() as cur:
            cur.execute(query)
            return cur.fetchall()


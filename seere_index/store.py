from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import ExposureRecord


class ExposureStore:
    """
    Minimal local concept store for SEERE exposure metadata.

    It intentionally stores fingerprints and metadata, never raw secret values.
    """

    def __init__(self, path: str | Path = "seere-index.db"):
        self.path = str(path)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS exposures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization TEXT NOT NULL,
                provider TEXT NOT NULL,
                kind TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_type TEXT NOT NULL,
                asset TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL,
                owner TEXT,
                UNIQUE(organization, fingerprint, source_type, asset)
            )
            """
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_exposure_org ON exposures(organization)"
        )
        self.db.commit()

    def upsert(self, record: ExposureRecord) -> None:
        self.db.execute(
            """
            INSERT INTO exposures (
                organization, provider, kind, fingerprint, severity,
                source_type, asset, first_seen, last_seen, status, owner
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(organization, fingerprint, source_type, asset)
            DO UPDATE SET
                severity=excluded.severity,
                last_seen=excluded.last_seen,
                status=excluded.status,
                owner=excluded.owner
            """,
            (
                record.organization.lower(),
                record.provider,
                record.kind,
                record.fingerprint,
                record.severity,
                record.source_type,
                record.asset,
                record.first_seen,
                record.last_seen,
                record.status,
                record.owner,
            ),
        )
        self.db.commit()

    def summary(self, organization: str) -> dict:
        rows = self.db.execute(
            """
            SELECT severity, COUNT(*) AS count
            FROM exposures
            WHERE organization = ? AND status != 'resolved'
            GROUP BY severity
            """,
            (organization.lower(),),
        ).fetchall()

        by_severity = {row["severity"]: row["count"] for row in rows}
        total = sum(by_severity.values())

        return {
            "organization": organization.lower(),
            "open_findings": total,
            "critical": by_severity.get("CRITICAL", 0),
            "high": by_severity.get("HIGH", 0),
            "medium": by_severity.get("MEDIUM", 0),
            "low": by_severity.get("LOW", 0),
        }

    def records(self, organization: str) -> list[dict]:
        rows = self.db.execute(
            """
            SELECT organization, provider, kind, fingerprint, severity,
                   source_type, asset, first_seen, last_seen, status, owner
            FROM exposures
            WHERE organization = ?
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END,
                last_seen DESC
            """,
            (organization.lower(),),
        ).fetchall()
        return [dict(row) for row in rows]

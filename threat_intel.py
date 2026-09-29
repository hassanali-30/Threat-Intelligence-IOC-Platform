#!/usr/bin/env python3
"""Local-first threat intelligence IOC collection and scoring platform.

It ingests authorized intelligence files, normalizes indicators, stores them
in SQLite, scores confidence/freshness, and correlates local events. It does
not scan, exploit, block, or contact external feeds.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import http.server
import ipaddress
import json
import re
import sqlite3
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit


TYPE_ALIASES = {
    "ip": "ip", "ipv4": "ip", "ipv4-addr": "ip", "ipv6": "ip",
    "ipv6-addr": "ip", "domain": "domain", "domain-name": "domain",
    "url": "url", "uri": "url", "hash": "hash", "file-hash": "hash",
    "sha256": "hash", "sha1": "hash", "md5": "hash", "email": "email",
    "email-addr": "email",
}
SOURCE_WEIGHTS = {"trusted": 1.0, "internal": 1.0, "community": 0.75, "unknown": 0.5}
SEVERITY_WEIGHTS = {"critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.4, "info": 0.2}
STIX_PATTERN = re.compile(r"\[(?:ipv4-addr|ipv6-addr|domain-name|url|email-addr|file):(?:value|hashes\.[A-Z0-9_-]+)\s*=\s*'([^']+)'\]", re.I)


@dataclass(frozen=True)
class IOC:
    indicator_type: str
    value: str
    source: str = "unknown"
    confidence: float = 0.5
    severity: str = "medium"
    first_seen: float | None = None
    last_seen: float | None = None
    expires_at: float | None = None
    tags: tuple[str, ...] = ()
    context: str = ""


def now() -> float:
    return time.time()


def parse_time(value: Any, default: float | None = None) -> float | None:
    if value in (None, ""):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).replace("Z", "+00:00")
    try:
        return float(text)
    except ValueError:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()


def normalize_type(value: Any) -> str:
    normalized = str(value or "").lower().replace("_", "-")
    return TYPE_ALIASES.get(normalized, normalized)


def normalize_value(indicator_type: str, value: Any) -> str:
    text = str(value or "").strip()
    if indicator_type == "ip":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return text.lower()
    if indicator_type == "domain":
        return text.lower().rstrip(".")
    if indicator_type == "url":
        parsed = urlsplit(text)
        if parsed.scheme and parsed.netloc:
            return parsed._replace(fragment="").geturl().lower()
        return text.lower()
    if indicator_type == "hash":
        return text.lower()
    if indicator_type == "email":
        return text.lower()
    return text.lower()


def normalize_row(row: dict[str, Any]) -> IOC:
    lowered = {str(key).lower(): value for key, value in row.items()}
    indicator_type = normalize_type(
        lowered.get("indicator_type", lowered.get("type", lowered.get("ioc_type", "")))
    )
    value = normalize_value(indicator_type, lowered.get("value", lowered.get("indicator", "")))
    tags = lowered.get("tags", "")
    if isinstance(tags, list):
        tag_tuple = tuple(str(tag) for tag in tags)
    else:
        tag_tuple = tuple(item.strip() for item in str(tags).split(",") if item.strip())
    confidence = float(lowered.get("confidence", 0.5) or 0.5)
    if confidence > 1:
        confidence /= 100
    return IOC(
        indicator_type=indicator_type,
        value=value,
        source=str(lowered.get("source", "unknown") or "unknown").lower(),
        confidence=max(0.0, min(1.0, confidence)),
        severity=str(lowered.get("severity", "medium") or "medium").lower(),
        first_seen=parse_time(lowered.get("first_seen"), now()),
        last_seen=parse_time(lowered.get("last_seen"), now()),
        expires_at=parse_time(lowered.get("expires_at")),
        tags=tag_tuple,
        context=str(lowered.get("context", lowered.get("description", "")) or ""),
    )


def parse_stix(data: dict[str, Any], source: str = "community") -> list[IOC]:
    result: list[IOC] = []
    for item in data.get("objects", []):
        if item.get("type") != "indicator":
            continue
        match = STIX_PATTERN.search(str(item.get("pattern", "")))
        if not match:
            continue
        raw_type = str(item["pattern"]).split(":", 1)[0].strip("[")
        result.append(IOC(
            indicator_type=normalize_type(raw_type),
            value=normalize_value(normalize_type(raw_type), match.group(1)),
            source=source,
            confidence=float(item.get("confidence", 50)) / 100,
            severity="medium",
            first_seen=parse_time(item.get("valid_from"), now()),
            expires_at=parse_time(item.get("valid_until")),
            tags=tuple(item.get("labels", [])),
            context=str(item.get("description", "")),
        ))
    return result


def load_iocs(path: str | Path) -> list[IOC]:
    file_path = Path(path)
    if file_path.suffix.lower() == ".json":
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and payload.get("type") == "bundle":
            return parse_stix(payload)
        rows = payload if isinstance(payload, list) else payload.get("iocs", [])
        return [normalize_row(row) for row in rows]
    with file_path.open(newline="", encoding="utf-8") as handle:
        return [normalize_row(row) for row in csv.DictReader(handle)]


def freshness_factor(last_seen: float | None, current: float | None = None) -> float:
    if not last_seen:
        return 0.5
    age_days = max(0.0, (current or now()) - last_seen) / 86400
    return max(0.1, 1.0 / (1.0 + age_days / 30.0))


def score_ioc(ioc: IOC, current: float | None = None) -> float:
    base = (
        SOURCE_WEIGHTS.get(ioc.source, SOURCE_WEIGHTS["unknown"])
        * max(0.0, min(1.0, ioc.confidence))
        * SEVERITY_WEIGHTS.get(ioc.severity, SEVERITY_WEIGHTS["medium"])
        * freshness_factor(ioc.last_seen, current)
    )
    return round(100 * base, 2)


def is_expired(ioc: IOC, current: float | None = None) -> bool:
    return ioc.expires_at is not None and ioc.expires_at <= (current or now())


class IOCStore:
    def __init__(self, path: str = "threat_intel.db") -> None:
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("""CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY, indicator_type TEXT NOT NULL, value TEXT NOT NULL,
            source TEXT, confidence REAL, severity TEXT, first_seen REAL,
            last_seen REAL, expires_at REAL, tags_json TEXT, context TEXT,
            score REAL, updated_at REAL, UNIQUE(indicator_type, value)
        )""")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS sightings (
            id INTEGER PRIMARY KEY, ioc_id INTEGER, seen_at REAL, event_source TEXT,
            context TEXT, FOREIGN KEY(ioc_id) REFERENCES iocs(id)
        )""")
        self.connection.commit()

    def upsert(self, ioc: IOC) -> int:
        score = score_ioc(ioc)
        self.connection.execute(
            """INSERT INTO iocs(indicator_type,value,source,confidence,severity,first_seen,
               last_seen,expires_at,tags_json,context,score,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(indicator_type,value) DO UPDATE SET
               source=excluded.source, confidence=excluded.confidence, severity=excluded.severity,
               last_seen=excluded.last_seen, expires_at=excluded.expires_at,
               tags_json=excluded.tags_json, context=excluded.context,
               score=excluded.score, updated_at=excluded.updated_at""",
            (ioc.indicator_type, ioc.value, ioc.source, ioc.confidence, ioc.severity,
             ioc.first_seen, ioc.last_seen, ioc.expires_at, json.dumps(ioc.tags),
             ioc.context, score, now()),
        )
        row = self.connection.execute(
            "SELECT id FROM iocs WHERE indicator_type=? AND value=?",
            (ioc.indicator_type, ioc.value),
        ).fetchone()
        self.connection.commit()
        return int(row["id"])

    def search(self, query: str = "", limit: int = 100) -> list[dict[str, Any]]:
        pattern = f"%{query.lower()}%"
        rows = self.connection.execute(
            """SELECT * FROM iocs WHERE lower(value) LIKE ? OR lower(indicator_type) LIKE ?
               ORDER BY score DESC LIMIT ?""", (pattern, pattern, limit)
        ).fetchall()
        return [dict(row) for row in rows]

    def correlate(self, values: Iterable[str]) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for value in values:
            rows = self.connection.execute(
                "SELECT * FROM iocs WHERE value=? ORDER BY score DESC", (normalize_value("", value),)
            ).fetchall()
            matches.extend(dict(row) for row in rows)
        return matches

    def prune_expired(self) -> int:
        cursor = self.connection.execute("DELETE FROM iocs WHERE expires_at IS NOT NULL AND expires_at <= ?", (now(),))
        self.connection.commit()
        return cursor.rowcount

    def close(self) -> None:
        self.connection.close()


class APIHandler(http.server.BaseHTTPRequestHandler):
    store: IOCStore | None = None

    def do_GET(self) -> None:
        if self.path == "/health":
            payload = {"status": "ok", "service": "threat-intelligence"}
        elif self.path.startswith("/search"):
            query = self.path.split("q=", 1)[1] if "q=" in self.path else ""
            payload = {"results": self.store.search(query) if self.store else []}
        else:
            payload = {"service": "threat-intelligence", "endpoints": ["/health", "/search?q=..."]}
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: Any) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Local IOC collection and scoring platform")
    parser.add_argument("--input", help="CSV, JSON, or STIX bundle")
    parser.add_argument("--db", default="threat_intel.db")
    parser.add_argument("--search")
    parser.add_argument("--correlate", nargs="*", help="IOC values to match")
    parser.add_argument("--prune-expired", action="store_true")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    if not any((args.input, args.search is not None, args.correlate, args.prune_expired, args.serve)):
        parser.error("Use --input, --search, --correlate, --prune-expired, or --serve")
    store = IOCStore(args.db)
    try:
        if args.input:
            for ioc in load_iocs(args.input):
                if ioc.value:
                    store.upsert(ioc)
            print(f"Imported intelligence from {args.input}")
        if args.search is not None:
            print(json.dumps(store.search(args.search), indent=2))
        if args.correlate:
            print(json.dumps(store.correlate(args.correlate), indent=2))
        if args.prune_expired:
            print(f"Removed expired indicators: {store.prune_expired()}")
        if args.serve:
            APIHandler.store = store
            server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), APIHandler)
            print(f"IOC API listening on http://127.0.0.1:{args.port}")
            server.serve_forever()
        return 0
    finally:
        if not args.serve:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())

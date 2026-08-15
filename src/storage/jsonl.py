"""Thread-safe append-only JSONL persistence for sensor output."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable

from pydantic import BaseModel


class JsonlEventStore:
    """Small append-only store used by the assessment runtime.

    The lock protects readers from observing a partially written batch inside
    this process. ``durable=True`` additionally calls ``fsync`` after every
    batch for crash-sensitive demonstrations; the default favors throughput.
    """

    SCHEMA_VERSION = 1

    def __init__(self, path: Path | str, *, durable: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.durable = durable
        self._lock = threading.RLock()

    @staticmethod
    def _body(payload: BaseModel | Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(payload, BaseModel):
            return payload.model_dump(mode="json")
        return dict(payload)

    @staticmethod
    def _validate_label(name: str, value: str) -> str:
        normalized = str(value).strip()
        if not normalized:
            raise ValueError(f"{name} must not be empty")
        return normalized

    def append(
        self,
        record_type: str,
        session_id: str,
        payload: BaseModel | Dict[str, Any],
    ) -> None:
        self.append_many([(record_type, session_id, payload)])

    def append_many(
        self,
        records: Iterable[tuple[str, str, BaseModel | Dict[str, Any]]],
    ) -> int:
        encoded: list[str] = []
        persisted_at = datetime.now(timezone.utc).isoformat()
        for record_type, session_id, payload in records:
            record = {
                "schema_version": self.SCHEMA_VERSION,
                "persisted_at": persisted_at,
                "record_type": self._validate_label("record_type", record_type),
                "session_id": self._validate_label("session_id", session_id),
                "payload": self._body(payload),
            }
            encoded.append(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        if not encoded:
            return 0

        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(encoded))
            handle.write("\n")
            handle.flush()
            if self.durable:
                os.fsync(handle.fileno())
        return len(encoded)

    def read_all(self) -> list[Dict[str, Any]]:
        with self._lock:
            if not self.path.exists():
                return []
            records: list[Dict[str, Any]] = []
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"invalid JSONL record at {self.path}:{line_number}: {exc.msg}"
                        ) from exc
                    if not isinstance(value, dict):
                        raise ValueError(
                            f"invalid JSONL record at {self.path}:{line_number}: expected object"
                        )
                    records.append(value)
            return records

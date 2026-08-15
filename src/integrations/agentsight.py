"""AgentSight report/export adapters.

The upstream AgentSight report schema can evolve. This module intentionally
normalizes semantic fields instead of binding the sensor to one JSON layout.
Every imported record keeps its original payload in metadata for auditability.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence

from pydantic import ValidationError

from src.collector.runtime import AgentSightRuntime
from src.models import (
    BaseOSEvent,
    FileAccessEvent,
    FileDeleteEvent,
    FileWriteEvent,
    LLMInteractionEvent,
    NetworkConnectionEvent,
    ProcessExecutionEvent,
    ProcessExitEvent,
    ProcessForkEvent,
)


class AgentSightIntegrationError(RuntimeError):
    """Raised when an AgentSight document or CLI operation cannot be used."""


def _decode_json_or_jsonl(text: str, source: str) -> Any:
    """Decode strict JSON first, then non-empty JSON Lines records."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as json_error:
        records: List[Any] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise AgentSightIntegrationError(
                    f"invalid JSON/JSONL at {source}:{line_number}: {exc}"
                ) from exc
        if records:
            return records
        raise AgentSightIntegrationError(f"empty or invalid AgentSight JSON from {source}") from json_error


@dataclass
class AgentSightImportResult:
    llm_events: List[LLMInteractionEvent] = field(default_factory=list)
    os_events: List[BaseOSEvent] = field(default_factory=list)
    ignored_records: int = 0
    warnings: List[str] = field(default_factory=list)

    @property
    def total_events(self) -> int:
        return len(self.llm_events) + len(self.os_events)


def _first(mapping: Dict[str, Any], names: Sequence[str], default: Any = None) -> Any:
    for name in names:
        value = mapping.get(name)
        if value is not None:
            return value
    return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _parse_timestamp(value: Any) -> datetime:
    """Parse an AgentSight timestamp without inventing event time.

    Temporal correlation is security-significant.  Missing or malformed source
    timestamps are therefore rejected and surfaced as import warnings instead
    of being replaced by ``now()``.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = float(value)
        if numeric > 1e17:  # nanoseconds since epoch
            numeric /= 1e9
        elif numeric > 1e14:  # microseconds since epoch
            numeric /= 1e6
        elif numeric > 1e11:  # milliseconds since epoch
            numeric /= 1e3
        try:
            parsed = datetime.fromtimestamp(numeric, tz=timezone.utc)
        except (OSError, OverflowError, ValueError) as exc:
            raise ValueError(f"invalid timestamp: {value!r}") from exc
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            try:
                return _parse_timestamp(float(raw))
            except ValueError as exc:
                raise ValueError(f"invalid timestamp: {value!r}") from exc
    else:
        raise ValueError("missing timestamp")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timestamp_value(record: Dict[str, Any]) -> Any:
    value = _first(
        record,
        (
            "timestamp",
            "time",
            "ts",
            "created_at",
            "started_at",
            "start_time",
            "start_timestamp",
            "timestamp_ms",
            "timestamp_us",
            "epoch_ns",
            "unix_timestamp_ns",
        ),
    )
    if value is not None:
        return value
    if "timestamp_ns" in record:
        value = record["timestamp_ns"]
        try:
            numeric = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"invalid timestamp_ns: {value!r}") from exc
        # A small timestamp_ns is normally a monotonic kernel timestamp. It
        # cannot be correlated to wall-clock LLM activity without a boot-epoch
        # mapping, so reject it rather than silently inventing a 1970 date.
        if numeric < 100_000_000_000_000_000:
            raise ValueError(
                "timestamp_ns is not a Unix-epoch nanosecond timestamp; "
                "provide an ISO/epoch timestamp or an explicit boot mapping"
            )
        return value
    return None


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: List[str] = []
        for item in value:
            if isinstance(item, dict):
                role = item.get("role")
                content = _stringify(item.get("content", item.get("text", item)))
                parts.append(f"{role}: {content}" if role else content)
            else:
                parts.append(_stringify(item))
        return "\n".join(part for part in parts if part)
    if isinstance(value, dict):
        for key in ("content", "text", "prompt", "message", "output"):
            if key in value:
                return _stringify(value[key])
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return str(value)


def _record_kind(record: Dict[str, Any]) -> str:
    value = _first(record, ("event_type", "type", "kind", "record_type", "name"), "")
    return re.sub(r"[^a-z0-9]+", "_", str(value).casefold()).strip("_")


def _session_id(record: Dict[str, Any], default: str) -> str:
    value = _first(
        record,
        ("session_id", "sessionId", "agent_session_id", "run_id", "trace_id"),
        default,
    )
    return str(value or default)


def _source_identifier(record: Dict[str, Any]) -> str:
    value = _first(record, ("event_id", "eventId", "id", "span_id", "call_id"), "")
    return str(value or "")


def _stable_event_id(prefix: str, record: Dict[str, Any]) -> str:
    source_id = _source_identifier(record)
    if source_id:
        return f"agentsight:{prefix}:{source_id}"
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:24]
    return f"agentsight:{prefix}:sha256:{digest}"


def _semantic_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Merge common envelope payloads while preserving envelope metadata."""
    for key in ("data", "payload", "event", "attributes"):
        nested = record.get(key)
        if isinstance(nested, dict):
            merged = dict(record)
            merged.update(nested)
            return merged
    return record


def _looks_like_record(record: Dict[str, Any]) -> bool:
    keys = {
        "event_type",
        "type",
        "kind",
        "record_type",
        "timestamp",
        "pid",
        "prompt",
        "messages",
    }
    return bool(keys.intersection(record))


def _common_os(record: Dict[str, Any]) -> Dict[str, Any]:
    timestamp = _parse_timestamp(_timestamp_value(record))
    pid = max(0, _safe_int(_first(record, ("pid", "process_id", "processId"), 0)))
    ppid = max(0, _safe_int(_first(record, ("ppid", "parent_pid", "parentPid"), 0)))
    uid = max(0, _safe_int(_first(record, ("uid", "user_id"), 0)))
    gid = max(0, _safe_int(_first(record, ("gid", "group_id"), 0)))
    source_session = _session_id(record, "")
    return {
        "event_id": _stable_event_id("os", record),
        "timestamp": timestamp,
        "pid": pid,
        "ppid": ppid,
        "uid": uid,
        "gid": gid,
        "comm": str(_first(record, ("comm", "process_name", "processName"), "") or ""),
        "executable": str(_first(record, ("executable", "exe", "binary"), "") or ""),
        "cwd": str(_first(record, ("cwd", "working_directory"), "unknown") or "unknown"),
        "source": "agentsight-import",
        "sequence": max(0, _safe_int(_first(record, ("sequence", "seq"), 0))),
        "process_start_ns": max(
            0,
            _safe_int(_first(record, ("process_start_ns", "start_boottime_ns"), 0)),
        ),
        "parent_start_ns": max(
            0,
            _safe_int(_first(record, ("parent_start_ns", "parent_start_boottime_ns"), 0)),
        ),
        "metadata": {
            "agentsight_session_id": source_session or None,
            "agentsight_record": record,
        },
    }


class AgentSightImporter:
    """Normalize AgentSight snapshots, reports, exported JSON, or JSONL."""

    @staticmethod
    def load(path: Path | str) -> Any:
        source = Path(path)
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise AgentSightIntegrationError(f"unable to read AgentSight document {source}: {exc}") from exc
        return _decode_json_or_jsonl(text, str(source))

    @staticmethod
    def _records(document: Any) -> Iterator[Dict[str, Any]]:
        stack = [document]
        visited: set[int] = set()
        envelope_keys = {"data", "payload", "event", "attributes"}
        while stack:
            value = stack.pop()
            if isinstance(value, list):
                stack.extend(reversed(value))
                continue
            if not isinstance(value, dict):
                continue
            object_id = id(value)
            if object_id in visited:
                continue
            visited.add(object_id)
            yield _semantic_record(value)
            for key, child in reversed(list(value.items())):
                if not isinstance(child, (dict, list)):
                    continue
                if key in envelope_keys and isinstance(child, dict):
                    # The envelope and payload were already emitted as one
                    # semantic record. Traverse only nested collections so a
                    # payload without an upstream event_id is not duplicated.
                    for nested in reversed(list(child.values())):
                        if isinstance(nested, (dict, list)):
                            stack.append(nested)
                    continue
                stack.append(child)

    @staticmethod
    def _llm_event(record: Dict[str, Any], default_session_id: str) -> Optional[LLMInteractionEvent]:
        kind = _record_kind(record)
        explicit = any(
            token in kind
            for token in (
                "llm",
                "prompt",
                "model_call",
                "inference",
                "chat_completion",
            )
        )
        prompt_value = _first(record, ("prompt", "messages", "user_prompt"))
        if prompt_value is None and explicit:
            prompt_value = _first(record, ("input", "request"))
        if prompt_value is None:
            return None
        # A process/audit record can contain a field named "prompt" in nested
        # metadata. Do not convert it into an LLM interaction unless the kind is
        # LLM-like (or no kind was supplied, as in some prompts JSONL exports).
        if kind and not explicit and not (
            "model" in record
            and any(key in record for key in ("prompt", "messages", "user_prompt"))
        ):
            return None
        prompt = _stringify(prompt_value)
        if not prompt:
            return None
        response_value = _first(record, ("response", "output", "completion", "assistant_response"))
        duration = _first(record, ("duration_ms", "latency_ms", "elapsed_ms"))
        duration_ms = _safe_int(duration, -1) if duration is not None else -1
        request_id = _first(record, ("request_id", "requestId", "call_id", "span_id", "id"))
        return LLMInteractionEvent(
            event_id=_stable_event_id("llm", record),
            timestamp=_parse_timestamp(_timestamp_value(record)),
            session_id=_session_id(record, default_session_id),
            request_id=str(request_id) if request_id is not None else None,
            pid=(
                max(0, _safe_int(_first(record, ("pid", "process_id", "processId"), 0)))
                or None
            ),
            llm_provider=str(_first(record, ("provider", "llm_provider", "vendor"), "unknown")),
            model=str(_first(record, ("model", "model_name", "llm_model"), "unknown")),
            prompt=prompt,
            response=_stringify(response_value) or None,
            duration_ms=duration_ms if duration_ms >= 0 else None,
            source="agentsight",
            metadata={
                "agentsight_session_id": _session_id(record, default_session_id),
                "agentsight_record": record,
            },
        )

    @staticmethod
    def _file_event(record: Dict[str, Any], kind: str, common: Dict[str, Any]) -> Optional[BaseOSEvent]:
        path_value = _first(record, ("file_path", "path", "filename"))
        if path_value is None or not any(
            token in kind for token in ("file", "open", "write", "delete", "unlink", "remove")
        ):
            return None
        path = str(path_value)
        result = _safe_int(_first(record, ("result", "return_value"), 0))
        if any(token in kind for token in ("delete", "unlink", "remove")):
            return FileDeleteEvent(
                **common,
                path=path,
                raw_path=path,
                dirfd=_safe_int(_first(record, ("dirfd", "directory_fd"), -100), -100),
                result=result,
            )
        if "write" in kind:
            return FileWriteEvent(
                **common,
                path=path,
                raw_path=path,
                fd=_safe_int(_first(record, ("fd", "file_descriptor"), -1), -1),
                dirfd=_safe_int(_first(record, ("dirfd", "directory_fd"), -100), -100),
                bytes_written=max(
                    0,
                    _safe_int(_first(record, ("bytes_written", "bytes", "size"), 0)),
                ),
                result=result,
            )
        flags = max(0, _safe_int(_first(record, ("flags", "open_flags"), 0)))
        return FileAccessEvent(
            **common,
            path=path,
            raw_path=path,
            fd=_safe_int(_first(record, ("fd", "file_descriptor"), -1), -1),
            dirfd=_safe_int(_first(record, ("dirfd", "directory_fd"), -100), -100),
            flags=flags,
            result=result,
            write_intent=bool(_first(record, ("write_intent", "writable"), False)),
        )

    @staticmethod
    def _network_event(record: Dict[str, Any], kind: str, common: Dict[str, Any]) -> Optional[BaseOSEvent]:
        remote = _first(record, ("remote_addr", "remote_address", "host", "destination"))
        port = _first(record, ("remote_port", "port", "destination_port"))
        if remote is None or port is None or not any(
            token in kind for token in ("network", "connect", "socket", "http", "api")
        ):
            return None
        return NetworkConnectionEvent(
            **common,
            remote_addr=str(remote),
            remote_port=max(0, min(65535, _safe_int(port))),
            family=max(0, _safe_int(_first(record, ("family", "address_family"), 0))),
            protocol=str(_first(record, ("protocol",), "tcp") or "tcp"),
            result=_safe_int(_first(record, ("result", "return_value"), 0)),
        )

    @staticmethod
    def _process_event(record: Dict[str, Any], kind: str, common: Dict[str, Any]) -> Optional[BaseOSEvent]:
        if any(token in kind for token in ("process_exit", "proc_exit")) or kind == "exit":
            return ProcessExitEvent(
                **common,
                exit_code=_safe_int(_first(record, ("exit_code", "code", "status"), 0)),
                signal=max(0, _safe_int(_first(record, ("signal", "signal_number"), 0))),
                duration_ns=max(
                    0,
                    _safe_int(_first(record, ("duration_ns", "elapsed_ns"), 0)),
                ),
            )
        if any(token in kind for token in ("process_fork", "proc_fork")) or kind == "fork":
            child_pid = max(0, _safe_int(_first(record, ("child_pid", "pid"), common["pid"])))
            parent_pid = max(0, _safe_int(_first(record, ("parent_pid", "ppid"), common["ppid"])))
            values = {
                **common,
                "pid": child_pid,
                "ppid": parent_pid,
                "process_start_ns": max(
                    0,
                    _safe_int(
                        _first(
                            record,
                            ("child_start_ns", "process_start_ns", "start_boottime_ns"),
                            common["process_start_ns"],
                        )
                    ),
                ),
                "parent_start_ns": max(
                    0,
                    _safe_int(
                        _first(
                            record,
                            ("parent_start_ns", "parent_start_boottime_ns"),
                            common["parent_start_ns"],
                        )
                    ),
                ),
            }
            return ProcessForkEvent(
                **values,
                child_comm=str(
                    _first(record, ("child_comm", "child_process_name"), common["comm"]) or ""
                ),
            )
        process_kind = any(
            token in kind
            for token in ("process_exec", "process_start", "exec", "spawn", "command_execution")
        ) or kind in {"process", "command"} or (
            not kind
            and any(key in record for key in ("executable", "argv", "command", "cmdline"))
        )
        if not process_kind:
            return None
        argv_value = _first(record, ("argv", "args", "command_args"), [])
        if isinstance(argv_value, str):
            try:
                argv = shlex.split(argv_value)
            except ValueError:
                argv = argv_value.split()
        elif isinstance(argv_value, list):
            argv = [str(item) for item in argv_value]
        else:
            argv = []
        command = _first(record, ("command", "cmdline"))
        if not argv and command:
            try:
                argv = shlex.split(str(command))
            except ValueError:
                argv = str(command).split()
        executable = common["executable"] or (argv[0] if argv else "")
        values = {**common, "executable": executable}
        return ProcessExecutionEvent(
            **values,
            argv=argv,
            argv_truncated=bool(_first(record, ("argv_truncated",), False)),
            syscall="agentsight",
        )

    @classmethod
    def _os_event(cls, record: Dict[str, Any]) -> Optional[BaseOSEvent]:
        kind = _record_kind(record)
        recognized_kind = any(
            token in kind
            for token in (
                "process",
                "proc_",
                "exec",
                "spawn",
                "fork",
                "exit",
                "file",
                "open",
                "write",
                "delete",
                "unlink",
                "remove",
                "network",
                "connect",
                "socket",
                "http",
                "api_call",
                "command",
            )
        )
        implicit_os_record = any(
            key in record
            for key in (
                "executable",
                "argv",
                "command",
                "file_path",
                "remote_addr",
                "remote_address",
            )
        ) and any(key in record for key in ("pid", "process_id", "processId"))
        if not recognized_kind and not implicit_os_record:
            return None
        common = _common_os(record)
        common["event_id"] = _stable_event_id(f"os:{kind or 'event'}", record)
        if (any(token in kind for token in ("process_fork", "proc_fork")) or kind == "fork"):
            common["pid"] = max(
                0, _safe_int(_first(record, ("child_pid", "pid"), common["pid"]))
            )
            common["ppid"] = max(
                0, _safe_int(_first(record, ("parent_pid", "ppid"), common["ppid"]))
            )
        if common["pid"] <= 0:
            return None
        # Specific side effects are checked before the generic process record.
        return (
            cls._file_event(record, kind, common)
            or cls._network_event(record, kind, common)
            or cls._process_event(record, kind, common)
        )

    def parse(self, document: Any, default_session_id: str) -> AgentSightImportResult:
        if not default_session_id:
            raise ValueError("default_session_id must not be empty")
        result = AgentSightImportResult()
        seen_event_ids: set[str] = set()
        for index, record in enumerate(self._records(document), start=1):
            candidates: list[LLMInteractionEvent | BaseOSEvent] = []
            errors: list[str] = []
            for label, parser in (
                ("LLM", lambda: self._llm_event(record, default_session_id)),
                ("OS", lambda: self._os_event(record)),
            ):
                try:
                    event = parser()
                except (TypeError, ValueError, ValidationError) as exc:
                    message = f"{label}: {exc}"
                    if message not in errors:
                        errors.append(message)
                    continue
                if event is not None:
                    candidates.append(event)

            if not candidates:
                if errors or _looks_like_record(record):
                    result.ignored_records += 1
                if errors:
                    result.warnings.append(
                        f"record {index} ignored: " + "; ".join(errors)
                    )
                continue
            if errors:
                result.warnings.append(
                    f"record {index} partially imported: " + "; ".join(errors)
                )
            for event in candidates:
                if event.event_id in seen_event_ids:
                    continue
                seen_event_ids.add(event.event_id)
                if isinstance(event, LLMInteractionEvent):
                    result.llm_events.append(event)
                else:
                    result.os_events.append(event)
        result.llm_events.sort(key=lambda item: (item.timestamp, item.event_id))
        result.os_events.sort(key=lambda item: (item.timestamp, item.sequence, item.event_id))
        return result

    def parse_file(self, path: Path | str, default_session_id: str) -> AgentSightImportResult:
        return self.parse(self.load(path), default_session_id)

    def import_into_runtime(
        self,
        path: Path | str,
        runtime: AgentSightRuntime,
        session_id: str,
    ) -> AgentSightImportResult:
        result = self.parse_file(path, session_id)
        for event in result.llm_events:
            runtime.record_llm_interaction(event.model_copy(update={"session_id": session_id}))
        runtime.ingest_many(result.os_events)
        return result


class AgentSightCLI:
    """Small wrapper around AgentSight report/export commands."""

    def __init__(self, executable: str = "agentsight", timeout_seconds: float = 15.0):
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        resolved = shutil.which(executable)
        if not resolved:
            raise AgentSightIntegrationError(f"AgentSight executable not found: {executable}")
        self.executable = resolved
        self.timeout_seconds = timeout_seconds

    def _run_variants(self, variants: Iterable[List[str]]) -> subprocess.CompletedProcess[str]:
        failures: List[str] = []
        for arguments in variants:
            command = [self.executable, *arguments]
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                failures.append(
                    f"{' '.join(command)}: timed out after {self.timeout_seconds:g}s"
                )
                continue
            except OSError as exc:
                failures.append(f"{' '.join(command)}: {type(exc).__name__}: {exc}")
                continue
            if result.returncode == 0:
                return result
            failures.append(
                f"{' '.join(command)}: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        raise AgentSightIntegrationError("AgentSight command failed:\n" + "\n".join(failures))

    def export_snapshot(self, database: Path | str, output: Path | str) -> Path:
        database_path = str(Path(database))
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            output_path.unlink(missing_ok=True)
        except OSError as exc:
            raise AgentSightIntegrationError(
                f"unable to replace AgentSight snapshot {output_path}: {exc}"
            ) from exc
        self._run_variants(
            [
                ["report", "--db", database_path, "export", "-o", str(output_path)],
                ["report", "export", "--db", database_path, "-o", str(output_path)],
            ]
        )
        if not output_path.exists():
            raise AgentSightIntegrationError(
                "AgentSight reported success but did not create the snapshot"
            )
        return output_path

    def _report_json(self, database: Path | str, report: str) -> Any:
        database_path = str(Path(database))
        result = self._run_variants(
            [
                ["report", "--db", database_path, report, "--json"],
                ["report", report, "--db", database_path, "--json"],
            ]
        )
        return _decode_json_or_jsonl(result.stdout, f"agentsight report {report}")

    def prompts_json(self, database: Path | str) -> Any:
        return self._report_json(database, "prompts")

    def audit_json(self, database: Path | str) -> Any:
        """Return AgentSight's process/file/API audit report as JSON/JSONL."""
        return self._report_json(database, "audit")

    def combined_report(self, database: Path | str) -> Dict[str, Any]:
        """Fetch both LLM calls and system audit records for normalization."""
        return {
            "prompts": self.prompts_json(database),
            "audit": self.audit_json(database),
        }


class AgentSightPromptPoller:
    """Continuously import new LLM interactions from an AgentSight database.

    The AgentSight CLI remains the owner of the upstream SQLite schema. This
    adapter asks the CLI for JSON instead of reading private tables directly,
    making the integration less sensitive to upstream schema migrations.
    """

    def __init__(
        self,
        database: Path | str,
        runtime: AgentSightRuntime,
        session_id: str,
        *,
        interval_seconds: float = 2.0,
        executable: str = "agentsight",
        cli: Optional[AgentSightCLI] = None,
        importer: Optional[AgentSightImporter] = None,
    ):
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if not session_id:
            raise ValueError("session_id must not be empty")
        self.database = Path(database)
        self.runtime = runtime
        self.session_id = session_id
        self.interval_seconds = interval_seconds
        self.cli = cli or AgentSightCLI(executable)
        self.importer = importer or AgentSightImporter()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._state_lock = threading.RLock()
        self._starting = False
        self.poll_count = 0
        self.imported_events = 0
        self.ignored_records = 0
        self.last_error: Optional[str] = None
        self.last_warnings: List[str] = []

    def refresh(self) -> AgentSightImportResult:
        document = self.cli.prompts_json(self.database)
        result = self.importer.parse(document, self.session_id)
        if self.runtime.sessions.snapshot_session(self.session_id) is None:
            raise AgentSightIntegrationError(f"session not found: {self.session_id}")
        imported = 0
        for event in result.llm_events:
            normalized = event.model_copy(update={"session_id": self.session_id})
            _, added = self.runtime.record_llm_interaction_with_status(normalized)
            imported += int(added)
        with self._state_lock:
            self.poll_count += 1
            self.imported_events += imported
            self.ignored_records += result.ignored_records
            self.last_warnings = list(result.warnings[-20:])
            self.last_error = None
        return result

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.refresh()
            except Exception as exc:  # keep OS collection available if AgentSight is transiently unavailable
                with self._state_lock:
                    self.poll_count += 1
                    self.last_error = f"{type(exc).__name__}: {exc}"
            self._stop.wait(self.interval_seconds)

    def start(self, *, initial_refresh: bool = False) -> None:
        with self._state_lock:
            if self._starting or (self._thread and self._thread.is_alive()):
                raise RuntimeError("AgentSight prompt poller is already running")
            self._starting = True
        try:
            self._stop.clear()
            if initial_refresh:
                self.refresh()
            thread = threading.Thread(
                target=self._run,
                name="agentsight-prompt-poller",
                daemon=True,
            )
            with self._state_lock:
                self._thread = thread
            thread.start()
        finally:
            with self._state_lock:
                self._starting = False

    def stop(self) -> None:
        self._stop.set()
        with self._state_lock:
            thread = self._thread
        if thread and thread.is_alive():
            timeout = max(2.0, float(getattr(self.cli, "timeout_seconds", 0.0)) + 1.0)
            thread.join(timeout=timeout)
        with self._state_lock:
            if thread is not None and thread.is_alive():
                self.last_error = "AgentSight prompt poller did not stop before timeout"
            else:
                self._thread = None

    def metrics(self) -> Dict[str, Any]:
        with self._state_lock:
            return {
                "running": int(bool(self._thread and self._thread.is_alive())),
                "starting": int(self._starting),
                "poll_count": self.poll_count,
                "imported_events": self.imported_events,
                "ignored_records": self.ignored_records,
                "last_error": self.last_error,
                "warnings": list(self.last_warnings),
                "database": str(self.database),
            }

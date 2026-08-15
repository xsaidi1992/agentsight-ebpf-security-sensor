"""AgentSight report/export adapters.

The upstream AgentSight report schema can evolve. This module intentionally
normalizes semantic fields instead of binding the sensor to one JSON layout.
Every imported record keeps its original payload in metadata for auditability.
"""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# Rôle du module : importer les événements AgentSight, normaliser leurs horodatages et les corréler au runtime.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


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


# [BESOIN A/C/E/P] Classe `AgentSightIntegrationError` : implémente le comportement documenté par sa
# docstring : « Raised when an AgentSight document or CLI operation cannot be used ».
class AgentSightIntegrationError(RuntimeError):
    """Raised when an AgentSight document or CLI operation cannot be used."""


# [BESOIN A/C/E/P] Fonction `_decode_json_or_jsonl` : implémente le comportement documenté par sa
# docstring : « Decode strict JSON first, then non-empty JSON Lines records ».
def _decode_json_or_jsonl(text: str, source: str) -> Any:
    """Decode strict JSON first, then non-empty JSON Lines records."""
    # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
    # explicite.
    try:
        return json.loads(text)
    except json.JSONDecodeError as json_error:
        records: List[Any] = []
        # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for line_number, line in enumerate(text.splitlines(), start=1):
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if not line.strip():
                continue
            # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
            # diagnostic explicite.
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise AgentSightIntegrationError(
                    f"invalid JSON/JSONL at {source}:{line_number}: {exc}"
                ) from exc
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if records:
            return records
        # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire une
        # fausse preuve.
        raise AgentSightIntegrationError(f"empty or invalid AgentSight JSON from {source}") from json_error


# [BESOIN A/C/E/P] Classe `AgentSightImportResult` : classe dédiée à l’opération
# `AgentSightImportResult` dans le flux qui consiste à importer les événements
# AgentSight, normaliser leurs horodatages et les corréler au runtime.
@dataclass
class AgentSightImportResult:
    # [BESOIN A/C/E/P] Attribut `llm_events` : porte une donnée nécessaire au rôle du composant.
    llm_events: List[LLMInteractionEvent] = field(default_factory=list)
    # [BESOIN A/C/E/P] Attribut `os_events` : porte une donnée nécessaire au rôle du composant.
    os_events: List[BaseOSEvent] = field(default_factory=list)
    # [BESOIN A/C/E/P] Attribut `ignored_records` : porte une donnée nécessaire au rôle du composant.
    ignored_records: int = 0
    # [BESOIN A/C/E/P] Attribut `warnings` : porte une donnée nécessaire au rôle du composant.
    warnings: List[str] = field(default_factory=list)

    # [BESOIN A/C/E/P] Fonction `total_events` : fonction dédiée à l’opération `total_events` dans le
    # flux qui consiste à importer les événements AgentSight, normaliser leurs
    # horodatages et les corréler au runtime.
    @property
    def total_events(self) -> int:
        return len(self.llm_events) + len(self.os_events)


# [BESOIN A/C/E/P] Fonction `_first` : fonction dédiée à l’opération `_first` dans le flux qui consiste
# à importer les événements AgentSight, normaliser leurs horodatages et les corréler au
# runtime.
def _first(mapping: Dict[str, Any], names: Sequence[str], default: Any = None) -> Any:
    # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
    # traçable.
    for name in names:
        value = mapping.get(name)
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if value is not None:
            return value
    return default


# [BESOIN A/C/E/P] Fonction `_safe_int` : fonction dédiée à l’opération `_safe_int` dans le flux qui
# consiste à importer les événements AgentSight, normaliser leurs horodatages et les
# corréler au runtime.
def _safe_int(value: Any, default: int = 0) -> int:
    # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
    # explicite.
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


# [BESOIN A/C/E/P] Fonction `_parse_timestamp` : implémente le comportement documenté par sa docstring :
# « Parse an AgentSight timestamp without inventing event time ».
def _parse_timestamp(value: Any) -> datetime:
    """Parse an AgentSight timestamp without inventing event time.

    Temporal correlation is security-significant.  Missing or malformed source
    timestamps are therefore rejected and surfaced as import warnings instead
    of being replaced by ``now()``.
    """
    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if isinstance(value, datetime):
        parsed = value
    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = float(value)
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if numeric > 1e17:  # nanoseconds since epoch
            numeric /= 1e9
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        elif numeric > 1e14:  # microseconds since epoch
            numeric /= 1e6
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        elif numeric > 1e11:  # milliseconds since epoch
            numeric /= 1e3
        # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            parsed = datetime.fromtimestamp(numeric, tz=timezone.utc)
        except (OSError, OverflowError, ValueError) as exc:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError(f"invalid timestamp: {value!r}") from exc
    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
            # diagnostic explicite.
            try:
                return _parse_timestamp(float(raw))
            except ValueError as exc:
                # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise ValueError(f"invalid timestamp: {value!r}") from exc
    else:
        # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire une
        # fausse preuve.
        raise ValueError("missing timestamp")

    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# [BESOIN A/C/E/P] Fonction `_timestamp_value` : fonction dédiée à l’opération `_timestamp_value` dans
# le flux qui consiste à importer les événements AgentSight, normaliser leurs
# horodatages et les corréler au runtime.
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
    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if value is not None:
        return value
    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if "timestamp_ns" in record:
        value = record["timestamp_ns"]
        # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            numeric = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError(f"invalid timestamp_ns: {value!r}") from exc
        # A small timestamp_ns is normally a monotonic kernel timestamp. It
        # cannot be correlated to wall-clock LLM activity without a boot-epoch
        # mapping, so reject it rather than silently inventing a 1970 date.
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if numeric < 100_000_000_000_000_000:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError(
                "timestamp_ns is not a Unix-epoch nanosecond timestamp; "
                "provide an ISO/epoch timestamp or an explicit boot mapping"
            )
        return value
    return None


# [BESOIN A/C/E/P] Fonction `_stringify` : fonction dédiée à l’opération `_stringify` dans le flux qui
# consiste à importer les événements AgentSight, normaliser leurs horodatages et les
# corréler au runtime.
def _stringify(value: Any) -> str:
    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if value is None:
        return ""
    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if isinstance(value, str):
        return value
    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if isinstance(value, list):
        parts: List[str] = []
        # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for item in value:
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if isinstance(item, dict):
                role = item.get("role")
                content = _stringify(item.get("content", item.get("text", item)))
                parts.append(f"{role}: {content}" if role else content)
            else:
                parts.append(_stringify(item))
        return "\n".join(part for part in parts if part)
    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if isinstance(value, dict):
        # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for key in ("content", "text", "prompt", "message", "output"):
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if key in value:
                return _stringify(value[key])
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return str(value)


# [BESOIN A/C/E/P] Fonction `_record_kind` : fonction dédiée à l’opération `_record_kind` dans le flux
# qui consiste à importer les événements AgentSight, normaliser leurs horodatages et
# les corréler au runtime.
def _record_kind(record: Dict[str, Any]) -> str:
    value = _first(record, ("event_type", "type", "kind", "record_type", "name"), "")
    return re.sub(r"[^a-z0-9]+", "_", str(value).casefold()).strip("_")


# [BESOIN A/C/E/P] Fonction `_session_id` : fonction dédiée à l’opération `_session_id` dans le flux qui
# consiste à importer les événements AgentSight, normaliser leurs horodatages et les
# corréler au runtime.
def _session_id(record: Dict[str, Any], default: str) -> str:
    value = _first(
        record,
        ("session_id", "sessionId", "agent_session_id", "run_id", "trace_id"),
        default,
    )
    return str(value or default)


# [BESOIN A/C/E/P] Fonction `_source_identifier` : fonction dédiée à l’opération `_source_identifier`
# dans le flux qui consiste à importer les événements AgentSight, normaliser leurs
# horodatages et les corréler au runtime.
def _source_identifier(record: Dict[str, Any]) -> str:
    value = _first(record, ("event_id", "eventId", "id", "span_id", "call_id"), "")
    return str(value or "")


# [BESOIN A/C/E/P] Fonction `_stable_event_id` : fonction dédiée à l’opération `_stable_event_id` dans
# le flux qui consiste à importer les événements AgentSight, normaliser leurs
# horodatages et les corréler au runtime.
def _stable_event_id(prefix: str, record: Dict[str, Any]) -> str:
    source_id = _source_identifier(record)
    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if source_id:
        return f"agentsight:{prefix}:{source_id}"
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:24]
    return f"agentsight:{prefix}:sha256:{digest}"


# [BESOIN A/C/E/P] Fonction `_semantic_record` : implémente le comportement documenté par sa docstring :
# « Merge common envelope payloads while preserving envelope metadata ».
def _semantic_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Merge common envelope payloads while preserving envelope metadata."""
    # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
    # traçable.
    for key in ("data", "payload", "event", "attributes"):
        nested = record.get(key)
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if isinstance(nested, dict):
            merged = dict(record)
            merged.update(nested)
            return merged
    return record


# [BESOIN A/C/E/P] Fonction `_looks_like_record` : fonction dédiée à l’opération `_looks_like_record`
# dans le flux qui consiste à importer les événements AgentSight, normaliser leurs
# horodatages et les corréler au runtime.
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


# [BESOIN A/C/E/P] Fonction `_common_os` : fonction dédiée à l’opération `_common_os` dans le flux qui
# consiste à importer les événements AgentSight, normaliser leurs horodatages et les
# corréler au runtime.
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


# [BESOIN A/C/E/P] Classe `AgentSightImporter` : implémente le comportement documenté par sa docstring :
# « Normalize AgentSight snapshots, reports, exported JSON, or JSONL ».
class AgentSightImporter:
    """Normalize AgentSight snapshots, reports, exported JSON, or JSONL."""

    # [BESOIN A/C/E/P] Fonction `load` : fonction dédiée à l’opération `load` dans le flux qui consiste
    # à importer les événements AgentSight, normaliser leurs horodatages et les
    # corréler au runtime.
    @staticmethod
    def load(path: Path | str) -> Any:
        source = Path(path)
        # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise AgentSightIntegrationError(f"unable to read AgentSight document {source}: {exc}") from exc
        return _decode_json_or_jsonl(text, str(source))

    # [BESOIN A/C/E/P] Fonction `_records` : fonction dédiée à l’opération `_records` dans le flux qui
    # consiste à importer les événements AgentSight, normaliser leurs horodatages et
    # les corréler au runtime.
    @staticmethod
    def _records(document: Any) -> Iterator[Dict[str, Any]]:
        stack = [document]
        visited: set[int] = set()
        envelope_keys = {"data", "payload", "event", "attributes"}
        # [BESOIN A/C/E/P] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la condition
        # d’arrêt.
        while stack:
            value = stack.pop()
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if isinstance(value, list):
                stack.extend(reversed(value))
                continue
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if not isinstance(value, dict):
                continue
            object_id = id(value)
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if object_id in visited:
                continue
            visited.add(object_id)
            yield _semantic_record(value)
            # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
            # traçable.
            for key, child in reversed(list(value.items())):
                # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if not isinstance(child, (dict, list)):
                    continue
                # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if key in envelope_keys and isinstance(child, dict):
                    # The envelope and payload were already emitted as one
                    # semantic record. Traverse only nested collections so a
                    # payload without an upstream event_id is not duplicated.
                    # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière
                    # déterministe et traçable.
                    for nested in reversed(list(child.values())):
                        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de
                        # poursuivre le flux fonctionnel.
                        if isinstance(nested, (dict, list)):
                            stack.append(nested)
                    continue
                stack.append(child)

    # [BESOIN A/C/E/P] Fonction `_llm_event` : fonction dédiée à l’opération `_llm_event` dans le flux
    # qui consiste à importer les événements AgentSight, normaliser leurs horodatages
    # et les corréler au runtime.
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
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if prompt_value is None and explicit:
            prompt_value = _first(record, ("input", "request"))
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if prompt_value is None:
            return None
        # A process/audit record can contain a field named "prompt" in nested
        # metadata. Do not convert it into an LLM interaction unless the kind is
        # LLM-like (or no kind was supplied, as in some prompts JSONL exports).
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if kind and not explicit and not (
            "model" in record
            and any(key in record for key in ("prompt", "messages", "user_prompt"))
        ):
            return None
        prompt = _stringify(prompt_value)
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
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

    # [BESOIN A/C/E/P] Fonction `_file_event` : fonction dédiée à l’opération `_file_event` dans le flux
    # qui consiste à importer les événements AgentSight, normaliser leurs horodatages
    # et les corréler au runtime.
    @staticmethod
    def _file_event(record: Dict[str, Any], kind: str, common: Dict[str, Any]) -> Optional[BaseOSEvent]:
        path_value = _first(record, ("file_path", "path", "filename"))
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if path_value is None or not any(
            token in kind for token in ("file", "open", "write", "delete", "unlink", "remove")
        ):
            return None
        path = str(path_value)
        result = _safe_int(_first(record, ("result", "return_value"), 0))
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if any(token in kind for token in ("delete", "unlink", "remove")):
            return FileDeleteEvent(
                **common,
                path=path,
                raw_path=path,
                dirfd=_safe_int(_first(record, ("dirfd", "directory_fd"), -100), -100),
                result=result,
            )
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
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

    # [BESOIN A/C/E/P] Fonction `_network_event` : fonction dédiée à l’opération `_network_event` dans
    # le flux qui consiste à importer les événements AgentSight, normaliser leurs
    # horodatages et les corréler au runtime.
    @staticmethod
    def _network_event(record: Dict[str, Any], kind: str, common: Dict[str, Any]) -> Optional[BaseOSEvent]:
        remote = _first(record, ("remote_addr", "remote_address", "host", "destination"))
        port = _first(record, ("remote_port", "port", "destination_port"))
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
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

    # [BESOIN A/C/E/P] Fonction `_process_event` : fonction dédiée à l’opération `_process_event` dans
    # le flux qui consiste à importer les événements AgentSight, normaliser leurs
    # horodatages et les corréler au runtime.
    @staticmethod
    def _process_event(record: Dict[str, Any], kind: str, common: Dict[str, Any]) -> Optional[BaseOSEvent]:
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
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
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
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
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not process_kind:
            return None
        argv_value = _first(record, ("argv", "args", "command_args"), [])
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if isinstance(argv_value, str):
            # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
            # diagnostic explicite.
            try:
                argv = shlex.split(argv_value)
            except ValueError:
                argv = argv_value.split()
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        elif isinstance(argv_value, list):
            argv = [str(item) for item in argv_value]
        else:
            argv = []
        command = _first(record, ("command", "cmdline"))
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not argv and command:
            # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
            # diagnostic explicite.
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

    # [BESOIN A/C/E/P] Fonction `_os_event` : fonction dédiée à l’opération `_os_event` dans le flux qui
    # consiste à importer les événements AgentSight, normaliser leurs horodatages et
    # les corréler au runtime.
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
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not recognized_kind and not implicit_os_record:
            return None
        common = _common_os(record)
        common["event_id"] = _stable_event_id(f"os:{kind or 'event'}", record)
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if (any(token in kind for token in ("process_fork", "proc_fork")) or kind == "fork"):
            common["pid"] = max(
                0, _safe_int(_first(record, ("child_pid", "pid"), common["pid"]))
            )
            common["ppid"] = max(
                0, _safe_int(_first(record, ("parent_pid", "ppid"), common["ppid"]))
            )
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if common["pid"] <= 0:
            return None
        # Specific side effects are checked before the generic process record.
        return (
            cls._file_event(record, kind, common)
            or cls._network_event(record, kind, common)
            or cls._process_event(record, kind, common)
        )

    # [BESOIN A/C/E/P] Fonction `parse` : analyse un document AgentSight et produit des événements
    # normalisés sans inventer les données manquantes.
    def parse(self, document: Any, default_session_id: str) -> AgentSightImportResult:
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not default_session_id:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("default_session_id must not be empty")
        result = AgentSightImportResult()
        seen_event_ids: set[str] = set()
        # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for index, record in enumerate(self._records(document), start=1):
            candidates: list[LLMInteractionEvent | BaseOSEvent] = []
            errors: list[str] = []
            # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
            # traçable.
            for label, parser in (
                ("LLM", lambda: self._llm_event(record, default_session_id)),
                ("OS", lambda: self._os_event(record)),
            ):
                # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
                # diagnostic explicite.
                try:
                    event = parser()
                except (TypeError, ValueError, ValidationError) as exc:
                    message = f"{label}: {exc}"
                    # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                    # flux fonctionnel.
                    if message not in errors:
                        errors.append(message)
                    continue
                # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if event is not None:
                    candidates.append(event)

            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if not candidates:
                # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if errors or _looks_like_record(record):
                    result.ignored_records += 1
                # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if errors:
                    result.warnings.append(
                        f"record {index} ignored: " + "; ".join(errors)
                    )
                continue
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if errors:
                result.warnings.append(
                    f"record {index} partially imported: " + "; ".join(errors)
                )
            # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
            # traçable.
            for event in candidates:
                # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if event.event_id in seen_event_ids:
                    continue
                seen_event_ids.add(event.event_id)
                # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le
                # flux fonctionnel.
                if isinstance(event, LLMInteractionEvent):
                    result.llm_events.append(event)
                else:
                    result.os_events.append(event)
        result.llm_events.sort(key=lambda item: (item.timestamp, item.event_id))
        result.os_events.sort(key=lambda item: (item.timestamp, item.sequence, item.event_id))
        return result

    # [BESOIN A/C/E/P] Fonction `parse_file` : charge puis analyse un export AgentSight depuis un
    # fichier.
    def parse_file(self, path: Path | str, default_session_id: str) -> AgentSightImportResult:
        return self.parse(self.load(path), default_session_id)

    # [BESOIN A/C/E/P] Fonction `import_into_runtime` : importe les événements AgentSight dans le
    # runtime avec déduplication et corrélation.
    def import_into_runtime(
        self,
        path: Path | str,
        runtime: AgentSightRuntime,
        session_id: str,
    ) -> AgentSightImportResult:
        result = self.parse_file(path, session_id)
        # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for event in result.llm_events:
            runtime.record_llm_interaction(event.model_copy(update={"session_id": session_id}))
        runtime.ingest_many(result.os_events)
        return result


# [BESOIN A/C/E/P] Classe `AgentSightCLI` : implémente le comportement documenté par sa docstring : «
# Small wrapper around AgentSight report/export commands ».
class AgentSightCLI:
    """Small wrapper around AgentSight report/export commands."""

    # [BESOIN A/C/E/P] Fonction `__init__` : initialise l’état interne et les dépendances nécessaires au
    # composant.
    def __init__(self, executable: str = "agentsight", timeout_seconds: float = 15.0):
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if timeout_seconds <= 0:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("timeout_seconds must be positive")
        resolved = shutil.which(executable)
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not resolved:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise AgentSightIntegrationError(f"AgentSight executable not found: {executable}")
        self.executable = resolved
        self.timeout_seconds = timeout_seconds

    # [BESOIN A/C/E/P] Fonction `_run_variants` : fonction dédiée à l’opération `_run_variants` dans le
    # flux qui consiste à importer les événements AgentSight, normaliser leurs
    # horodatages et les corréler au runtime.
    def _run_variants(self, variants: Iterable[List[str]]) -> subprocess.CompletedProcess[str]:
        failures: List[str] = []
        # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for arguments in variants:
            command = [self.executable, *arguments]
            # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
            # diagnostic explicite.
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
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if result.returncode == 0:
                return result
            failures.append(
                f"{' '.join(command)}: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire une
        # fausse preuve.
        raise AgentSightIntegrationError("AgentSight command failed:\n" + "\n".join(failures))

    # [BESOIN A/C/E/P] Fonction `export_snapshot` : fonction dédiée à l’opération `export_snapshot` dans
    # le flux qui consiste à importer les événements AgentSight, normaliser leurs
    # horodatages et les corréler au runtime.
    def export_snapshot(self, database: Path | str, output: Path | str) -> Path:
        database_path = str(Path(database))
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            output_path.unlink(missing_ok=True)
        except OSError as exc:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise AgentSightIntegrationError(
                f"unable to replace AgentSight snapshot {output_path}: {exc}"
            ) from exc
        self._run_variants(
            [
                ["report", "--db", database_path, "export", "-o", str(output_path)],
                ["report", "export", "--db", database_path, "-o", str(output_path)],
            ]
        )
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not output_path.exists():
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise AgentSightIntegrationError(
                "AgentSight reported success but did not create the snapshot"
            )
        return output_path

    # [BESOIN A/C/E/P] Fonction `_report_json` : fonction dédiée à l’opération `_report_json` dans le
    # flux qui consiste à importer les événements AgentSight, normaliser leurs
    # horodatages et les corréler au runtime.
    def _report_json(self, database: Path | str, report: str) -> Any:
        database_path = str(Path(database))
        result = self._run_variants(
            [
                ["report", "--db", database_path, report, "--json"],
                ["report", report, "--db", database_path, "--json"],
            ]
        )
        return _decode_json_or_jsonl(result.stdout, f"agentsight report {report}")

    # [BESOIN A/C/E/P] Fonction `prompts_json` : fonction dédiée à l’opération `prompts_json` dans le
    # flux qui consiste à importer les événements AgentSight, normaliser leurs
    # horodatages et les corréler au runtime.
    def prompts_json(self, database: Path | str) -> Any:
        return self._report_json(database, "prompts")

    # [BESOIN A/C/E/P] Fonction `audit_json` : implémente le comportement documenté par sa docstring : «
    # Return AgentSight's process/file/API audit report as JSON/JSONL ».
    def audit_json(self, database: Path | str) -> Any:
        """Return AgentSight's process/file/API audit report as JSON/JSONL."""
        return self._report_json(database, "audit")

    # [BESOIN A/C/E/P] Fonction `combined_report` : implémente le comportement documenté par sa
    # docstring : « Fetch both LLM calls and system audit records for normalization ».
    def combined_report(self, database: Path | str) -> Dict[str, Any]:
        """Fetch both LLM calls and system audit records for normalization."""
        return {
            "prompts": self.prompts_json(database),
            "audit": self.audit_json(database),
        }


# [BESOIN A/C/E/P] Classe `AgentSightPromptPoller` : implémente le comportement documenté par sa
# docstring : « Continuously import new LLM interactions from an AgentSight database ».
class AgentSightPromptPoller:
    """Continuously import new LLM interactions from an AgentSight database.

    The AgentSight CLI remains the owner of the upstream SQLite schema. This
    adapter asks the CLI for JSON instead of reading private tables directly,
    making the integration less sensitive to upstream schema migrations.
    """

    # [BESOIN A/C/E/P] Fonction `__init__` : initialise l’état interne et les dépendances nécessaires au
    # composant.
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
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if interval_seconds <= 0:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("interval_seconds must be positive")
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not session_id:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
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

    # [BESOIN A/C/E/P] Fonction `refresh` : interroge périodiquement AgentSight et n’importe que les
    # nouveaux événements.
    def refresh(self) -> AgentSightImportResult:
        document = self.cli.prompts_json(self.database)
        result = self.importer.parse(document, self.session_id)
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self.runtime.sessions.snapshot_session(self.session_id) is None:
            # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise AgentSightIntegrationError(f"session not found: {self.session_id}")
        imported = 0
        # [BESOIN A/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for event in result.llm_events:
            normalized = event.model_copy(update={"session_id": self.session_id})
            _, added = self.runtime.record_llm_interaction_with_status(normalized)
            imported += int(added)
        # [BESOIN A/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._state_lock:
            self.poll_count += 1
            self.imported_events += imported
            self.ignored_records += result.ignored_records
            self.last_warnings = list(result.warnings[-20:])
            self.last_error = None
        return result

    # [BESOIN A/C/E/P] Fonction `_run` : fonction dédiée à l’opération `_run` dans le flux qui consiste
    # à importer les événements AgentSight, normaliser leurs horodatages et les
    # corréler au runtime.
    def _run(self) -> None:
        # [BESOIN A/C/E/P] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la condition
        # d’arrêt.
        while not self._stop.is_set():
            # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
            # diagnostic explicite.
            try:
                self.refresh()
            except Exception as exc:  # keep OS collection available if AgentSight is transiently unavailable
                # [BESOIN A/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture
                # déterministes.
                with self._state_lock:
                    self.poll_count += 1
                    self.last_error = f"{type(exc).__name__}: {exc}"
            self._stop.wait(self.interval_seconds)

    # [BESOIN A/C/E/P] Fonction `start` : démarre le composant de façon contrôlée et refuse les états
    # ambigus.
    def start(self, *, initial_refresh: bool = False) -> None:
        # [BESOIN A/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._state_lock:
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if self._starting or (self._thread and self._thread.is_alive()):
                # [BESOIN A/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise RuntimeError("AgentSight prompt poller is already running")
            self._starting = True
        # [BESOIN A/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            self._stop.clear()
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if initial_refresh:
                self.refresh()
            thread = threading.Thread(
                target=self._run,
                name="agentsight-prompt-poller",
                daemon=True,
            )
            # [BESOIN A/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture
            # déterministes.
            with self._state_lock:
                self._thread = thread
            thread.start()
        finally:
            # [BESOIN A/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture
            # déterministes.
            with self._state_lock:
                self._starting = False

    # [BESOIN A/C/E/P] Fonction `stop` : arrête proprement le composant et libère les ressources
    # associées.
    def stop(self) -> None:
        self._stop.set()
        # [BESOIN A/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._state_lock:
            thread = self._thread
        # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if thread and thread.is_alive():
            timeout = max(2.0, float(getattr(self.cli, "timeout_seconds", 0.0)) + 1.0)
            thread.join(timeout=timeout)
        # [BESOIN A/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self._state_lock:
            # [BESOIN A/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if thread is not None and thread.is_alive():
                self.last_error = "AgentSight prompt poller did not stop before timeout"
            else:
                self._thread = None

    # [BESOIN A/C/E/P] Fonction `metrics` : expose les compteurs de fonctionnement, d’erreur et de perte
    # nécessaires à l’observabilité.
    def metrics(self) -> Dict[str, Any]:
        # [BESOIN A/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
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

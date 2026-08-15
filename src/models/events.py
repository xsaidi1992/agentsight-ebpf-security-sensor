"""Normalized and strictly validated event models.

All timestamps are normalized to timezone-aware UTC at the model boundary.  The
kernel collector, AgentSight adapter, API and tests therefore share one stable
representation and cannot accidentally compare naive and aware datetimes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import shlex
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_event_id() -> str:
    return str(uuid4())


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class EventSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    PROCESS_FORK = "PROCESS_FORK"
    PROCESS_EXIT = "PROCESS_EXIT"
    FILE_ACCESS = "FILE_ACCESS"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    LLM_INTERACTION = "LLM_INTERACTION"
    SECURITY_EVENT = "AI_AGENT_SECURITY_EVENT"


class CorrelationLink(BaseModel):
    """Explainable association between one LLM interaction and one OS event."""

    model_config = ConfigDict(extra="forbid")

    llm_event_id: str
    llm_request_id: Optional[str] = None
    method: str = "temporal_session_window"
    confidence: float = Field(ge=0.0, le=1.0)
    latency_ms: int = Field(ge=0)
    rationale: str
    causal_proof: bool = False


class BaseOSEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=new_event_id, min_length=1)
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: EventType
    pid: int = Field(ge=0)
    ppid: int = Field(ge=0)
    uid: int = Field(ge=0)
    gid: int = Field(ge=0)
    comm: str = ""
    executable: str = ""
    cwd: str = "unknown"
    source: str = "ebpf"
    sequence: int = Field(default=0, ge=0)
    kernel_timestamp_ns: int = Field(default=0, ge=0)
    process_start_ns: int = Field(default=0, ge=0)
    parent_start_ns: int = Field(default=0, ge=0)
    correlation: Optional[CorrelationLink] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _as_utc(value)


class ProcessExecutionEvent(BaseOSEvent):
    event_type: Literal[EventType.PROCESS_EXECUTION] = EventType.PROCESS_EXECUTION
    argv: List[str] = Field(default_factory=list)
    argv_truncated: bool = False
    filename_truncated: bool = False
    syscall: str = "execve"

    @property
    def command(self) -> str:
        if self.argv:
            return shlex.join(self.argv)
        return self.executable or self.comm

    @property
    def command_name(self) -> str:
        candidate = (self.argv[0] if self.argv else "") or self.executable or self.comm
        return Path(candidate).name


class ProcessForkEvent(BaseOSEvent):
    event_type: Literal[EventType.PROCESS_FORK] = EventType.PROCESS_FORK
    child_comm: str = ""


class ProcessExitEvent(BaseOSEvent):
    event_type: Literal[EventType.PROCESS_EXIT] = EventType.PROCESS_EXIT
    exit_code: int = 0
    signal: int = Field(default=0, ge=0)
    duration_ns: int = Field(default=0, ge=0)


class FileAccessEvent(BaseOSEvent):
    event_type: Literal[EventType.FILE_ACCESS] = EventType.FILE_ACCESS
    path: str
    raw_path: str
    fd: int = -1
    dirfd: int = -100
    flags: int = Field(default=0, ge=0)
    result: int = 0
    operation: str = "OPEN"
    write_intent: bool = False
    path_truncated: bool = False


class FileWriteEvent(BaseOSEvent):
    event_type: Literal[EventType.FILE_WRITE] = EventType.FILE_WRITE
    path: str
    raw_path: str
    fd: int = -1
    dirfd: int = -100
    bytes_written: int = Field(default=0, ge=0)
    result: int = 0
    path_truncated: bool = False


class FileDeleteEvent(BaseOSEvent):
    event_type: Literal[EventType.FILE_DELETE] = EventType.FILE_DELETE
    path: str
    raw_path: str
    dirfd: int = -100
    result: int = 0
    path_truncated: bool = False


class NetworkConnectionEvent(BaseOSEvent):
    event_type: Literal[EventType.NETWORK_CONNECTION] = EventType.NETWORK_CONNECTION
    remote_addr: str
    remote_port: int = Field(ge=0, le=65535)
    family: int = Field(default=0, ge=0)
    protocol: str = "tcp"
    result: int = 0


class LLMInteractionEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=new_event_id, min_length=1)
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: Literal[EventType.LLM_INTERACTION] = EventType.LLM_INTERACTION
    session_id: str = Field(min_length=1)
    request_id: Optional[str] = None
    pid: Optional[int] = Field(default=None, ge=0)
    llm_provider: str = "unknown"
    model: str = "unknown"
    prompt: str
    response: Optional[str] = None
    duration_ms: Optional[int] = Field(default=None, ge=0)
    source: str = "agentsight"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _as_utc(value)


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=new_event_id, min_length=1)
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: Literal[EventType.SECURITY_EVENT] = EventType.SECURITY_EVENT
    type: Literal["AI_AGENT_SECURITY_EVENT"] = "AI_AGENT_SECURITY_EVENT"
    severity: EventSeverity
    session_id: str = Field(min_length=1)
    pid: int = Field(ge=0)
    ppid: int = Field(ge=0)
    action: str
    target: str
    rule_name: str
    rule_description: str
    raw_events: List[Dict[str, Any]] = Field(default_factory=list)
    correlation: Optional[CorrelationLink] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _as_utc(value)

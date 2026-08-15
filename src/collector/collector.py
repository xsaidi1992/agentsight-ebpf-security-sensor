"""Convert native ring-buffer JSON records into validated domain events."""
from __future__ import annotations

import logging
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import ValidationError

from src.models import (
    BaseOSEvent,
    FileAccessEvent,
    FileDeleteEvent,
    FileWriteEvent,
    NetworkConnectionEvent,
    ProcessExecutionEvent,
    ProcessExitEvent,
    ProcessForkEvent,
)

from .live_ebpf import LiveExecCollector

logger = logging.getLogger(__name__)


@dataclass
class CollectorMetrics:
    events_received: int = 0
    sequence_gap_events: int = 0
    estimated_sequence_drops: int = 0
    out_of_order_records: int = 0
    invalid_records: int = 0
    last_sequence: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)


class BPFEventCollector:
    ABI_VERSION = 2
    EVENT_TYPE_BY_RECORD = {
        "exec": 1,
        "fork": 2,
        "exit": 3,
        "file_open": 4,
        "file_write": 5,
        "file_delete": 6,
        "network_connect": 7,
    }

    def __init__(self, live: Optional[LiveExecCollector] = None):
        self.live = live or LiveExecCollector()
        self.running = False
        self.metrics_state = CollectorMetrics()
        self.boot_epoch_offset_ns = time.time_ns() - time.monotonic_ns()
        self.capture_id = uuid4().hex
        try:
            self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        except OSError:
            self.boot_id = "unknown-boot"

    @staticmethod
    def preflight() -> Dict[str, Any]:
        return LiveExecCollector.preflight()

    def start(
        self,
        *,
        root_pid: Optional[int] = None,
        tracked_pids: Optional[List[int]] = None,
    ) -> None:
        self.live.start(root_pid=root_pid, tracked_pids=tracked_pids)
        self.metrics_state = CollectorMetrics()
        self.boot_epoch_offset_ns = time.time_ns() - time.monotonic_ns()
        self.capture_id = uuid4().hex
        self.running = True

    def stop(self) -> None:
        self.running = False
        self.live.stop()

    def _timestamp(self, raw: Dict[str, Any]) -> tuple[datetime, int]:
        kernel_timestamp_ns = int(raw.get("timestamp_ns", 0))
        if kernel_timestamp_ns > 0:
            epoch_ns = self.boot_epoch_offset_ns + kernel_timestamp_ns
            return (
                datetime.fromtimestamp(epoch_ns / 1_000_000_000, tz=timezone.utc),
                kernel_timestamp_ns,
            )
        return datetime.now(timezone.utc), 0

    def _record_sequence(self, sequence: int) -> None:
        previous = self.metrics_state.last_sequence
        if previous > 0 and sequence > previous + 1:
            gap = sequence - previous - 1
            self.metrics_state.sequence_gap_events += 1
            self.metrics_state.estimated_sequence_drops += gap
            logger.warning("eBPF sequence gap detected: %s missing record(s)", gap)
        elif sequence > 0 and previous > 0 and sequence <= previous:
            self.metrics_state.out_of_order_records += 1
        if sequence > previous:
            self.metrics_state.last_sequence = sequence

    @staticmethod
    def _read_cwd(pid: int) -> str:
        try:
            return os.readlink(Path("/proc") / str(pid) / "cwd")
        except OSError:
            return "unknown"

    @staticmethod
    def _read_executable(pid: int) -> str:
        try:
            return os.readlink(Path("/proc") / str(pid) / "exe")
        except OSError:
            return ""

    @staticmethod
    def _read_fd_path(pid: int, fd: int) -> str:
        if fd < 0:
            return ""
        try:
            return os.readlink(Path("/proc") / str(pid) / "fd" / str(fd))
        except OSError:
            return ""

    @classmethod
    def _resolve_path(cls, pid: int, raw_path: str, dirfd: int) -> tuple[str, str]:
        if not raw_path:
            return raw_path, "unknown"
        path = Path(raw_path)
        if path.is_absolute():
            return str(path), cls._read_cwd(pid)
        base = "unknown"
        try:
            if dirfd == -100:
                base = os.readlink(Path("/proc") / str(pid) / "cwd")
            elif dirfd >= 0:
                base = os.readlink(Path("/proc") / str(pid) / "fd" / str(dirfd))
        except OSError:
            pass
        if base != "unknown":
            return os.path.normpath(str(Path(base) / path)), base
        return raw_path, base

    def _common(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        timestamp, kernel_timestamp_ns = self._timestamp(raw)
        sequence = int(raw.get("sequence", 0))
        self._record_sequence(sequence)
        event_id = (
            f"kernel:{self.boot_id}:{self.capture_id}:{sequence}"
            if sequence > 0
            else (
                f"kernel:{self.boot_id}:{self.capture_id}:"
                f"{raw.get('record_type')}:{kernel_timestamp_ns}:{raw.get('pid', 0)}"
            )
        )
        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "pid": int(raw["pid"]),
            "ppid": int(raw.get("ppid", 0)),
            "uid": int(raw.get("uid", 0)),
            "gid": int(raw.get("gid", 0)),
            "comm": str(raw.get("comm", "")),
            "sequence": sequence,
            "kernel_timestamp_ns": kernel_timestamp_ns,
            "process_start_ns": int(raw.get("process_start_ns", 0)),
            "parent_start_ns": int(raw.get("parent_start_ns", 0)),
            "source": "ebpf",
        }

    def decode_record(self, raw: Dict[str, Any]) -> Optional[BaseOSEvent]:
        record_type = str(raw.get("record_type", ""))
        expected_type = self.EVENT_TYPE_BY_RECORD.get(record_type)
        if expected_type is None:
            return None
        try:
            version = int(raw.get("version", 0))
            event_type = int(raw.get("event_type", 0))
            if version != self.ABI_VERSION or event_type != expected_type:
                raise ValueError(
                    f"unsupported kernel ABI version/type: {version}/{event_type} for {record_type}"
                )
            common = self._common(raw)

            if record_type == "exec":
                syscall = "execveat" if int(raw.get("syscall_kind", 1)) == 2 else "execve"
                kernel_filename = str(raw.get("filename", ""))
                proc_executable = self._read_executable(common["pid"])
                executable = proc_executable or kernel_filename
                argv = [str(item) for item in raw.get("argv", [])]
                if not argv and executable:
                    argv = [executable]
                metadata = {
                    "kernel_filename": kernel_filename,
                    "executable_resolution": (
                        "procfs" if proc_executable else "syscall-argument"
                    ),
                    "sensor_capture_id": self.capture_id,
                }
                event: BaseOSEvent = ProcessExecutionEvent(
                    **common,
                    executable=executable,
                    argv=argv,
                    argv_truncated=bool(raw.get("argv_truncated", False)),
                    filename_truncated=bool(raw.get("filename_truncated", False)),
                    syscall=syscall,
                    cwd=self._read_cwd(common["pid"]),
                    metadata=metadata,
                )
            elif record_type == "fork":
                event = ProcessForkEvent(
                    **common,
                    child_comm=str(raw.get("child_comm", raw.get("comm", ""))),
                    cwd=self._read_cwd(common["pid"]),
                )
            elif record_type == "exit":
                event = ProcessExitEvent(
                    **common,
                    exit_code=int(raw.get("exit_code", 0)),
                    signal=int(raw.get("signal", 0)),
                    duration_ns=int(raw.get("duration_ns", 0)),
                )
            elif record_type in {"file_open", "file_write", "file_delete"}:
                raw_path = str(raw.get("path", ""))
                fd = int(raw.get("fd", -1))
                dirfd = int(raw.get("dirfd", -100))
                path_resolution = "kernel-open-map" if raw_path else "unresolved"
                # A process can write through an FD inherited across fork. The
                # eBPF map cannot cheaply clone every parent descriptor, so the
                # kernel still emits the write and userspace makes a best-effort
                # /proc/<pid>/fd lookup while the descriptor is live.
                if record_type == "file_write" and not raw_path:
                    fd_path = self._read_fd_path(common["pid"], fd)
                    if fd_path:
                        raw_path = fd_path
                        dirfd = -100
                        path_resolution = "procfs-fd"
                path, cwd = self._resolve_path(common["pid"], raw_path, dirfd)
                if not path and record_type == "file_write":
                    path = f"fd:{fd}"
                file_metadata = {
                    "path_resolution": path_resolution,
                    "sensor_capture_id": self.capture_id,
                }
                if record_type == "file_open":
                    flags = int(raw.get("open_flags", 0))
                    write_mask = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
                    event = FileAccessEvent(
                        **common,
                        executable="",
                        cwd=cwd,
                        path=path,
                        raw_path=raw_path,
                        fd=fd,
                        dirfd=dirfd,
                        flags=flags,
                        result=int(raw.get("result", 0)),
                        write_intent=bool(flags & write_mask),
                        path_truncated=bool(raw.get("path_truncated", False)),
                        metadata=file_metadata,
                    )
                elif record_type == "file_write":
                    event = FileWriteEvent(
                        **common,
                        executable="",
                        cwd=cwd,
                        path=path,
                        raw_path=raw_path,
                        fd=fd,
                        dirfd=dirfd,
                        bytes_written=int(raw.get("bytes", 0)),
                        result=int(raw.get("result", 0)),
                        path_truncated=bool(raw.get("path_truncated", False)),
                        metadata=file_metadata,
                    )
                else:
                    event = FileDeleteEvent(
                        **common,
                        executable="",
                        cwd=cwd,
                        path=path,
                        raw_path=raw_path,
                        dirfd=dirfd,
                        result=int(raw.get("result", 0)),
                        path_truncated=bool(raw.get("path_truncated", False)),
                        metadata=file_metadata,
                    )
            else:
                connect_result = int(raw.get("result", 0))
                event = NetworkConnectionEvent(
                    **common,
                    executable="",
                    cwd=self._read_cwd(common["pid"]),
                    remote_addr=str(raw.get("remote_addr", "unknown")),
                    remote_port=int(raw.get("remote_port", 0)),
                    family=int(raw.get("family", 0)),
                    result=connect_result,
                    metadata={
                        "connection_state": (
                            "connected" if connect_result == 0 else "in_progress"
                        ),
                        "sensor_capture_id": self.capture_id,
                    },
                )

            self.metrics_state.events_received += 1
            self.metrics_state.by_type[record_type] = self.metrics_state.by_type.get(record_type, 0) + 1
            return event
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            self.metrics_state.invalid_records += 1
            logger.warning("invalid eBPF record ignored: %s", exc)
            return None

    def poll(self, timeout: float = 0.25, max_events: int = 512) -> List[BaseOSEvent]:
        if not self.running:
            return []
        decoded: List[BaseOSEvent] = []
        for raw in self.live.poll(timeout=timeout, max_events=max_events):
            event = self.decode_record(raw)
            if event is not None:
                decoded.append(event)
        return decoded

    def metrics(self) -> Dict[str, Any]:
        return {**asdict(self.metrics_state), **self.live.metrics()}

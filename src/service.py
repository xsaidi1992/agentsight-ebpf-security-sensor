"""Long-running service that correlates a live eBPF sensor with sessions."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from src.collector import AgentSightRuntime, BPFEventCollector
from src.models import LLMInteractionEvent, ProcessExecutionEvent


def _proc_stat(pid: int) -> tuple[int, int]:
    stat_path = Path("/proc") / str(pid) / "stat"
    stat_text = stat_path.read_text(encoding="utf-8")
    close_paren = stat_text.rfind(")")
    if close_paren < 0:
        raise ValueError(f"unable to parse {stat_path}")
    fields = stat_text[close_paren + 2 :].split()
    if len(fields) < 20:
        raise ValueError(f"incomplete process stat: {stat_path}")
    ppid = int(fields[1])
    start_ticks = int(fields[19])
    return ppid, start_ticks


def _boot_epoch_seconds() -> float:
    try:
        for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    # Approximate the Unix boot epoch from two monotonic clock readings.
    # This is more accurate than returning "now" for a process that may have
    # started long before this service, and it keeps the process start time on
    # the same basis as /proc/<pid>/stat.
    return time.time() - time.monotonic()


def _start_ns(pid: int) -> int:
    try:
        _, ticks = _proc_stat(pid)
        hz = int(os.sysconf("SC_CLK_TCK"))
        return int(ticks * 1_000_000_000 // hz)
    except (OSError, ProcessLookupError, ValueError):
        return 0


def process_event_from_proc(pid: int) -> ProcessExecutionEvent:
    """Register an already-running process without modifying that process."""
    proc = Path("/proc") / str(pid)
    if not proc.exists():
        raise ProcessLookupError(pid)

    ppid, start_ticks = _proc_stat(pid)
    hz = int(os.sysconf("SC_CLK_TCK"))
    process_start_ns = int(start_ticks * 1_000_000_000 // hz)
    timestamp = datetime.fromtimestamp(
        _boot_epoch_seconds() + (start_ticks / hz),
        tz=timezone.utc,
    )

    uid = 0
    gid = 0
    for line in (proc / "status").read_text(encoding="utf-8").splitlines():
        if line.startswith("Uid:"):
            uid = int(line.split()[1])
        elif line.startswith("Gid:"):
            gid = int(line.split()[1])

    try:
        executable = os.readlink(proc / "exe")
    except OSError:
        executable = ""
    raw_cmdline = (proc / "cmdline").read_bytes().split(b"\0")
    argv = [item.decode("utf-8", errors="replace") for item in raw_cmdline if item]
    comm = (proc / "comm").read_text(encoding="utf-8").strip()
    try:
        cwd = os.readlink(proc / "cwd")
    except OSError:
        cwd = "unknown"

    return ProcessExecutionEvent(
        event_id=f"procfs:{pid}:{process_start_ns}",
        timestamp=timestamp,
        pid=pid,
        ppid=ppid,
        uid=uid,
        gid=gid,
        comm=comm,
        executable=executable,
        argv=argv,
        cwd=cwd,
        process_start_ns=process_start_ns,
        parent_start_ns=_start_ns(ppid),
        source="procfs-registration",
        syscall="procfs",
    )


def discover_process_tree(root_pid: int) -> List[int]:
    """Return root and existing descendants in breadth-first order."""
    if root_pid <= 0:
        raise ValueError("root_pid must be positive")
    if not (Path("/proc") / str(root_pid)).exists():
        raise ProcessLookupError(root_pid)
    parent_by_pid: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            ppid, _ = _proc_stat(pid)
        except (OSError, ProcessLookupError, ValueError):
            continue
        parent_by_pid[pid] = ppid

    children: dict[int, List[int]] = {}
    for pid, ppid in parent_by_pid.items():
        children.setdefault(ppid, []).append(pid)
    result: List[int] = []
    queue = [root_pid]
    seen: set[int] = set()
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        result.append(pid)
        queue.extend(sorted(children.get(pid, [])))
    return result


class LiveSensorService:
    GATED_EXEC_CODE = (
        "import os,signal,sys;"
        "os.kill(os.getpid(),signal.SIGSTOP);"
        "os.execvp(sys.argv[1],sys.argv[1:])"
    )

    def __init__(
        self,
        collector: Optional[BPFEventCollector] = None,
        runtime: Optional[AgentSightRuntime] = None,
    ):
        self.collector = collector or BPFEventCollector()
        self.runtime = runtime or AgentSightRuntime()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._owned_process: Optional[subprocess.Popen[bytes]] = None
        self._state_lock = threading.RLock()
        self._starting = False
        self.last_error: Optional[str] = None

    def _ensure_stopped(self) -> None:
        if self._starting:
            raise RuntimeError("sensor service is already starting")
        if self._thread and self._thread.is_alive():
            raise RuntimeError("sensor service is already running")
        if self._owned_process and self._owned_process.poll() is None:
            raise RuntimeError("sensor service already owns a running process")

    def _begin_start(self) -> None:
        with self._state_lock:
            self._ensure_stopped()
            self._starting = True
            self.last_error = None

    def _finish_start(self) -> None:
        with self._state_lock:
            self._starting = False

    def _start_loop(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._collect_loop,
            name="agentsight-runtime",
            daemon=True,
        )
        self._thread.start()

    @staticmethod
    def _wait_for_pre_exec_stop(
        process: subprocess.Popen[bytes], timeout_seconds: float = 5.0
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            waited_pid, status = os.waitpid(
                process.pid, os.WUNTRACED | os.WNOHANG
            )
            if waited_pid == 0:
                time.sleep(0.01)
                continue
            if waited_pid != process.pid:
                continue
            if os.WIFSTOPPED(status):
                return
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                process.returncode = os.waitstatus_to_exitcode(status)
                raise RuntimeError(
                    "gated agent exited before reaching the pre-exec stop"
                )
        raise TimeoutError(
            f"gated agent did not stop before exec within {timeout_seconds:g}s"
        )

    def start_existing(
        self,
        root_pid: int,
        session_id: str,
        agent_name: str,
        llm_events: Optional[Iterable[LLMInteractionEvent]] = None,
    ) -> None:
        if root_pid <= 0:
            raise ValueError("root_pid must be positive")
        self._begin_start()
        collector_started = False
        try:
            tree = discover_process_tree(root_pid)
            root_event = process_event_from_proc(root_pid)
            self.collector.start(root_pid=root_pid, tracked_pids=tree[1:])
            collector_started = True
            self.runtime.create_session(session_id, agent_name, root_event)
            for event in llm_events or []:
                self.runtime.record_llm_interaction(
                    event.model_copy(update={"session_id": session_id})
                )
            for pid in tree[1:]:
                try:
                    self.runtime.ingest(process_event_from_proc(pid))
                except (OSError, ProcessLookupError, ValueError):
                    continue
            self._start_loop()
        except Exception:
            if collector_started:
                self.collector.stop()
            raise
        finally:
            self._finish_start()

    def start(
        self,
        root_pid: int,
        session_id: str,
        agent_name: str,
        llm_events: Optional[Iterable[LLMInteractionEvent]] = None,
    ) -> None:
        """Backward-compatible alias for attaching to an existing root PID."""
        self.start_existing(root_pid, session_id, agent_name, llm_events=llm_events)

    def start_command(
        self,
        command: Sequence[str],
        session_id: str,
        agent_name: str,
        llm_events: Optional[Iterable[LLMInteractionEvent]] = None,
        *,
        stdout=None,
        stderr=None,
    ) -> subprocess.Popen[bytes]:
        """Launch a command behind SIGSTOP so no first exec is missed.

        The temporary Python child stops before exec. The sensor is attached and
        the root PID is inserted into the kernel filter, then the child resumes
        and execs the requested agent command under observation.
        """
        normalized_command = [str(item) for item in command]
        if not normalized_command or not normalized_command[0]:
            raise ValueError("command must not be empty")
        self._begin_start()
        process: Optional[subprocess.Popen[bytes]] = None
        collector_started = False
        try:
            process = subprocess.Popen(
                [sys.executable, "-c", self.GATED_EXEC_CODE, *normalized_command],
                stdout=stdout,
                stderr=stderr,
            )
            with self._state_lock:
                self._owned_process = process
            self._wait_for_pre_exec_stop(process)
            root_event = process_event_from_proc(process.pid)
            self.collector.start(root_pid=process.pid)
            collector_started = True
            self.runtime.create_session(session_id, agent_name, root_event)
            for event in llm_events or []:
                self.runtime.record_llm_interaction(
                    event.model_copy(update={"session_id": session_id})
                )
            self._start_loop()
            os.kill(process.pid, signal.SIGCONT)
            return process
        except Exception:
            if process is not None:
                try:
                    os.kill(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            if collector_started:
                self.collector.stop()
            with self._state_lock:
                self._owned_process = None
            raise
        finally:
            self._finish_start()

    def _collect_loop(self) -> None:
        try:
            while not self._stop.is_set():
                events = self.collector.poll(timeout=0.25)
                for event in events:
                    self.runtime.ingest(event)
        except Exception as exc:  # keep the API alive but expose the failure
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._stop.set()

    def stop(self, terminate_owned_process: bool = True) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self.collector.stop()
        process = self._owned_process
        if terminate_owned_process and process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        self._owned_process = None
        self._thread = None

    def metrics(self) -> dict:
        return {
            **self.collector.metrics(),
            **self.runtime.metrics(),
            "service_error": self.last_error,
            "service_running": int(bool(self._thread and self._thread.is_alive())),
            "service_starting": int(self._starting),
        }

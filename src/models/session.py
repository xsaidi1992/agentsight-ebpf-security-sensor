"""Agent-session state, process lineage, and chronological correlation."""
from __future__ import annotations

from bisect import bisect_right
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Union

from pydantic import BaseModel, ConfigDict, Field

from .events import (
    BaseOSEvent,
    CorrelationLink,
    FileAccessEvent,
    FileDeleteEvent,
    FileWriteEvent,
    LLMInteractionEvent,
    NetworkConnectionEvent,
    ProcessExecutionEvent,
    ProcessExitEvent,
    ProcessForkEvent,
    SecurityEvent,
)

TimelineModel = Union[BaseOSEvent, LLMInteractionEvent, SecurityEvent]


def _aware_timestamp(raw: object) -> datetime:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, str):
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return datetime.min.replace(tzinfo=timezone.utc)


def _timeline_sort_key(payload: Dict) -> tuple[datetime, int, str]:
    return (
        _aware_timestamp(payload.get("timestamp")),
        int(payload.get("sequence", 0) or 0),
        str(payload.get("event_id", "")),
    )


class ProcessNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity: str
    generation: int = Field(ge=1)
    pid: int = Field(ge=0)
    ppid: int = Field(ge=0)
    parent_identity: Optional[str] = None
    process_start_ns: int = Field(default=0, ge=0)
    parent_start_ns: int = Field(default=0, ge=0)
    comm: str = ""
    executable: str = ""
    argv: List[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    end_time: Optional[datetime] = None
    status: str = "RUNNING"
    exit_code: Optional[int] = None
    signal: Optional[int] = None
    exec_count: int = Field(default=0, ge=0)
    sequence: int = Field(default=0, ge=0)
    observed_via: str = "exec"
    children: Set[str] = Field(default_factory=set)


class SessionTimeline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: List[Dict] = Field(default_factory=list)
    # Internal index: serialized API/session output still contains only events.
    event_ids: Set[str] = Field(default_factory=set, exclude=True)

    def model_post_init(self, __context: object) -> None:
        self.event_ids.update(
            str(item["event_id"])
            for item in self.events
            if item.get("event_id")
        )

    def contains(self, event_id: str) -> bool:
        return bool(event_id) and event_id in self.event_ids

    def add(self, event: TimelineModel) -> bool:
        event_id = getattr(event, "event_id", None)
        if event_id and self.contains(event_id):
            return False
        payload = event.model_dump(mode="json")
        key = _timeline_sort_key(payload)
        # Binary insertion preserves chronological ordering without sorting the
        # complete timeline after every kernel event.
        low, high = 0, len(self.events)
        while low < high:
            middle = (low + high) // 2
            if _timeline_sort_key(self.events[middle]) <= key:
                low = middle + 1
            else:
                high = middle
        self.events.insert(low, payload)
        if event_id:
            self.event_ids.add(str(event_id))
        return True


class SessionSummary(BaseModel):
    session_id: str
    agent_name: str
    active: bool
    total_processes: int
    active_processes: int
    total_timeline_events: int
    total_security_events: int
    llm_interactions: int
    unique_files: int
    network_connections: int
    duration_seconds: float


class AgentSession(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    agent_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    main_pid: int
    main_ppid: int
    main_executable: str
    main_command: str
    main_identity: Optional[str] = None
    processes: Dict[str, ProcessNode] = Field(default_factory=dict)
    latest_process_by_pid: Dict[int, str] = Field(default_factory=dict)
    pid_generations: Dict[int, int] = Field(default_factory=dict)
    timeline: SessionTimeline = Field(default_factory=SessionTimeline)
    llm_interactions: List[LLMInteractionEvent] = Field(default_factory=list)
    security_events: List[SecurityEvent] = Field(default_factory=list)
    files_accessed: Set[str] = Field(default_factory=set)
    network_events: List[NetworkConnectionEvent] = Field(default_factory=list)
    correlation_window_seconds: int = Field(default=300, ge=1)

    def _next_identity(self, pid: int) -> tuple[str, int]:
        generation = self.pid_generations.get(pid, 0) + 1
        self.pid_generations[pid] = generation
        identity = f"{pid}:{generation}"
        self.latest_process_by_pid[pid] = identity
        return identity, generation

    def _latest_node(self, pid: int) -> Optional[ProcessNode]:
        identity = self.latest_process_by_pid.get(pid)
        return self.processes.get(identity) if identity else None

    def _node_for_event(self, event: BaseOSEvent) -> Optional[ProcessNode]:
        node = self._latest_node(event.pid)
        if node is None:
            return None
        if (
            event.process_start_ns
            and node.process_start_ns
            and event.process_start_ns != node.process_start_ns
        ):
            return None
        return node

    def _parent_identity(self, ppid: int, parent_start_ns: int = 0) -> Optional[str]:
        identity = self.latest_process_by_pid.get(ppid)
        parent = self.processes.get(identity) if identity else None
        if parent is None:
            return None
        if (
            parent_start_ns
            and parent.process_start_ns
            and parent_start_ns != parent.process_start_ns
        ):
            return None
        return identity

    def _link_parent(self, node: ProcessNode) -> None:
        parent_identity = self._parent_identity(node.ppid, node.parent_start_ns)
        if node.parent_identity and node.parent_identity != parent_identity:
            previous_parent = self.processes.get(node.parent_identity)
            if previous_parent:
                previous_parent.children.discard(node.identity)
        node.parent_identity = parent_identity
        if parent_identity and parent_identity in self.processes:
            self.processes[parent_identity].children.add(node.identity)

    def _adopt_waiting_children(self, parent: ProcessNode) -> None:
        for child in self.processes.values():
            if child.identity == parent.identity or child.parent_identity is not None:
                continue
            if child.ppid != parent.pid:
                continue
            if (
                child.parent_start_ns
                and parent.process_start_ns
                and child.parent_start_ns != parent.process_start_ns
            ):
                continue
            child.parent_identity = parent.identity
            parent.children.add(child.identity)

    @staticmethod
    def _retire_reused_node(node: ProcessNode, timestamp: datetime) -> None:
        if node.status == "RUNNING":
            node.status = "REPLACED"
            node.end_time = timestamp
            node.last_seen = max(node.last_seen, timestamp)

    def _create_node(
        self,
        *,
        pid: int,
        ppid: int,
        process_start_ns: int,
        parent_start_ns: int,
        comm: str,
        executable: str,
        argv: List[str],
        timestamp: datetime,
        sequence: int,
        observed_via: str,
        exec_count: int,
    ) -> ProcessNode:
        identity, generation = self._next_identity(pid)
        node = ProcessNode(
            identity=identity,
            generation=generation,
            pid=pid,
            ppid=ppid,
            process_start_ns=process_start_ns,
            parent_start_ns=parent_start_ns,
            comm=comm,
            executable=executable,
            argv=list(argv),
            first_seen=timestamp,
            last_seen=timestamp,
            sequence=sequence,
            observed_via=observed_via,
            exec_count=exec_count,
        )
        self.processes[identity] = node
        self._link_parent(node)
        self._adopt_waiting_children(node)
        if pid == self.main_pid and self.main_identity is None:
            self.main_identity = identity
        return node

    def add_fork(self, event: ProcessForkEvent) -> ProcessNode:
        node = self._latest_node(event.pid)
        identity_conflict = bool(
            node
            and event.process_start_ns
            and node.process_start_ns
            and event.process_start_ns != node.process_start_ns
        )
        if node and node.status == "RUNNING" and not identity_conflict:
            node.ppid = event.ppid
            node.parent_start_ns = event.parent_start_ns or node.parent_start_ns
            node.comm = event.child_comm or event.comm or node.comm
            node.last_seen = max(node.last_seen, event.timestamp)
            node.sequence = max(node.sequence, event.sequence)
            self._link_parent(node)
            self.timeline.add(event)
            return node
        if node and identity_conflict:
            self._retire_reused_node(node, event.timestamp)
        node = self._create_node(
            pid=event.pid,
            ppid=event.ppid,
            process_start_ns=event.process_start_ns,
            parent_start_ns=event.parent_start_ns,
            comm=event.child_comm or event.comm,
            executable="",
            argv=[],
            timestamp=event.timestamp,
            sequence=event.sequence,
            observed_via="fork",
            exec_count=0,
        )
        self.timeline.add(event)
        return node

    def add_process(self, event: ProcessExecutionEvent) -> ProcessNode:
        node = self._latest_node(event.pid)
        process_reused = bool(
            node
            and node.status != "RUNNING"
            and event.process_start_ns
            and node.process_start_ns
            and event.process_start_ns != node.process_start_ns
        )
        conflicting_live_identity = bool(
            node
            and node.status == "RUNNING"
            and event.process_start_ns
            and node.process_start_ns
            and event.process_start_ns != node.process_start_ns
        )
        if node is None or process_reused or conflicting_live_identity:
            if node and conflicting_live_identity:
                self._retire_reused_node(node, event.timestamp)
            node = self._create_node(
                pid=event.pid,
                ppid=event.ppid,
                process_start_ns=event.process_start_ns,
                parent_start_ns=event.parent_start_ns,
                comm=event.comm,
                executable=event.executable,
                argv=event.argv,
                timestamp=event.timestamp,
                sequence=event.sequence,
                observed_via="exec",
                exec_count=1,
            )
        else:
            node.ppid = event.ppid
            node.process_start_ns = event.process_start_ns or node.process_start_ns
            node.parent_start_ns = event.parent_start_ns or node.parent_start_ns
            node.comm = event.comm or node.comm
            node.executable = event.executable or node.executable
            node.argv = list(event.argv) or node.argv
            node.last_seen = max(node.last_seen, event.timestamp)
            node.sequence = max(node.sequence, event.sequence)
            node.exec_count += 1
            node.observed_via = "fork+exec" if node.observed_via == "fork" else "exec"
            self._link_parent(node)
            self._adopt_waiting_children(node)

        if event.pid == self.main_pid:
            self.main_identity = node.identity
            self.main_ppid = event.ppid
            self.main_executable = event.executable or self.main_executable
            self.main_command = event.command or self.main_command
        self.timeline.add(event)
        return node

    def add_exit(self, event: ProcessExitEvent) -> Optional[ProcessNode]:
        node = self._node_for_event(event)
        if node:
            node.status = "EXITED"
            node.end_time = event.timestamp
            node.last_seen = max(node.last_seen, event.timestamp)
            node.exit_code = event.exit_code
            node.signal = event.signal
        self.timeline.add(event)
        # A root process may exit before a still-running descendant. Close the
        # session only when the complete observed process tree has terminated.
        if self.active_process_count() == 0:
            self.mark_ended(event.timestamp)
        return node

    def add_os_event(self, event: BaseOSEvent) -> bool:
        if self.timeline.contains(event.event_id):
            return False
        if isinstance(event, ProcessExecutionEvent):
            self.add_process(event)
            return True
        if isinstance(event, ProcessForkEvent):
            self.add_fork(event)
            return True
        if isinstance(event, ProcessExitEvent):
            self.add_exit(event)
            return True
        if isinstance(event, (FileAccessEvent, FileWriteEvent, FileDeleteEvent)):
            self.files_accessed.add(event.path)
        if isinstance(event, NetworkConnectionEvent):
            self.network_events.append(event)
        node = self._node_for_event(event)
        if node:
            node.last_seen = max(node.last_seen, event.timestamp)
        self.timeline.add(event)
        return True

    def _correlation_for(
        self,
        timestamp: datetime,
        pid: int = 0,
        ppid: int = 0,
    ) -> Optional[CorrelationLink]:
        if not self.llm_interactions:
            return None
        timestamps = [item.timestamp for item in self.llm_interactions]
        index = bisect_right(timestamps, timestamp) - 1
        if index < 0:
            return None
        llm_event = self.llm_interactions[index]
        latency_seconds = (timestamp - llm_event.timestamp).total_seconds()
        if latency_seconds < 0 or latency_seconds > self.correlation_window_seconds:
            return None

        if latency_seconds <= 5:
            confidence = 0.95
        elif latency_seconds <= 30:
            confidence = 0.85
        elif latency_seconds <= 120:
            confidence = 0.70
        else:
            confidence = 0.55

        method = "temporal_session_window"
        rationale = (
            "The OS event belongs to the same trusted process session and follows "
            "the nearest preceding AgentSight LLM interaction."
        )
        if llm_event.pid is not None and llm_event.pid in {pid, ppid}:
            method = "pid_and_temporal_session_window"
            confidence = min(0.99, confidence + 0.04)
            rationale = (
                "The event follows the nearest preceding AgentSight LLM interaction "
                "inside the same session and its process identity matches the event "
                "PID or parent PID."
            )
        return CorrelationLink(
            llm_event_id=llm_event.event_id,
            llm_request_id=llm_event.request_id,
            method=method,
            confidence=confidence,
            latency_ms=max(0, int(latency_seconds * 1000)),
            rationale=rationale,
            causal_proof=False,
        )

    def _backfill_correlations(self) -> None:
        """Annotate earlier timeline/security records after a late LLM import.

        AgentSight reports can be imported after kernel events were already
        collected.  Backfilling keeps the API timeline useful without claiming
        causal proof.  The immutable source event ID and raw record remain
        unchanged.
        """
        for payload in self.timeline.events:
            event_type = str(payload.get("event_type", ""))
            if event_type == "LLM_INTERACTION" or payload.get("correlation"):
                continue
            link = self._correlation_for(
                _aware_timestamp(payload.get("timestamp")),
                int(payload.get("pid", 0) or 0),
                int(payload.get("ppid", 0) or 0),
            )
            if link is not None:
                payload["correlation"] = link.model_dump(mode="json")

        self.network_events = [
            item
            if item.correlation
            else item.model_copy(
                update={
                    "correlation": self._correlation_for(
                        item.timestamp, item.pid, item.ppid
                    )
                }
            )
            for item in self.network_events
        ]
        self.security_events = [
            item
            if item.correlation
            else item.model_copy(
                update={
                    "correlation": self._correlation_for(
                        item.timestamp, item.pid, item.ppid
                    )
                }
            )
            for item in self.security_events
        ]

    def add_llm_interaction(self, event: LLMInteractionEvent) -> bool:
        if self.timeline.contains(event.event_id):
            return False
        self.llm_interactions.append(event)
        self.llm_interactions.sort(key=lambda item: (item.timestamp, item.event_id))
        added = self.timeline.add(event)
        if added:
            self._backfill_correlations()
        return added

    def add_security_event(self, event: SecurityEvent) -> bool:
        if self.timeline.contains(event.event_id):
            return False
        if event.correlation is None:
            event = event.model_copy(
                update={
                    "correlation": self._correlation_for(
                        event.timestamp, event.pid, event.ppid
                    )
                }
            )
        self.security_events.append(event)
        self.security_events.sort(key=lambda item: (item.timestamp, item.event_id))
        return self.timeline.add(event)

    def correlate_os_event(self, event: BaseOSEvent) -> BaseOSEvent:
        if event.correlation:
            return event
        link = self._correlation_for(event.timestamp, event.pid, event.ppid)
        return event if link is None else event.model_copy(update={"correlation": link})

    def active_process_count(self) -> int:
        return sum(1 for process in self.processes.values() if process.status == "RUNNING")

    def get_process_tree(self) -> Dict:
        root_identity = self.main_identity or self.latest_process_by_pid.get(self.main_pid)
        visiting: Set[str] = set()

        def build(identity: str) -> Dict:
            if identity in visiting:
                return {"identity": identity, "cycle": True, "children": []}
            node = self.processes.get(identity)
            if node is None:
                return {"identity": identity, "comm": "unknown", "children": []}
            visiting.add(identity)
            result = {
                "identity": node.identity,
                "pid": node.pid,
                "ppid": node.ppid,
                "generation": node.generation,
                "comm": node.comm,
                "executable": node.executable,
                "argv": node.argv,
                "status": node.status,
                "process_start_ns": node.process_start_ns,
                "children": [build(child) for child in sorted(node.children)],
            }
            visiting.remove(identity)
            return result

        if not root_identity:
            return {"pid": self.main_pid, "comm": "unknown", "children": []}
        return build(root_identity)

    def is_active(self) -> bool:
        return self.end_time is None

    def mark_ended(self, when: Optional[datetime] = None) -> None:
        self.end_time = when or datetime.now(timezone.utc)

    def summary(self) -> SessionSummary:
        end = self.end_time or datetime.now(timezone.utc)
        return SessionSummary(
            session_id=self.session_id,
            agent_name=self.agent_name,
            active=self.is_active(),
            total_processes=len(self.processes),
            active_processes=self.active_process_count(),
            total_timeline_events=len(self.timeline.events),
            total_security_events=len(self.security_events),
            llm_interactions=len(self.llm_interactions),
            unique_files=len(self.files_accessed),
            network_connections=len(self.network_events),
            duration_seconds=max(0.0, (end - self.start_time).total_seconds()),
        )

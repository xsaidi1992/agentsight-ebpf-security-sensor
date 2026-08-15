"""Agent-session state, process lineage, and chronological correlation."""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# Rôle du module : reconstruire la session, les générations de PID, l’arbre de processus et la timeline corrélée.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


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

# [BESOIN C/E] Attribut `TimelineModel` : porte une donnée nécessaire au rôle du composant.
TimelineModel = Union[BaseOSEvent, LLMInteractionEvent, SecurityEvent]


# [BESOIN C/E] Fonction `_aware_timestamp` : fonction dédiée à l’opération `_aware_timestamp` dans le
# flux qui consiste à reconstruire la session, les générations de PID, l’arbre de processus
# et la timeline corrélée.
def _aware_timestamp(raw: object) -> datetime:
    # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux fonctionnel.
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux fonctionnel.
    if isinstance(raw, str):
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return datetime.min.replace(tzinfo=timezone.utc)


# [BESOIN C/E] Fonction `_timeline_sort_key` : fonction dédiée à l’opération `_timeline_sort_key` dans
# le flux qui consiste à reconstruire la session, les générations de PID, l’arbre de
# processus et la timeline corrélée.
def _timeline_sort_key(payload: Dict) -> tuple[datetime, int, str]:
    return (
        _aware_timestamp(payload.get("timestamp")),
        int(payload.get("sequence", 0) or 0),
        str(payload.get("event_id", "")),
    )


# [BESOIN C/E] Classe `ProcessNode` : classe dédiée à l’opération `ProcessNode` dans le flux qui
# consiste à reconstruire la session, les générations de PID, l’arbre de processus et la
# timeline corrélée.
class ProcessNode(BaseModel):
    # [BESOIN C/E] Attribut `model_config` : porte une donnée nécessaire au rôle du composant.
    model_config = ConfigDict(extra="forbid")

    # [BESOIN C/E] Attribut `identity` : porte une donnée nécessaire au rôle du composant.
    identity: str
    # [BESOIN C/E] Attribut `generation` : porte une donnée nécessaire au rôle du composant.
    generation: int = Field(ge=1)
    # [BESOIN C/E] Champ `pid` : PID du processus réellement observé, utilisé pour les filtres et le
    # rattachement de session.
    pid: int = Field(ge=0)
    # [BESOIN C/E] Champ `ppid` : PID du parent, nécessaire à la reconstruction de l’arbre demandé.
    ppid: int = Field(ge=0)
    # [BESOIN C/E] Attribut `parent_identity` : porte une donnée nécessaire au rôle du composant.
    parent_identity: Optional[str] = None
    # [BESOIN C/E] Champ `process_start_ns` : temps de démarrage du processus, combiné au PID pour
    # résister au PID reuse.
    process_start_ns: int = Field(default=0, ge=0)
    # [BESOIN C/E] Champ `parent_start_ns` : temps de démarrage du parent, utilisé pour éviter une
    # filiation erronée.
    parent_start_ns: int = Field(default=0, ge=0)
    # [BESOIN C/E] Champ `comm` : nom court du processus fourni par le kernel.
    comm: str = ""
    # [BESOIN C/E] Champ `executable` : chemin de l’exécutable réellement lancé.
    executable: str = ""
    # [BESOIN C/E] Champ `argv` : arguments bornés capturés pour reconstituer la commande.
    argv: List[str] = Field(default_factory=list)
    # [BESOIN C/E] Attribut `first_seen` : porte une donnée nécessaire au rôle du composant.
    first_seen: datetime
    # [BESOIN C/E] Attribut `last_seen` : porte une donnée nécessaire au rôle du composant.
    last_seen: datetime
    # [BESOIN C/E] Attribut `end_time` : porte une donnée nécessaire au rôle du composant.
    end_time: Optional[datetime] = None
    # [BESOIN C/E] Attribut `status` : porte une donnée nécessaire au rôle du composant.
    status: str = "RUNNING"
    # [BESOIN C/E] Attribut `exit_code` : porte une donnée nécessaire au rôle du composant.
    exit_code: Optional[int] = None
    # [BESOIN C/E] Attribut `signal` : porte une donnée nécessaire au rôle du composant.
    signal: Optional[int] = None
    # [BESOIN C/E] Attribut `exec_count` : porte une donnée nécessaire au rôle du composant.
    exec_count: int = Field(default=0, ge=0)
    # [BESOIN C/E] Champ `sequence` : séquence kernel utilisée pour détecter les trous et pertes de
    # transport.
    sequence: int = Field(default=0, ge=0)
    # [BESOIN C/E] Attribut `observed_via` : porte une donnée nécessaire au rôle du composant.
    observed_via: str = "exec"
    # [BESOIN C/E] Attribut `children` : porte une donnée nécessaire au rôle du composant.
    children: Set[str] = Field(default_factory=set)


# [BESOIN C/E] Classe `SessionTimeline` : classe dédiée à l’opération `SessionTimeline` dans le flux qui
# consiste à reconstruire la session, les générations de PID, l’arbre de processus et la
# timeline corrélée.
class SessionTimeline(BaseModel):
    # [BESOIN C/E] Attribut `model_config` : porte une donnée nécessaire au rôle du composant.
    model_config = ConfigDict(extra="forbid")

    # [BESOIN C/E] Attribut `events` : porte une donnée nécessaire au rôle du composant.
    events: List[Dict] = Field(default_factory=list)
    # Internal index: serialized API/session output still contains only events.
    # [BESOIN C/E] Attribut `event_ids` : porte une donnée nécessaire au rôle du composant.
    event_ids: Set[str] = Field(default_factory=set, exclude=True)

    # [BESOIN C/E] Fonction `model_post_init` : fonction dédiée à l’opération `model_post_init` dans le
    # flux qui consiste à reconstruire la session, les générations de PID, l’arbre de
    # processus et la timeline corrélée.
    def model_post_init(self, __context: object) -> None:
        self.event_ids.update(
            str(item["event_id"])
            for item in self.events
            if item.get("event_id")
        )

    # [BESOIN C/E] Fonction `contains` : fonction dédiée à l’opération `contains` dans le flux qui
    # consiste à reconstruire la session, les générations de PID, l’arbre de processus et
    # la timeline corrélée.
    def contains(self, event_id: str) -> bool:
        return bool(event_id) and event_id in self.event_ids

    # [BESOIN C/E] Fonction `add` : fonction dédiée à l’opération `add` dans le flux qui consiste à
    # reconstruire la session, les générations de PID, l’arbre de processus et la timeline
    # corrélée.
    def add(self, event: TimelineModel) -> bool:
        event_id = getattr(event, "event_id", None)
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if event_id and self.contains(event_id):
            return False
        payload = event.model_dump(mode="json")
        key = _timeline_sort_key(payload)
        # Binary insertion preserves chronological ordering without sorting the
        # complete timeline after every kernel event.
        low, high = 0, len(self.events)
        # [BESOIN C/E] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la condition
        # d’arrêt.
        while low < high:
            middle = (low + high) // 2
            # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if _timeline_sort_key(self.events[middle]) <= key:
                low = middle + 1
            else:
                high = middle
        self.events.insert(low, payload)
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if event_id:
            self.event_ids.add(str(event_id))
        return True


# [BESOIN C/E] Classe `SessionSummary` : classe dédiée à l’opération `SessionSummary` dans le flux qui
# consiste à reconstruire la session, les générations de PID, l’arbre de processus et la
# timeline corrélée.
class SessionSummary(BaseModel):
    # [BESOIN C/E] Champ `session_id` : identifiant de l’Agent Session à laquelle appartient l’élément.
    session_id: str
    # [BESOIN C/E] Attribut `agent_name` : porte une donnée nécessaire au rôle du composant.
    agent_name: str
    # [BESOIN C/E] Attribut `active` : porte une donnée nécessaire au rôle du composant.
    active: bool
    # [BESOIN C/E] Attribut `total_processes` : porte une donnée nécessaire au rôle du composant.
    total_processes: int
    # [BESOIN C/E] Attribut `active_processes` : porte une donnée nécessaire au rôle du composant.
    active_processes: int
    # [BESOIN C/E] Attribut `total_timeline_events` : porte une donnée nécessaire au rôle du composant.
    total_timeline_events: int
    # [BESOIN C/E] Attribut `total_security_events` : porte une donnée nécessaire au rôle du composant.
    total_security_events: int
    # [BESOIN C/E] Attribut `llm_interactions` : porte une donnée nécessaire au rôle du composant.
    llm_interactions: int
    # [BESOIN C/E] Attribut `unique_files` : porte une donnée nécessaire au rôle du composant.
    unique_files: int
    # [BESOIN C/E] Attribut `network_connections` : porte une donnée nécessaire au rôle du composant.
    network_connections: int
    # [BESOIN C/E] Attribut `duration_seconds` : porte une donnée nécessaire au rôle du composant.
    duration_seconds: float


# [BESOIN C/E] Classe `AgentSession` : classe dédiée à l’opération `AgentSession` dans le flux qui
# consiste à reconstruire la session, les générations de PID, l’arbre de processus et la
# timeline corrélée.
class AgentSession(BaseModel):
    # [BESOIN C/E] Attribut `model_config` : porte une donnée nécessaire au rôle du composant.
    model_config = ConfigDict(extra="forbid")

    # [BESOIN C/E] Champ `session_id` : identifiant de l’Agent Session à laquelle appartient l’élément.
    session_id: str
    # [BESOIN C/E] Attribut `agent_name` : porte une donnée nécessaire au rôle du composant.
    agent_name: str
    # [BESOIN C/E] Attribut `start_time` : porte une donnée nécessaire au rôle du composant.
    start_time: datetime
    # [BESOIN C/E] Attribut `end_time` : porte une donnée nécessaire au rôle du composant.
    end_time: Optional[datetime] = None
    # [BESOIN C/E] Attribut `main_pid` : porte une donnée nécessaire au rôle du composant.
    main_pid: int
    # [BESOIN C/E] Attribut `main_ppid` : porte une donnée nécessaire au rôle du composant.
    main_ppid: int
    # [BESOIN C/E] Attribut `main_executable` : porte une donnée nécessaire au rôle du composant.
    main_executable: str
    # [BESOIN C/E] Attribut `main_command` : porte une donnée nécessaire au rôle du composant.
    main_command: str
    # [BESOIN C/E] Attribut `main_identity` : porte une donnée nécessaire au rôle du composant.
    main_identity: Optional[str] = None
    # [BESOIN C/E] Attribut `processes` : porte une donnée nécessaire au rôle du composant.
    processes: Dict[str, ProcessNode] = Field(default_factory=dict)
    # [BESOIN C/E] Attribut `latest_process_by_pid` : porte une donnée nécessaire au rôle du composant.
    latest_process_by_pid: Dict[int, str] = Field(default_factory=dict)
    # [BESOIN C/E] Attribut `pid_generations` : porte une donnée nécessaire au rôle du composant.
    pid_generations: Dict[int, int] = Field(default_factory=dict)
    # [BESOIN C/E] Attribut `timeline` : porte une donnée nécessaire au rôle du composant.
    timeline: SessionTimeline = Field(default_factory=SessionTimeline)
    # [BESOIN C/E] Attribut `llm_interactions` : porte une donnée nécessaire au rôle du composant.
    llm_interactions: List[LLMInteractionEvent] = Field(default_factory=list)
    # [BESOIN C/E] Attribut `security_events` : porte une donnée nécessaire au rôle du composant.
    security_events: List[SecurityEvent] = Field(default_factory=list)
    # [BESOIN C/E] Attribut `files_accessed` : porte une donnée nécessaire au rôle du composant.
    files_accessed: Set[str] = Field(default_factory=set)
    # [BESOIN C/E] Attribut `network_events` : porte une donnée nécessaire au rôle du composant.
    network_events: List[NetworkConnectionEvent] = Field(default_factory=list)
    # [BESOIN C/E] Attribut `correlation_window_seconds` : porte une donnée nécessaire au rôle du
    # composant.
    correlation_window_seconds: int = Field(default=300, ge=1)

    # [BESOIN C/E] Fonction `_next_identity` : fonction dédiée à l’opération `_next_identity` dans le
    # flux qui consiste à reconstruire la session, les générations de PID, l’arbre de
    # processus et la timeline corrélée.
    def _next_identity(self, pid: int) -> tuple[str, int]:
        generation = self.pid_generations.get(pid, 0) + 1
        self.pid_generations[pid] = generation
        identity = f"{pid}:{generation}"
        self.latest_process_by_pid[pid] = identity
        return identity, generation

    # [BESOIN C/E] Fonction `_latest_node` : fonction dédiée à l’opération `_latest_node` dans le flux
    # qui consiste à reconstruire la session, les générations de PID, l’arbre de processus
    # et la timeline corrélée.
    def _latest_node(self, pid: int) -> Optional[ProcessNode]:
        identity = self.latest_process_by_pid.get(pid)
        return self.processes.get(identity) if identity else None

    # [BESOIN C/E] Fonction `_node_for_event` : fonction dédiée à l’opération `_node_for_event` dans le
    # flux qui consiste à reconstruire la session, les générations de PID, l’arbre de
    # processus et la timeline corrélée.
    def _node_for_event(self, event: BaseOSEvent) -> Optional[ProcessNode]:
        node = self._latest_node(event.pid)
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if node is None:
            return None
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if (
            event.process_start_ns
            and node.process_start_ns
            and event.process_start_ns != node.process_start_ns
        ):
            return None
        return node

    # [BESOIN C/E] Fonction `_parent_identity` : fonction dédiée à l’opération `_parent_identity` dans
    # le flux qui consiste à reconstruire la session, les générations de PID, l’arbre de
    # processus et la timeline corrélée.
    def _parent_identity(self, ppid: int, parent_start_ns: int = 0) -> Optional[str]:
        identity = self.latest_process_by_pid.get(ppid)
        parent = self.processes.get(identity) if identity else None
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if parent is None:
            return None
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if (
            parent_start_ns
            and parent.process_start_ns
            and parent_start_ns != parent.process_start_ns
        ):
            return None
        return identity

    # [BESOIN C/E] Fonction `_link_parent` : fonction dédiée à l’opération `_link_parent` dans le flux
    # qui consiste à reconstruire la session, les générations de PID, l’arbre de processus
    # et la timeline corrélée.
    def _link_parent(self, node: ProcessNode) -> None:
        parent_identity = self._parent_identity(node.ppid, node.parent_start_ns)
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if node.parent_identity and node.parent_identity != parent_identity:
            previous_parent = self.processes.get(node.parent_identity)
            # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if previous_parent:
                previous_parent.children.discard(node.identity)
        node.parent_identity = parent_identity
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if parent_identity and parent_identity in self.processes:
            self.processes[parent_identity].children.add(node.identity)

    # [BESOIN C/E] Fonction `_adopt_waiting_children` : fonction dédiée à l’opération
    # `_adopt_waiting_children` dans le flux qui consiste à reconstruire la session, les
    # générations de PID, l’arbre de processus et la timeline corrélée.
    def _adopt_waiting_children(self, parent: ProcessNode) -> None:
        # [BESOIN C/E] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for child in self.processes.values():
            # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if child.identity == parent.identity or child.parent_identity is not None:
                continue
            # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if child.ppid != parent.pid:
                continue
            # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if (
                child.parent_start_ns
                and parent.process_start_ns
                and child.parent_start_ns != parent.process_start_ns
            ):
                continue
            child.parent_identity = parent.identity
            parent.children.add(child.identity)

    # [BESOIN C/E] Fonction `_retire_reused_node` : fonction dédiée à l’opération `_retire_reused_node`
    # dans le flux qui consiste à reconstruire la session, les générations de PID, l’arbre
    # de processus et la timeline corrélée.
    @staticmethod
    def _retire_reused_node(node: ProcessNode, timestamp: datetime) -> None:
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if node.status == "RUNNING":
            node.status = "REPLACED"
            node.end_time = timestamp
            node.last_seen = max(node.last_seen, timestamp)

    # [BESOIN C/E] Fonction `_create_node` : fonction dédiée à l’opération `_create_node` dans le flux
    # qui consiste à reconstruire la session, les générations de PID, l’arbre de processus
    # et la timeline corrélée.
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
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if pid == self.main_pid and self.main_identity is None:
            self.main_identity = identity
        return node

    # [BESOIN C/E] Fonction `add_fork` : fonction dédiée à l’opération `add_fork` dans le flux qui
    # consiste à reconstruire la session, les générations de PID, l’arbre de processus et
    # la timeline corrélée.
    def add_fork(self, event: ProcessForkEvent) -> ProcessNode:
        node = self._latest_node(event.pid)
        identity_conflict = bool(
            node
            and event.process_start_ns
            and node.process_start_ns
            and event.process_start_ns != node.process_start_ns
        )
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if node and node.status == "RUNNING" and not identity_conflict:
            node.ppid = event.ppid
            node.parent_start_ns = event.parent_start_ns or node.parent_start_ns
            node.comm = event.child_comm or event.comm or node.comm
            node.last_seen = max(node.last_seen, event.timestamp)
            node.sequence = max(node.sequence, event.sequence)
            self._link_parent(node)
            self.timeline.add(event)
            return node
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
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

    # [BESOIN C/E] Fonction `add_process` : fonction dédiée à l’opération `add_process` dans le flux qui
    # consiste à reconstruire la session, les générations de PID, l’arbre de processus et
    # la timeline corrélée.
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
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if node is None or process_reused or conflicting_live_identity:
            # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
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

        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if event.pid == self.main_pid:
            self.main_identity = node.identity
            self.main_ppid = event.ppid
            self.main_executable = event.executable or self.main_executable
            self.main_command = event.command or self.main_command
        self.timeline.add(event)
        return node

    # [BESOIN C/E] Fonction `add_exit` : fonction dédiée à l’opération `add_exit` dans le flux qui
    # consiste à reconstruire la session, les générations de PID, l’arbre de processus et
    # la timeline corrélée.
    def add_exit(self, event: ProcessExitEvent) -> Optional[ProcessNode]:
        node = self._node_for_event(event)
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if node:
            node.status = "EXITED"
            node.end_time = event.timestamp
            node.last_seen = max(node.last_seen, event.timestamp)
            node.exit_code = event.exit_code
            node.signal = event.signal
        self.timeline.add(event)
        # A root process may exit before a still-running descendant. Close the
        # session only when the complete observed process tree has terminated.
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self.active_process_count() == 0:
            self.mark_ended(event.timestamp)
        return node

    # [BESOIN C/E] Fonction `add_os_event` : fonction dédiée à l’opération `add_os_event` dans le flux
    # qui consiste à reconstruire la session, les générations de PID, l’arbre de processus
    # et la timeline corrélée.
    def add_os_event(self, event: BaseOSEvent) -> bool:
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self.timeline.contains(event.event_id):
            return False
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if isinstance(event, ProcessExecutionEvent):
            self.add_process(event)
            return True
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if isinstance(event, ProcessForkEvent):
            self.add_fork(event)
            return True
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if isinstance(event, ProcessExitEvent):
            self.add_exit(event)
            return True
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if isinstance(event, (FileAccessEvent, FileWriteEvent, FileDeleteEvent)):
            self.files_accessed.add(event.path)
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if isinstance(event, NetworkConnectionEvent):
            self.network_events.append(event)
        node = self._node_for_event(event)
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if node:
            node.last_seen = max(node.last_seen, event.timestamp)
        self.timeline.add(event)
        return True

    # [BESOIN C/E] Fonction `_correlation_for` : fonction dédiée à l’opération `_correlation_for` dans
    # le flux qui consiste à reconstruire la session, les générations de PID, l’arbre de
    # processus et la timeline corrélée.
    def _correlation_for(
        self,
        timestamp: datetime,
        pid: int = 0,
        ppid: int = 0,
    ) -> Optional[CorrelationLink]:
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not self.llm_interactions:
            return None
        timestamps = [item.timestamp for item in self.llm_interactions]
        index = bisect_right(timestamps, timestamp) - 1
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if index < 0:
            return None
        llm_event = self.llm_interactions[index]
        latency_seconds = (timestamp - llm_event.timestamp).total_seconds()
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if latency_seconds < 0 or latency_seconds > self.correlation_window_seconds:
            return None

        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if latency_seconds <= 5:
            confidence = 0.95
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        elif latency_seconds <= 30:
            confidence = 0.85
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        elif latency_seconds <= 120:
            confidence = 0.70
        else:
            confidence = 0.55

        method = "temporal_session_window"
        rationale = (
            "The OS event belongs to the same trusted process session and follows "
            "the nearest preceding AgentSight LLM interaction."
        )
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
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

    # [BESOIN C/E] Fonction `_backfill_correlations` : implémente le comportement documenté par sa
    # docstring : « Annotate earlier timeline/security records after a late LLM import ».
    def _backfill_correlations(self) -> None:
        """Annotate earlier timeline/security records after a late LLM import.

        AgentSight reports can be imported after kernel events were already
        collected.  Backfilling keeps the API timeline useful without claiming
        causal proof.  The immutable source event ID and raw record remain
        unchanged.
        """
        # [BESOIN C/E] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for payload in self.timeline.events:
            event_type = str(payload.get("event_type", ""))
            # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if event_type == "LLM_INTERACTION" or payload.get("correlation"):
                continue
            link = self._correlation_for(
                _aware_timestamp(payload.get("timestamp")),
                int(payload.get("pid", 0) or 0),
                int(payload.get("ppid", 0) or 0),
            )
            # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
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

    # [BESOIN C/E] Fonction `add_llm_interaction` : ajoute l’interaction LLM et déclenche le recalcul
    # des corrélations pertinentes.
    def add_llm_interaction(self, event: LLMInteractionEvent) -> bool:
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self.timeline.contains(event.event_id):
            return False
        self.llm_interactions.append(event)
        self.llm_interactions.sort(key=lambda item: (item.timestamp, item.event_id))
        added = self.timeline.add(event)
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if added:
            self._backfill_correlations()
        return added

    # [BESOIN C/E] Fonction `add_security_event` : attache une alerte explicable à la session et à sa
    # timeline.
    def add_security_event(self, event: SecurityEvent) -> bool:
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self.timeline.contains(event.event_id):
            return False
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
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

    # [BESOIN C/E] Fonction `correlate_os_event` : fonction dédiée à l’opération `correlate_os_event`
    # dans le flux qui consiste à reconstruire la session, les générations de PID, l’arbre
    # de processus et la timeline corrélée.
    def correlate_os_event(self, event: BaseOSEvent) -> BaseOSEvent:
        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if event.correlation:
            return event
        link = self._correlation_for(event.timestamp, event.pid, event.ppid)
        return event if link is None else event.model_copy(update={"correlation": link})

    # [BESOIN C/E] Fonction `active_process_count` : compte les processus non terminés de la session.
    def active_process_count(self) -> int:
        return sum(1 for process in self.processes.values() if process.status == "RUNNING")

    # [BESOIN C/E] Fonction `get_process_tree` : produit une représentation hiérarchique des processus
    # et de leurs générations.
    def get_process_tree(self) -> Dict:
        root_identity = self.main_identity or self.latest_process_by_pid.get(self.main_pid)
        visiting: Set[str] = set()

        # [BESOIN C/E] Fonction `build` : compile le probe eBPF et le collecteur natif en conservant des
        # erreurs actionnables.
        def build(identity: str) -> Dict:
            # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if identity in visiting:
                return {"identity": identity, "cycle": True, "children": []}
            node = self.processes.get(identity)
            # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
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

        # [BESOIN C/E] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not root_identity:
            return {"pid": self.main_pid, "comm": "unknown", "children": []}
        return build(root_identity)

    # [BESOIN C/E] Fonction `is_active` : indique si la session est toujours ouverte.
    def is_active(self) -> bool:
        return self.end_time is None

    # [BESOIN C/E] Fonction `mark_ended` : enregistre la fin de session dans un horodatage UTC.
    def mark_ended(self, when: Optional[datetime] = None) -> None:
        self.end_time = when or datetime.now(timezone.utc)

    # [BESOIN C/E] Fonction `summary` : construit le résumé synthétique de la session.
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

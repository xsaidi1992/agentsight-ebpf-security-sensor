"""Normalized and strictly validated event models.

All timestamps are normalized to timezone-aware UTC at the model boundary.  The
kernel collector, AgentSight adapter, API and tests therefore share one stable
representation and cannot accidentally compare naive and aware datetimes.
"""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN F] Partie F - exposition des données par l’API backend.
# Rôle du module : définir et valider les événements OS, LLM, corrélations et alertes de sécurité.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import shlex
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# [BESOIN B/C/D/E/F] Fonction `utc_now` : fonction dédiée à l’opération `utc_now` dans le flux qui
# consiste à définir et valider les événements OS, LLM, corrélations et alertes de
# sécurité.
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# [BESOIN B/C/D/E/F] Fonction `new_event_id` : fonction dédiée à l’opération `new_event_id` dans le flux
# qui consiste à définir et valider les événements OS, LLM, corrélations et alertes
# de sécurité.
def new_event_id() -> str:
    return str(uuid4())


# [BESOIN B/C/D/E/F] Fonction `_as_utc` : fonction dédiée à l’opération `_as_utc` dans le flux qui
# consiste à définir et valider les événements OS, LLM, corrélations et alertes de
# sécurité.
def _as_utc(value: datetime) -> datetime:
    # [BESOIN B/C/D/E/F] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# [BESOIN B/C/D/E/F] Classe `EventSeverity` : classe dédiée à l’opération `EventSeverity` dans le flux
# qui consiste à définir et valider les événements OS, LLM, corrélations et alertes
# de sécurité.
class EventSeverity(str, Enum):
    # [BESOIN B/C/D/E/F] Constante `LOW` : fixe un paramètre stable et auditable utilisé par ce module.
    LOW = "LOW"
    # [BESOIN B/C/D/E/F] Constante `MEDIUM` : fixe un paramètre stable et auditable utilisé par ce
    # module.
    MEDIUM = "MEDIUM"
    # [BESOIN B/C/D/E/F] Constante `HIGH` : fixe un paramètre stable et auditable utilisé par ce module.
    HIGH = "HIGH"
    # [BESOIN B/C/D/E/F] Constante `CRITICAL` : fixe un paramètre stable et auditable utilisé par ce
    # module.
    CRITICAL = "CRITICAL"


# [BESOIN B/C/D/E/F] Classe `EventType` : classe dédiée à l’opération `EventType` dans le flux qui
# consiste à définir et valider les événements OS, LLM, corrélations et alertes de
# sécurité.
class EventType(str, Enum):
    # [BESOIN B/C/D/E/F] Constante `PROCESS_EXECUTION` : fixe un paramètre stable et auditable utilisé
    # par ce module.
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    # [BESOIN B/C/D/E/F] Constante `PROCESS_FORK` : fixe un paramètre stable et auditable utilisé par ce
    # module.
    PROCESS_FORK = "PROCESS_FORK"
    # [BESOIN B/C/D/E/F] Constante `PROCESS_EXIT` : fixe un paramètre stable et auditable utilisé par ce
    # module.
    PROCESS_EXIT = "PROCESS_EXIT"
    # [BESOIN B/C/D/E/F] Constante `FILE_ACCESS` : fixe un paramètre stable et auditable utilisé par ce
    # module.
    FILE_ACCESS = "FILE_ACCESS"
    # [BESOIN B/C/D/E/F] Constante `FILE_WRITE` : fixe un paramètre stable et auditable utilisé par ce
    # module.
    FILE_WRITE = "FILE_WRITE"
    # [BESOIN B/C/D/E/F] Constante `FILE_DELETE` : fixe un paramètre stable et auditable utilisé par ce
    # module.
    FILE_DELETE = "FILE_DELETE"
    # [BESOIN B/C/D/E/F] Constante `NETWORK_CONNECTION` : fixe un paramètre stable et auditable utilisé
    # par ce module.
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    # [BESOIN B/C/D/E/F] Constante `LLM_INTERACTION` : fixe un paramètre stable et auditable utilisé par
    # ce module.
    LLM_INTERACTION = "LLM_INTERACTION"
    # [BESOIN B/C/D/E/F] Constante `SECURITY_EVENT` : fixe un paramètre stable et auditable utilisé par
    # ce module.
    SECURITY_EVENT = "AI_AGENT_SECURITY_EVENT"


# [BESOIN B/C/D/E/F] Classe `CorrelationLink` : implémente le comportement documenté par sa docstring :
# « Explainable association between one LLM interaction and one OS event ».
class CorrelationLink(BaseModel):
    """Explainable association between one LLM interaction and one OS event."""

    # [BESOIN B/C/D/E/F] Attribut `model_config` : porte une donnée nécessaire au rôle du composant.
    model_config = ConfigDict(extra="forbid")

    # [BESOIN B/C/D/E/F] Attribut `llm_event_id` : porte une donnée nécessaire au rôle du composant.
    llm_event_id: str
    # [BESOIN B/C/D/E/F] Attribut `llm_request_id` : porte une donnée nécessaire au rôle du composant.
    llm_request_id: Optional[str] = None
    # [BESOIN B/C/D/E/F] Attribut `method` : porte une donnée nécessaire au rôle du composant.
    method: str = "temporal_session_window"
    # [BESOIN B/C/D/E/F] Attribut `confidence` : porte une donnée nécessaire au rôle du composant.
    confidence: float = Field(ge=0.0, le=1.0)
    # [BESOIN B/C/D/E/F] Attribut `latency_ms` : porte une donnée nécessaire au rôle du composant.
    latency_ms: int = Field(ge=0)
    # [BESOIN B/C/D/E/F] Attribut `rationale` : porte une donnée nécessaire au rôle du composant.
    rationale: str
    # [BESOIN B/C/D/E/F] Attribut `causal_proof` : porte une donnée nécessaire au rôle du composant.
    causal_proof: bool = False


# [BESOIN B/C/D/E/F] Classe `BaseOSEvent` : classe dédiée à l’opération `BaseOSEvent` dans le flux qui
# consiste à définir et valider les événements OS, LLM, corrélations et alertes de
# sécurité.
class BaseOSEvent(BaseModel):
    # [BESOIN B/C/D/E/F] Attribut `model_config` : porte une donnée nécessaire au rôle du composant.
    model_config = ConfigDict(extra="forbid")

    # [BESOIN B/C/D/E/F] Champ `event_id` : identifiant stable utilisé pour la déduplication et la
    # traçabilité.
    event_id: str = Field(default_factory=new_event_id, min_length=1)
    # [BESOIN B/C/D/E/F] Champ `timestamp` : horodatage UTC normalisé de l’événement.
    timestamp: datetime = Field(default_factory=utc_now)
    # [BESOIN B/C/D/E/F] Champ `event_type` : type normalisé permettant le dispatch, le filtrage API et
    # la timeline.
    event_type: EventType
    # [BESOIN B/C/D/E/F] Champ `pid` : PID du processus réellement observé, utilisé pour les filtres et
    # le rattachement de session.
    pid: int = Field(ge=0)
    # [BESOIN B/C/D/E/F] Champ `ppid` : PID du parent, nécessaire à la reconstruction de l’arbre
    # demandé.
    ppid: int = Field(ge=0)
    # [BESOIN B/C/D/E/F] Champ `uid` : identité utilisateur Linux de l’action observée.
    uid: int = Field(ge=0)
    # [BESOIN B/C/D/E/F] Champ `gid` : identité de groupe Linux associée au processus.
    gid: int = Field(ge=0)
    # [BESOIN B/C/D/E/F] Champ `comm` : nom court du processus fourni par le kernel.
    comm: str = ""
    # [BESOIN B/C/D/E/F] Champ `executable` : chemin de l’exécutable réellement lancé.
    executable: str = ""
    # [BESOIN B/C/D/E/F] Attribut `cwd` : porte une donnée nécessaire au rôle du composant.
    cwd: str = "unknown"
    # [BESOIN B/C/D/E/F] Attribut `source` : porte une donnée nécessaire au rôle du composant.
    source: str = "ebpf"
    # [BESOIN B/C/D/E/F] Champ `sequence` : séquence kernel utilisée pour détecter les trous et pertes
    # de transport.
    sequence: int = Field(default=0, ge=0)
    # [BESOIN B/C/D/E/F] Champ `kernel_timestamp_ns` : horodatage monotone kernel conservé pour l’ordre
    # précis des événements.
    kernel_timestamp_ns: int = Field(default=0, ge=0)
    # [BESOIN B/C/D/E/F] Champ `process_start_ns` : temps de démarrage du processus, combiné au PID pour
    # résister au PID reuse.
    process_start_ns: int = Field(default=0, ge=0)
    # [BESOIN B/C/D/E/F] Champ `parent_start_ns` : temps de démarrage du parent, utilisé pour éviter une
    # filiation erronée.
    parent_start_ns: int = Field(default=0, ge=0)
    # [BESOIN B/C/D/E/F] Champ `correlation` : lien explicable entre l’événement OS et une interaction
    # LLM.
    correlation: Optional[CorrelationLink] = None
    # [BESOIN B/C/D/E/F] Champ `metadata` : métadonnées source conservées sans modifier le contrat
    # principal.
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # [BESOIN B/C/D/E/F] Fonction `normalize_timestamp` : normalise l’horodatage en UTC afin de rendre
    # les comparaisons fiables.
    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _as_utc(value)


# [BESOIN B/C/D/E/F] Classe `ProcessExecutionEvent` : classe dédiée à l’opération
# `ProcessExecutionEvent` dans le flux qui consiste à définir et valider les
# événements OS, LLM, corrélations et alertes de sécurité.
class ProcessExecutionEvent(BaseOSEvent):
    # [BESOIN B/C/D/E/F] Champ `event_type` : type normalisé permettant le dispatch, le filtrage API et
    # la timeline.
    event_type: Literal[EventType.PROCESS_EXECUTION] = EventType.PROCESS_EXECUTION
    # [BESOIN B/C/D/E/F] Champ `argv` : arguments bornés capturés pour reconstituer la commande.
    argv: List[str] = Field(default_factory=list)
    # [BESOIN B/C/D/E/F] Attribut `argv_truncated` : porte une donnée nécessaire au rôle du composant.
    argv_truncated: bool = False
    # [BESOIN B/C/D/E/F] Attribut `filename_truncated` : porte une donnée nécessaire au rôle du
    # composant.
    filename_truncated: bool = False
    # [BESOIN B/C/D/E/F] Attribut `syscall` : porte une donnée nécessaire au rôle du composant.
    syscall: str = "execve"

    # [BESOIN B/C/D/E/F] Fonction `command` : reconstruit une ligne de commande lisible à partir de
    # argv.
    @property
    def command(self) -> str:
        # [BESOIN B/C/D/E/F] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self.argv:
            return shlex.join(self.argv)
        return self.executable or self.comm

    # [BESOIN B/C/D/E/F] Fonction `command_name` : extrait le nom canonique de la commande pour les
    # règles de sécurité.
    @property
    def command_name(self) -> str:
        candidate = (self.argv[0] if self.argv else "") or self.executable or self.comm
        return Path(candidate).name


# [BESOIN B/C/D/E/F] Classe `ProcessForkEvent` : classe dédiée à l’opération `ProcessForkEvent` dans le
# flux qui consiste à définir et valider les événements OS, LLM, corrélations et
# alertes de sécurité.
class ProcessForkEvent(BaseOSEvent):
    # [BESOIN B/C/D/E/F] Champ `event_type` : type normalisé permettant le dispatch, le filtrage API et
    # la timeline.
    event_type: Literal[EventType.PROCESS_FORK] = EventType.PROCESS_FORK
    # [BESOIN B/C/D/E/F] Attribut `child_comm` : porte une donnée nécessaire au rôle du composant.
    child_comm: str = ""


# [BESOIN B/C/D/E/F] Classe `ProcessExitEvent` : classe dédiée à l’opération `ProcessExitEvent` dans le
# flux qui consiste à définir et valider les événements OS, LLM, corrélations et
# alertes de sécurité.
class ProcessExitEvent(BaseOSEvent):
    # [BESOIN B/C/D/E/F] Champ `event_type` : type normalisé permettant le dispatch, le filtrage API et
    # la timeline.
    event_type: Literal[EventType.PROCESS_EXIT] = EventType.PROCESS_EXIT
    # [BESOIN B/C/D/E/F] Attribut `exit_code` : porte une donnée nécessaire au rôle du composant.
    exit_code: int = 0
    # [BESOIN B/C/D/E/F] Attribut `signal` : porte une donnée nécessaire au rôle du composant.
    signal: int = Field(default=0, ge=0)
    # [BESOIN B/C/D/E/F] Attribut `duration_ns` : porte une donnée nécessaire au rôle du composant.
    duration_ns: int = Field(default=0, ge=0)


# [BESOIN B/C/D/E/F] Classe `FileAccessEvent` : classe dédiée à l’opération `FileAccessEvent` dans le
# flux qui consiste à définir et valider les événements OS, LLM, corrélations et
# alertes de sécurité.
class FileAccessEvent(BaseOSEvent):
    # [BESOIN B/C/D/E/F] Champ `event_type` : type normalisé permettant le dispatch, le filtrage API et
    # la timeline.
    event_type: Literal[EventType.FILE_ACCESS] = EventType.FILE_ACCESS
    # [BESOIN B/C/D/E/F] Attribut `path` : porte une donnée nécessaire au rôle du composant.
    path: str
    # [BESOIN B/C/D/E/F] Attribut `raw_path` : porte une donnée nécessaire au rôle du composant.
    raw_path: str
    # [BESOIN B/C/D/E/F] Attribut `fd` : porte une donnée nécessaire au rôle du composant.
    fd: int = -1
    # [BESOIN B/C/D/E/F] Attribut `dirfd` : porte une donnée nécessaire au rôle du composant.
    dirfd: int = -100
    # [BESOIN B/C/D/E/F] Attribut `flags` : porte une donnée nécessaire au rôle du composant.
    flags: int = Field(default=0, ge=0)
    # [BESOIN B/C/D/E/F] Attribut `result` : porte une donnée nécessaire au rôle du composant.
    result: int = 0
    # [BESOIN B/C/D/E/F] Attribut `operation` : porte une donnée nécessaire au rôle du composant.
    operation: str = "OPEN"
    # [BESOIN B/C/D/E/F] Attribut `write_intent` : porte une donnée nécessaire au rôle du composant.
    write_intent: bool = False
    # [BESOIN B/C/D/E/F] Attribut `path_truncated` : porte une donnée nécessaire au rôle du composant.
    path_truncated: bool = False


# [BESOIN B/C/D/E/F] Classe `FileWriteEvent` : classe dédiée à l’opération `FileWriteEvent` dans le flux
# qui consiste à définir et valider les événements OS, LLM, corrélations et alertes
# de sécurité.
class FileWriteEvent(BaseOSEvent):
    # [BESOIN B/C/D/E/F] Champ `event_type` : type normalisé permettant le dispatch, le filtrage API et
    # la timeline.
    event_type: Literal[EventType.FILE_WRITE] = EventType.FILE_WRITE
    # [BESOIN B/C/D/E/F] Attribut `path` : porte une donnée nécessaire au rôle du composant.
    path: str
    # [BESOIN B/C/D/E/F] Attribut `raw_path` : porte une donnée nécessaire au rôle du composant.
    raw_path: str
    # [BESOIN B/C/D/E/F] Attribut `fd` : porte une donnée nécessaire au rôle du composant.
    fd: int = -1
    # [BESOIN B/C/D/E/F] Attribut `dirfd` : porte une donnée nécessaire au rôle du composant.
    dirfd: int = -100
    # [BESOIN B/C/D/E/F] Attribut `bytes_written` : porte une donnée nécessaire au rôle du composant.
    bytes_written: int = Field(default=0, ge=0)
    # [BESOIN B/C/D/E/F] Attribut `result` : porte une donnée nécessaire au rôle du composant.
    result: int = 0
    # [BESOIN B/C/D/E/F] Attribut `path_truncated` : porte une donnée nécessaire au rôle du composant.
    path_truncated: bool = False


# [BESOIN B/C/D/E/F] Classe `FileDeleteEvent` : classe dédiée à l’opération `FileDeleteEvent` dans le
# flux qui consiste à définir et valider les événements OS, LLM, corrélations et
# alertes de sécurité.
class FileDeleteEvent(BaseOSEvent):
    # [BESOIN B/C/D/E/F] Champ `event_type` : type normalisé permettant le dispatch, le filtrage API et
    # la timeline.
    event_type: Literal[EventType.FILE_DELETE] = EventType.FILE_DELETE
    # [BESOIN B/C/D/E/F] Attribut `path` : porte une donnée nécessaire au rôle du composant.
    path: str
    # [BESOIN B/C/D/E/F] Attribut `raw_path` : porte une donnée nécessaire au rôle du composant.
    raw_path: str
    # [BESOIN B/C/D/E/F] Attribut `dirfd` : porte une donnée nécessaire au rôle du composant.
    dirfd: int = -100
    # [BESOIN B/C/D/E/F] Attribut `result` : porte une donnée nécessaire au rôle du composant.
    result: int = 0
    # [BESOIN B/C/D/E/F] Attribut `path_truncated` : porte une donnée nécessaire au rôle du composant.
    path_truncated: bool = False


# [BESOIN B/C/D/E/F] Classe `NetworkConnectionEvent` : classe dédiée à l’opération
# `NetworkConnectionEvent` dans le flux qui consiste à définir et valider les
# événements OS, LLM, corrélations et alertes de sécurité.
class NetworkConnectionEvent(BaseOSEvent):
    # [BESOIN B/C/D/E/F] Champ `event_type` : type normalisé permettant le dispatch, le filtrage API et
    # la timeline.
    event_type: Literal[EventType.NETWORK_CONNECTION] = EventType.NETWORK_CONNECTION
    # [BESOIN B/C/D/E/F] Attribut `remote_addr` : porte une donnée nécessaire au rôle du composant.
    remote_addr: str
    # [BESOIN B/C/D/E/F] Attribut `remote_port` : porte une donnée nécessaire au rôle du composant.
    remote_port: int = Field(ge=0, le=65535)
    # [BESOIN B/C/D/E/F] Attribut `family` : porte une donnée nécessaire au rôle du composant.
    family: int = Field(default=0, ge=0)
    # [BESOIN B/C/D/E/F] Attribut `protocol` : porte une donnée nécessaire au rôle du composant.
    protocol: str = "tcp"
    # [BESOIN B/C/D/E/F] Attribut `result` : porte une donnée nécessaire au rôle du composant.
    result: int = 0


# [BESOIN B/C/D/E/F] Classe `LLMInteractionEvent` : classe dédiée à l’opération `LLMInteractionEvent`
# dans le flux qui consiste à définir et valider les événements OS, LLM, corrélations
# et alertes de sécurité.
class LLMInteractionEvent(BaseModel):
    # [BESOIN B/C/D/E/F] Attribut `model_config` : porte une donnée nécessaire au rôle du composant.
    model_config = ConfigDict(extra="forbid")

    # [BESOIN B/C/D/E/F] Champ `event_id` : identifiant stable utilisé pour la déduplication et la
    # traçabilité.
    event_id: str = Field(default_factory=new_event_id, min_length=1)
    # [BESOIN B/C/D/E/F] Champ `timestamp` : horodatage UTC normalisé de l’événement.
    timestamp: datetime = Field(default_factory=utc_now)
    # [BESOIN B/C/D/E/F] Champ `event_type` : type normalisé permettant le dispatch, le filtrage API et
    # la timeline.
    event_type: Literal[EventType.LLM_INTERACTION] = EventType.LLM_INTERACTION
    # [BESOIN B/C/D/E/F] Champ `session_id` : identifiant de l’Agent Session à laquelle appartient
    # l’élément.
    session_id: str = Field(min_length=1)
    # [BESOIN B/C/D/E/F] Attribut `request_id` : porte une donnée nécessaire au rôle du composant.
    request_id: Optional[str] = None
    # [BESOIN B/C/D/E/F] Champ `pid` : PID du processus réellement observé, utilisé pour les filtres et
    # le rattachement de session.
    pid: Optional[int] = Field(default=None, ge=0)
    # [BESOIN B/C/D/E/F] Attribut `llm_provider` : porte une donnée nécessaire au rôle du composant.
    llm_provider: str = "unknown"
    # [BESOIN B/C/D/E/F] Attribut `model` : porte une donnée nécessaire au rôle du composant.
    model: str = "unknown"
    # [BESOIN B/C/D/E/F] Attribut `prompt` : porte une donnée nécessaire au rôle du composant.
    prompt: str
    # [BESOIN B/C/D/E/F] Attribut `response` : porte une donnée nécessaire au rôle du composant.
    response: Optional[str] = None
    # [BESOIN B/C/D/E/F] Attribut `duration_ms` : porte une donnée nécessaire au rôle du composant.
    duration_ms: Optional[int] = Field(default=None, ge=0)
    # [BESOIN B/C/D/E/F] Attribut `source` : porte une donnée nécessaire au rôle du composant.
    source: str = "agentsight"
    # [BESOIN B/C/D/E/F] Champ `metadata` : métadonnées source conservées sans modifier le contrat
    # principal.
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # [BESOIN B/C/D/E/F] Fonction `normalize_timestamp` : normalise l’horodatage en UTC afin de rendre
    # les comparaisons fiables.
    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _as_utc(value)


# [BESOIN B/C/D/E/F] Classe `SecurityEvent` : classe dédiée à l’opération `SecurityEvent` dans le flux
# qui consiste à définir et valider les événements OS, LLM, corrélations et alertes
# de sécurité.
class SecurityEvent(BaseModel):
    # [BESOIN B/C/D/E/F] Attribut `model_config` : porte une donnée nécessaire au rôle du composant.
    model_config = ConfigDict(extra="forbid")

    # [BESOIN B/C/D/E/F] Champ `event_id` : identifiant stable utilisé pour la déduplication et la
    # traçabilité.
    event_id: str = Field(default_factory=new_event_id, min_length=1)
    # [BESOIN B/C/D/E/F] Champ `timestamp` : horodatage UTC normalisé de l’événement.
    timestamp: datetime = Field(default_factory=utc_now)
    # [BESOIN B/C/D/E/F] Champ `event_type` : type normalisé permettant le dispatch, le filtrage API et
    # la timeline.
    event_type: Literal[EventType.SECURITY_EVENT] = EventType.SECURITY_EVENT
    # [BESOIN B/C/D/E/F] Attribut `type` : porte une donnée nécessaire au rôle du composant.
    type: Literal["AI_AGENT_SECURITY_EVENT"] = "AI_AGENT_SECURITY_EVENT"
    # [BESOIN B/C/D/E/F] Champ `severity` : niveau de criticité de l’alerte.
    severity: EventSeverity
    # [BESOIN B/C/D/E/F] Champ `session_id` : identifiant de l’Agent Session à laquelle appartient
    # l’élément.
    session_id: str = Field(min_length=1)
    # [BESOIN B/C/D/E/F] Champ `pid` : PID du processus réellement observé, utilisé pour les filtres et
    # le rattachement de session.
    pid: int = Field(ge=0)
    # [BESOIN B/C/D/E/F] Champ `ppid` : PID du parent, nécessaire à la reconstruction de l’arbre
    # demandé.
    ppid: int = Field(ge=0)
    # [BESOIN B/C/D/E/F] Champ `action` : catégorie d’action sensible détectée.
    action: str
    # [BESOIN B/C/D/E/F] Champ `target` : commande, chemin ou destination concernée par l’alerte.
    target: str
    # [BESOIN B/C/D/E/F] Champ `rule_name` : nom stable de la règle ayant déclenché l’alerte.
    rule_name: str
    # [BESOIN B/C/D/E/F] Champ `rule_description` : explication humaine de la règle appliquée.
    rule_description: str
    # [BESOIN B/C/D/E/F] Champ `raw_events` : preuves brutes minimales utilisées pour expliquer la
    # détection.
    raw_events: List[Dict[str, Any]] = Field(default_factory=list)
    # [BESOIN B/C/D/E/F] Champ `correlation` : lien explicable entre l’événement OS et une interaction
    # LLM.
    correlation: Optional[CorrelationLink] = None
    # [BESOIN B/C/D/E/F] Champ `metadata` : métadonnées source conservées sans modifier le contrat
    # principal.
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # [BESOIN B/C/D/E/F] Fonction `normalize_timestamp` : normalise l’horodatage en UTC afin de rendre
    # les comparaisons fiables.
    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _as_utc(value)

from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN D] Partie D - détection et explication des actions sensibles.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : fournir des fixtures déterministes représentant les événements demandés par le sujet.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from src.models import (
    FileAccessEvent,
    FileWriteEvent,
    LLMInteractionEvent,
    NetworkConnectionEvent,
    ProcessExecutionEvent,
    ProcessExitEvent,
    ProcessForkEvent,
)

# [TESTS / BESOIN B/C/D/E/T] Constante `BASE_TIME` : fixe un paramètre stable et auditable utilisé par
# ce module.
BASE_TIME = datetime(2026, 1, 1, 10, 1, 2, tzinfo=timezone.utc)


# [TESTS / BESOIN B/C/D/E/T] Fonction `at` : fonction dédiée à l’opération `at` dans le flux qui
# consiste à fournir des fixtures déterministes représentant les événements
# demandés par le sujet.
def at(seconds: float = 0) -> datetime:
    return BASE_TIME + timedelta(seconds=seconds)


# [TESTS / BESOIN B/C/D/E/T] Fonction `exec_event` : fonction dédiée à l’opération `exec_event` dans le
# flux qui consiste à fournir des fixtures déterministes représentant les
# événements demandés par le sujet.
def exec_event(
    pid: int = 100,
    ppid: int = 1,
    name: str = "python3",
    seconds: float = 0,
    *,
    start_ns: int | None = None,
    sequence: int | None = None,
    source: str = "ebpf",
    argv: list[str] | None = None,
) -> ProcessExecutionEvent:
    start = start_ns if start_ns is not None else pid * 1_000_000
    args = argv if argv is not None else [f"/usr/bin/{name}"]
    return ProcessExecutionEvent(
        timestamp=at(seconds),
        pid=pid,
        ppid=ppid,
        uid=1000,
        gid=1000,
        comm=name,
        executable=f"/usr/bin/{name}",
        argv=args,
        sequence=sequence if sequence is not None else pid,
        process_start_ns=start,
        parent_start_ns=ppid * 1_000_000 if ppid else 0,
        source=source,
    )


# [TESTS / BESOIN B/C/D/E/T] Fonction `fork_event` : fonction dédiée à l’opération `fork_event` dans le
# flux qui consiste à fournir des fixtures déterministes représentant les
# événements demandés par le sujet.
def fork_event(
    pid: int,
    ppid: int,
    seconds: float,
    *,
    start_ns: int | None = None,
    sequence: int | None = None,
) -> ProcessForkEvent:
    return ProcessForkEvent(
        timestamp=at(seconds),
        pid=pid,
        ppid=ppid,
        uid=1000,
        gid=1000,
        comm="child",
        child_comm="child",
        sequence=sequence if sequence is not None else pid,
        process_start_ns=start_ns if start_ns is not None else pid * 1_000_000,
        parent_start_ns=ppid * 1_000_000,
    )


# [TESTS / BESOIN B/C/D/E/T] Fonction `exit_event` : fonction dédiée à l’opération `exit_event` dans le
# flux qui consiste à fournir des fixtures déterministes représentant les
# événements demandés par le sujet.
def exit_event(
    pid: int,
    ppid: int,
    seconds: float,
    *,
    start_ns: int | None = None,
    sequence: int | None = None,
) -> ProcessExitEvent:
    return ProcessExitEvent(
        timestamp=at(seconds),
        pid=pid,
        ppid=ppid,
        uid=1000,
        gid=1000,
        comm="process",
        sequence=sequence if sequence is not None else pid,
        process_start_ns=start_ns if start_ns is not None else pid * 1_000_000,
        exit_code=0,
        signal=0,
    )


# [TESTS / BESOIN B/C/D/E/T] Fonction `llm_event` : fonction dédiée à l’opération `llm_event` dans le
# flux qui consiste à fournir des fixtures déterministes représentant les
# événements demandés par le sujet.
def llm_event(session_id: str = "s1", seconds: float = 0) -> LLMInteractionEvent:
    return LLMInteractionEvent(
        event_id=f"llm-{session_id}-{seconds}",
        timestamp=at(seconds),
        session_id=session_id,
        prompt="Download the report and save it locally",
        response="I will download and save the report.",
        llm_provider="openai",
        model="test-model",
        source="agentsight",
    )


# [TESTS / BESOIN B/C/D/E/T] Fonction `file_open_event` : fonction dédiée à l’opération
# `file_open_event` dans le flux qui consiste à fournir des fixtures
# déterministes représentant les événements demandés par le sujet.
def file_open_event(
    pid: int = 101,
    ppid: int = 100,
    seconds: float = 3,
    path: str = "/tmp/result.txt",
    *,
    write_intent: bool = True,
) -> FileAccessEvent:
    return FileAccessEvent(
        timestamp=at(seconds),
        pid=pid,
        ppid=ppid,
        uid=1000,
        gid=1000,
        comm="curl",
        path=path,
        raw_path=path,
        fd=3,
        flags=577 if write_intent else 0,
        result=3,
        write_intent=write_intent,
        process_start_ns=pid * 1_000_000,
    )


# [TESTS / BESOIN B/C/D/E/T] Fonction `file_write_event` : fonction dédiée à l’opération
# `file_write_event` dans le flux qui consiste à fournir des fixtures
# déterministes représentant les événements demandés par le sujet.
def file_write_event(
    pid: int = 101,
    ppid: int = 100,
    seconds: float = 4,
    path: str = "/tmp/result.txt",
) -> FileWriteEvent:
    return FileWriteEvent(
        timestamp=at(seconds),
        pid=pid,
        ppid=ppid,
        uid=1000,
        gid=1000,
        comm="curl",
        path=path,
        raw_path=path,
        fd=3,
        bytes_written=128,
        result=128,
        process_start_ns=pid * 1_000_000,
    )


# [TESTS / BESOIN B/C/D/E/T] Fonction `network_event` : fonction dédiée à l’opération `network_event`
# dans le flux qui consiste à fournir des fixtures déterministes représentant
# les événements demandés par le sujet.
def network_event(
    pid: int = 101,
    ppid: int = 100,
    seconds: float = 2,
    remote_addr: str = "127.0.0.1",
    remote_port: int = 443,
) -> NetworkConnectionEvent:
    return NetworkConnectionEvent(
        timestamp=at(seconds),
        pid=pid,
        ppid=ppid,
        uid=1000,
        gid=1000,
        comm="curl",
        remote_addr=remote_addr,
        remote_port=remote_port,
        family=2,
        result=0,
        process_start_ns=pid * 1_000_000,
    )


# [TESTS / BESOIN B/C/D/E/T] Fonction `event_factory` : fonction dédiée à l’opération `event_factory`
# dans le flux qui consiste à fournir des fixtures déterministes représentant
# les événements demandés par le sujet.
@pytest.fixture
def event_factory() -> dict[str, Any]:
    return {
        "at": at,
        "exec": exec_event,
        "fork": fork_event,
        "exit": exit_event,
        "llm": llm_event,
        "file_open": file_open_event,
        "file_write": file_write_event,
        "network": network_event,
    }

"""Long-running service that correlates a live eBPF sensor with sessions."""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN C] Partie C - modèle Agent Session, arbre de processus et rattachement des descendants.
# [BESOIN E] Partie E - corrélation entre activité LLM et activité du système d’exploitation.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# Rôle du module : orchestrer l’attachement au processus racine et la boucle de collecte en arrière-plan.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


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


# [BESOIN A/B/C/E/P] Fonction `_proc_stat` : fonction dédiée à l’opération `_proc_stat` dans le flux qui
# consiste à orchestrer l’attachement au processus racine et la boucle de collecte en
# arrière-plan.
def _proc_stat(pid: int) -> tuple[int, int]:
    stat_path = Path("/proc") / str(pid) / "stat"
    stat_text = stat_path.read_text(encoding="utf-8")
    close_paren = stat_text.rfind(")")
    # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if close_paren < 0:
        # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
        # une fausse preuve.
        raise ValueError(f"unable to parse {stat_path}")
    fields = stat_text[close_paren + 2 :].split()
    # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if len(fields) < 20:
        # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
        # une fausse preuve.
        raise ValueError(f"incomplete process stat: {stat_path}")
    ppid = int(fields[1])
    start_ticks = int(fields[19])
    return ppid, start_ticks


# [BESOIN A/B/C/E/P] Fonction `_boot_epoch_seconds` : fonction dédiée à l’opération
# `_boot_epoch_seconds` dans le flux qui consiste à orchestrer l’attachement au
# processus racine et la boucle de collecte en arrière-plan.
def _boot_epoch_seconds() -> float:
    # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
    # explicite.
    try:
        # [BESOIN A/B/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines():
            # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if line.startswith("btime "):
                return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    # Approximate the Unix boot epoch from two monotonic clock readings.
    # This is more accurate than returning "now" for a process that may have
    # started long before this service, and it keeps the process start time on
    # the same basis as /proc/<pid>/stat.
    return time.time() - time.monotonic()


# [BESOIN A/B/C/E/P] Fonction `_start_ns` : fonction dédiée à l’opération `_start_ns` dans le flux qui
# consiste à orchestrer l’attachement au processus racine et la boucle de collecte en
# arrière-plan.
def _start_ns(pid: int) -> int:
    # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
    # explicite.
    try:
        _, ticks = _proc_stat(pid)
        hz = int(os.sysconf("SC_CLK_TCK"))
        return int(ticks * 1_000_000_000 // hz)
    except (OSError, ProcessLookupError, ValueError):
        return 0


# [BESOIN A/B/C/E/P] Fonction `process_event_from_proc` : construit un événement processus cohérent à
# partir des métadonnées /proc.
def process_event_from_proc(pid: int) -> ProcessExecutionEvent:
    """Register an already-running process without modifying that process."""
    proc = Path("/proc") / str(pid)
    # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if not proc.exists():
        # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
        # une fausse preuve.
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
    # [BESOIN A/B/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
    # traçable.
    for line in (proc / "status").read_text(encoding="utf-8").splitlines():
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if line.startswith("Uid:"):
            uid = int(line.split()[1])
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        elif line.startswith("Gid:"):
            gid = int(line.split()[1])

    # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
    # explicite.
    try:
        executable = os.readlink(proc / "exe")
    except OSError:
        executable = ""
    raw_cmdline = (proc / "cmdline").read_bytes().split(b"\0")
    argv = [item.decode("utf-8", errors="replace") for item in raw_cmdline if item]
    comm = (proc / "comm").read_text(encoding="utf-8").strip()
    # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
    # explicite.
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


# [BESOIN A/B/C/E/P] Fonction `discover_process_tree` : inspecte /proc pour amorcer l’arbre des
# processus déjà existants.
def discover_process_tree(root_pid: int) -> List[int]:
    """Return root and existing descendants in breadth-first order."""
    # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if root_pid <= 0:
        # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
        # une fausse preuve.
        raise ValueError("root_pid must be positive")
    # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if not (Path("/proc") / str(root_pid)).exists():
        # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
        # une fausse preuve.
        raise ProcessLookupError(root_pid)
    parent_by_pid: dict[int, int] = {}
    # [BESOIN A/B/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
    # traçable.
    for entry in Path("/proc").iterdir():
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            ppid, _ = _proc_stat(pid)
        except (OSError, ProcessLookupError, ValueError):
            continue
        parent_by_pid[pid] = ppid

    children: dict[int, List[int]] = {}
    # [BESOIN A/B/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
    # traçable.
    for pid, ppid in parent_by_pid.items():
        children.setdefault(ppid, []).append(pid)
    result: List[int] = []
    queue = [root_pid]
    seen: set[int] = set()
    # [BESOIN A/B/C/E/P] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la condition
    # d’arrêt.
    while queue:
        pid = queue.pop(0)
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if pid in seen:
            continue
        seen.add(pid)
        result.append(pid)
        queue.extend(sorted(children.get(pid, [])))
    return result


# [BESOIN A/B/C/E/P] Classe `LiveSensorService` : classe dédiée à l’opération `LiveSensorService` dans
# le flux qui consiste à orchestrer l’attachement au processus racine et la boucle de
# collecte en arrière-plan.
class LiveSensorService:
    # [BESOIN A/B/C/E/P] Constante `GATED_EXEC_CODE` : fixe un paramètre stable et auditable utilisé par
    # ce module.
    GATED_EXEC_CODE = (
        "import os,signal,sys;"
        "os.kill(os.getpid(),signal.SIGSTOP);"
        "os.execvp(sys.argv[1],sys.argv[1:])"
    )

    # [BESOIN A/B/C/E/P] Fonction `__init__` : initialise l’état interne et les dépendances nécessaires
    # au composant.
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

    # [BESOIN A/B/C/E/P] Fonction `_ensure_stopped` : fonction dédiée à l’opération `_ensure_stopped`
    # dans le flux qui consiste à orchestrer l’attachement au processus racine et la
    # boucle de collecte en arrière-plan.
    def _ensure_stopped(self) -> None:
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self._starting:
            # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise RuntimeError("sensor service is already starting")
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self._thread and self._thread.is_alive():
            # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise RuntimeError("sensor service is already running")
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self._owned_process and self._owned_process.poll() is None:
            # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise RuntimeError("sensor service already owns a running process")

    # [BESOIN A/B/C/E/P] Fonction `_begin_start` : fonction dédiée à l’opération `_begin_start` dans le
    # flux qui consiste à orchestrer l’attachement au processus racine et la boucle
    # de collecte en arrière-plan.
    def _begin_start(self) -> None:
        # [BESOIN A/B/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture
        # déterministes.
        with self._state_lock:
            self._ensure_stopped()
            self._starting = True
            self.last_error = None

    # [BESOIN A/B/C/E/P] Fonction `_finish_start` : fonction dédiée à l’opération `_finish_start` dans
    # le flux qui consiste à orchestrer l’attachement au processus racine et la
    # boucle de collecte en arrière-plan.
    def _finish_start(self) -> None:
        # [BESOIN A/B/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture
        # déterministes.
        with self._state_lock:
            self._starting = False

    # [BESOIN A/B/C/E/P] Fonction `_start_loop` : fonction dédiée à l’opération `_start_loop` dans le
    # flux qui consiste à orchestrer l’attachement au processus racine et la boucle
    # de collecte en arrière-plan.
    def _start_loop(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._collect_loop,
            name="agentsight-runtime",
            daemon=True,
        )
        self._thread.start()

    # [BESOIN A/B/C/E/P] Fonction `_wait_for_pre_exec_stop` : fonction dédiée à l’opération
    # `_wait_for_pre_exec_stop` dans le flux qui consiste à orchestrer l’attachement
    # au processus racine et la boucle de collecte en arrière-plan.
    @staticmethod
    def _wait_for_pre_exec_stop(
        process: subprocess.Popen[bytes], timeout_seconds: float = 5.0
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        # [BESOIN A/B/C/E/P] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la condition
        # d’arrêt.
        while time.monotonic() < deadline:
            waited_pid, status = os.waitpid(
                process.pid, os.WUNTRACED | os.WNOHANG
            )
            # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if waited_pid == 0:
                time.sleep(0.01)
                continue
            # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if waited_pid != process.pid:
                continue
            # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if os.WIFSTOPPED(status):
                return
            # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                process.returncode = os.waitstatus_to_exitcode(status)
                # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
                # produire une fausse preuve.
                raise RuntimeError(
                    "gated agent exited before reaching the pre-exec stop"
                )
        # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
        # une fausse preuve.
        raise TimeoutError(
            f"gated agent did not stop before exec within {timeout_seconds:g}s"
        )

    # [BESOIN A/B/C/E/P] Fonction `start_existing` : attache le capteur à un processus déjà actif sans
    # modifier son code.
    def start_existing(
        self,
        root_pid: int,
        session_id: str,
        agent_name: str,
        llm_events: Optional[Iterable[LLMInteractionEvent]] = None,
    ) -> None:
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if root_pid <= 0:
            # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise ValueError("root_pid must be positive")
        self._begin_start()
        collector_started = False
        # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            tree = discover_process_tree(root_pid)
            root_event = process_event_from_proc(root_pid)
            self.collector.start(root_pid=root_pid, tracked_pids=tree[1:])
            collector_started = True
            self.runtime.create_session(session_id, agent_name, root_event)
            # [BESOIN A/B/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe
            # et traçable.
            for event in llm_events or []:
                self.runtime.record_llm_interaction(
                    event.model_copy(update={"session_id": session_id})
                )
            # [BESOIN A/B/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe
            # et traçable.
            for pid in tree[1:]:
                # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
                # diagnostic explicite.
                try:
                    self.runtime.ingest(process_event_from_proc(pid))
                except (OSError, ProcessLookupError, ValueError):
                    continue
            self._start_loop()
        except Exception:
            # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if collector_started:
                self.collector.stop()
            # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise
        finally:
            self._finish_start()

    # [BESOIN A/B/C/E/P] Fonction `start` : démarre le composant de façon contrôlée et refuse les états
    # ambigus.
    def start(
        self,
        root_pid: int,
        session_id: str,
        agent_name: str,
        llm_events: Optional[Iterable[LLMInteractionEvent]] = None,
    ) -> None:
        """Backward-compatible alias for attaching to an existing root PID."""
        self.start_existing(root_pid, session_id, agent_name, llm_events=llm_events)

    # [BESOIN A/B/C/E/P] Fonction `start_command` : lance un agent sous contrôle, attache le capteur
    # avant exec et crée sa session.
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
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not normalized_command or not normalized_command[0]:
            # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise ValueError("command must not be empty")
        self._begin_start()
        process: Optional[subprocess.Popen[bytes]] = None
        collector_started = False
        # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            process = subprocess.Popen(
                [sys.executable, "-c", self.GATED_EXEC_CODE, *normalized_command],
                stdout=stdout,
                stderr=stderr,
            )
            # [BESOIN A/B/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture
            # déterministes.
            with self._state_lock:
                self._owned_process = process
            self._wait_for_pre_exec_stop(process)
            root_event = process_event_from_proc(process.pid)
            self.collector.start(root_pid=process.pid)
            collector_started = True
            self.runtime.create_session(session_id, agent_name, root_event)
            # [BESOIN A/B/C/E/P] Boucle de traitement : parcourt chaque élément de manière déterministe
            # et traçable.
            for event in llm_events or []:
                self.runtime.record_llm_interaction(
                    event.model_copy(update={"session_id": session_id})
                )
            self._start_loop()
            os.kill(process.pid, signal.SIGCONT)
            return process
        except Exception:
            # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if process is not None:
                # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
                # diagnostic explicite.
                try:
                    os.kill(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
                # diagnostic explicite.
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if collector_started:
                self.collector.stop()
            # [BESOIN A/B/C/E/P] Gestion de ressource : garantit une ouverture et une fermeture
            # déterministes.
            with self._state_lock:
                self._owned_process = None
            # [BESOIN A/B/C/E/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de
            # produire une fausse preuve.
            raise
        finally:
            self._finish_start()

    # [BESOIN A/B/C/E/P] Fonction `_collect_loop` : fonction dédiée à l’opération `_collect_loop` dans
    # le flux qui consiste à orchestrer l’attachement au processus racine et la
    # boucle de collecte en arrière-plan.
    def _collect_loop(self) -> None:
        # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            # [BESOIN A/B/C/E/P] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la
            # condition d’arrêt.
            while not self._stop.is_set():
                events = self.collector.poll(timeout=0.25)
                # [BESOIN A/B/C/E/P] Boucle de traitement : parcourt chaque élément de manière
                # déterministe et traçable.
                for event in events:
                    self.runtime.ingest(event)
        except Exception as exc:  # keep the API alive but expose the failure
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._stop.set()

    # [BESOIN A/B/C/E/P] Fonction `stop` : arrête proprement le composant et libère les ressources
    # associées.
    def stop(self, terminate_owned_process: bool = True) -> None:
        self._stop.set()
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self.collector.stop()
        process = self._owned_process
        # [BESOIN A/B/C/E/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if terminate_owned_process and process and process.poll() is None:
            process.terminate()
            # [BESOIN A/B/C/E/P] Gestion d’erreur : isole les dépendances externes et conserve un
            # diagnostic explicite.
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        self._owned_process = None
        self._thread = None

    # [BESOIN A/B/C/E/P] Fonction `metrics` : expose les compteurs de fonctionnement, d’erreur et de
    # perte nécessaires à l’observabilité.
    def metrics(self) -> dict:
        return {
            **self.collector.metrics(),
            **self.runtime.metrics(),
            "service_error": self.last_error,
            "service_running": int(bool(self._thread and self._thread.is_alive())),
            "service_starting": int(self._starting),
        }

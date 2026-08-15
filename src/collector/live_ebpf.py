"""Build and supervise the native libbpf ring-buffer collector."""
from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN A] Partie A - architecture AgentSight et chaîne Linux kernel vers collecteur userspace.
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# Rôle du module : préparer, compiler, lancer et surveiller le collecteur natif libbpf.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import ctypes.util
import json
import platform
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


# [BESOIN A/B/P] Classe `LiveEBPFError` : implémente le comportement documenté par sa docstring : «
# Raised when the live kernel collector cannot be built or started ».
class LiveEBPFError(RuntimeError):
    """Raised when the live kernel collector cannot be built or started."""


# [BESOIN A/B/P] Fonction `_run_capture` : fonction dédiée à l’opération `_run_capture` dans le flux qui
# consiste à préparer, compiler, lancer et surveiller le collecteur natif libbpf.
def _run_capture(
    command: List[str], *, timeout: float = 30.0
) -> subprocess.CompletedProcess[str]:
    # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux fonctionnel.
    if timeout <= 0:
        # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire une
        # fausse preuve.
        raise ValueError("timeout must be positive")
    # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
    # explicite.
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # [BESOIN A/B/P] Fonction `as_text` : fonction dédiée à l’opération `as_text` dans le flux qui
        # consiste à préparer, compiler, lancer et surveiller le collecteur natif libbpf.
        def as_text(value: object, fallback: str = "") -> str:
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if value is None:
                return fallback
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return str(value)

        return subprocess.CompletedProcess(
            command,
            124,
            as_text(exc.stdout),
            as_text(exc.stderr, "timed out"),
        )


# [BESOIN A/B/P] Fonction `_has_bpf_capabilities` : implémente le comportement documenté par sa
# docstring : « Accept CAP_SYS_ADMIN or the modern CAP_BPF + CAP_PERFMON pair ».
def _has_bpf_capabilities() -> bool:
    """Accept CAP_SYS_ADMIN or the modern CAP_BPF + CAP_PERFMON pair."""
    # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
    # explicite.
    try:
        # [BESOIN A/B/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if line.startswith("CapEff:"):
                effective = int(line.split()[1], 16)
                cap_sys_admin = bool(effective & (1 << 21))
                cap_perfmon = bool(effective & (1 << 38))
                cap_bpf = bool(effective & (1 << 39))
                return cap_sys_admin or (cap_perfmon and cap_bpf)
    except (OSError, ValueError, IndexError):
        return False
    return False


# [BESOIN A/B/P] Fonction `_tracepoint_exists` : fonction dédiée à l’opération `_tracepoint_exists` dans
# le flux qui consiste à préparer, compiler, lancer et surveiller le collecteur natif
# libbpf.
def _tracepoint_exists(group: str, name: str) -> bool:
    relative = Path("events") / group / name / "id"
    roots = (Path("/sys/kernel/tracing"), Path("/sys/kernel/debug/tracing"))
    return any((root / relative).exists() for root in roots)


# [BESOIN A/B/P] Fonction `_libbpf_available` : fonction dédiée à l’opération `_libbpf_available` dans
# le flux qui consiste à préparer, compiler, lancer et surveiller le collecteur natif
# libbpf.
def _libbpf_available() -> bool:
    pkg_config = shutil.which("pkg-config")
    # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux fonctionnel.
    if pkg_config and _run_capture([pkg_config, "--exists", "libbpf"]).returncode == 0:
        return True
    headers = (
        Path("/usr/include/bpf/libbpf.h").exists()
        and Path("/usr/include/bpf/bpf.h").exists()
        and (Path("/usr/include/libelf.h").exists() or Path("/usr/include/gelf.h").exists())
    )
    libraries = all(ctypes.util.find_library(name) is not None for name in ("bpf", "elf", "z"))
    return headers and libraries


# [BESOIN A/B/P] Fonction `_clang_has_bpf_target` : fonction dédiée à l’opération
# `_clang_has_bpf_target` dans le flux qui consiste à préparer, compiler, lancer et
# surveiller le collecteur natif libbpf.
def _clang_has_bpf_target(clang: str) -> bool:
    result = _run_capture([clang, "-print-targets"])
    return result.returncode == 0 and any(
        line.strip().startswith("bpf") for line in result.stdout.splitlines()
    )


# [BESOIN A/B/P] Classe `LiveExecCollector` : implémente le comportement documenté par sa docstring : «
# CO-RE loader plus a bounded Python queue for normalized JSON records ».
class LiveExecCollector:
    """CO-RE loader plus a bounded Python queue for normalized JSON records."""

    # [BESOIN A/B/P] Constante `REQUIRED_TRACEPOINTS` : fixe un paramètre stable et auditable utilisé
    # par ce module.
    REQUIRED_TRACEPOINTS = (
        ("syscalls", "sys_enter_execve"),
        ("syscalls", "sys_exit_execve"),
        ("sched", "sched_process_exec"),
        ("sched", "sched_process_fork"),
        ("sched", "sched_process_exit"),
    )

    # [BESOIN A/B/P] Fonction `__init__` : initialise l’état interne et les dépendances nécessaires au
    # composant.
    def __init__(
        self,
        source_dir: Optional[Path] = None,
        build_dir: Optional[Path] = None,
        queue_size: int = 16384,
    ):
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if queue_size <= 0:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("queue_size must be positive")
        root = Path(__file__).resolve().parents[1]
        self.source_dir = Path(source_dir) if source_dir else root / "ebpf"
        self.build_dir = Path(build_dir) if build_dir else root.parent / ".build" / "ebpf"
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.vmlinux_h = self.build_dir / "vmlinux.h"
        self.object_path = self.build_dir / "agentsight_probe.o"
        self.helper_path = self.build_dir / "agentsight-ebpf-collector"
        self.process: Optional[subprocess.Popen[str]] = None
        self.event_queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=queue_size)
        self.reader_thread: Optional[threading.Thread] = None
        self.stderr_thread: Optional[threading.Thread] = None
        self.ready = threading.Event()
        self.stderr_lines: List[str] = []
        self.userspace_queue_drops = 0
        self.json_decode_errors = 0
        self.unknown_record_types = 0
        self.invalid_stats_records = 0
        self.last_exit_code: Optional[int] = None
        self.root_pid: Optional[int] = None
        self.tracked_pids: List[int] = []
        self.kernel_stats: Dict[str, int] = {
            "kernel_ringbuf_drops": 0,
            "pending_update_failures": 0,
            "failed_execs": 0,
            "missing_pending": 0,
            "tracking_state_failures": 0,
            "file_state_failures": 0,
            "network_state_failures": 0,
            "missing_file_pending": 0,
            "missing_network_pending": 0,
            "emitted_events": 0,
        }

    # [BESOIN A/B/P] Fonction `build_preflight` : vérifie les outils nécessaires à la compilation avant
    # de produire les binaires.
    @staticmethod
    def build_preflight() -> Dict[str, Any]:
        missing: List[str] = []
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if platform.system() != "Linux":
            return {"ok": False, "reason": "Linux is required", "missing": ["Linux"]}
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not Path("/sys/kernel/btf/vmlinux").exists():
            missing.append("kernel BTF at /sys/kernel/btf/vmlinux")

        bpftool = shutil.which("bpftool")
        clang = shutil.which("clang")
        cc = shutil.which("cc")
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not bpftool:
            missing.append("bpftool")
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not clang:
            missing.append("clang")
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        elif not _clang_has_bpf_target(clang):
            missing.append("clang with BPF target")
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not cc:
            missing.append("C compiler")
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not _libbpf_available():
            missing.append("libbpf development headers/library")

        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if missing:
            return {"ok": False, "reason": "missing: " + ", ".join(missing), "missing": missing}
        return {
            "ok": True,
            "reason": "BTF and libbpf build toolchain are available",
            "missing": [],
        }

    # [BESOIN A/B/P] Fonction `preflight` : vérifie les dépendances, capacités et prérequis avant toute
    # opération privilégiée.
    @classmethod
    def preflight(cls) -> Dict[str, Any]:
        build = cls.build_preflight()
        missing: List[str] = list(build["missing"])
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if platform.system() == "Linux":
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if not _has_bpf_capabilities():
                missing.append("CAP_SYS_ADMIN or CAP_BPF+CAP_PERFMON")
            # [BESOIN A/B/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
            # traçable.
            for group, name in cls.REQUIRED_TRACEPOINTS:
                # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
                # fonctionnel.
                if not _tracepoint_exists(group, name):
                    missing.append(f"tracepoint {group}:{name}")

        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if missing:
            return {"ok": False, "reason": "missing: " + ", ".join(missing), "missing": missing}
        return {
            "ok": True,
            "reason": "kernel, capabilities and libbpf toolchain are available",
            "missing": [],
        }

    # [BESOIN A/B/P] Fonction `_run` : fonction dédiée à l’opération `_run` dans le flux qui consiste à
    # préparer, compiler, lancer et surveiller le collecteur natif libbpf.
    @staticmethod
    def _run(command: List[str], *, stdout=None, timeout: float = 120.0) -> None:
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if timeout <= 0:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("timeout must be positive")
        # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            result = subprocess.run(
                command,
                stdout=stdout,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise LiveEBPFError(
                f"command timed out after {timeout:g}s: {' '.join(command)}"
            ) from exc
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if result.returncode != 0:
            detail = result.stderr.strip() or f"command failed with exit code {result.returncode}"
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise LiveEBPFError(f"{detail}\ncommand: {' '.join(command)}")

    # [BESOIN A/B/P] Fonction `build` : compile le probe eBPF et le collecteur natif en conservant des
    # erreurs actionnables.
    def build(self) -> Dict[str, str]:
        status = self.build_preflight()
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not status["ok"]:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise LiveEBPFError(str(status["reason"]))

        bpftool = shutil.which("bpftool")
        clang = shutil.which("clang")
        cc = shutil.which("cc")
        # [BESOIN A/B/P] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
        # besoin.
        assert bpftool and clang and cc

        # [BESOIN A/B/P] Gestion de ressource : garantit une ouverture et une fermeture déterministes.
        with self.vmlinux_h.open("w", encoding="utf-8") as handle:
            self._run(
                [bpftool, "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"],
                stdout=handle,
            )

        machine = platform.machine().lower()
        target_arch = {
            "x86_64": "x86",
            "amd64": "x86",
            "aarch64": "arm64",
            "arm64": "arm64",
            "ppc64le": "powerpc",
            "s390x": "s390",
            "riscv64": "riscv",
        }.get(machine)
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not target_arch:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise LiveEBPFError(f"unsupported architecture: {machine}")

        include_dirs = [self.build_dir, self.source_dir, Path("/usr/include")]
        multiarch = {
            "x86_64": "x86_64-linux-gnu",
            "amd64": "x86_64-linux-gnu",
            "aarch64": "aarch64-linux-gnu",
            "arm64": "aarch64-linux-gnu",
            "ppc64le": "powerpc64le-linux-gnu",
            "s390x": "s390x-linux-gnu",
            "riscv64": "riscv64-linux-gnu",
        }.get(machine)
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if multiarch:
            include_dirs.append(Path("/usr/include") / multiarch)

        bpf_command = [
            clang,
            "-O2",
            "-g",
            "-target",
            "bpf",
            f"-D__TARGET_ARCH_{target_arch}",
            "-Wall",
            "-Wextra",
            "-Werror",
        ]
        # [BESOIN A/B/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for include_dir in include_dirs:
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if include_dir.exists():
                bpf_command.extend(["-I", str(include_dir)])
        bpf_command.extend(["-c", str(self.source_dir / "probe.c"), "-o", str(self.object_path)])
        self._run(bpf_command)

        pkg_config = shutil.which("pkg-config")
        cflags: List[str] = []
        libraries: List[str] = ["-lbpf", "-lelf", "-lz"]
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if pkg_config and _run_capture([pkg_config, "--exists", "libbpf"]).returncode == 0:
            cflags_result = _run_capture([pkg_config, "--cflags", "libbpf"])
            libs_result = _run_capture([pkg_config, "--libs", "libbpf"])
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if cflags_result.returncode == 0:
                cflags = cflags_result.stdout.split()
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if libs_result.returncode == 0:
                libraries = libs_result.stdout.split()

        helper_command = [
            cc,
            "-O2",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(self.source_dir),
            *cflags,
            str(self.source_dir / "native" / "collector.c"),
            "-o",
            str(self.helper_path),
            *libraries,
        ]
        self._run(helper_command)
        return {"object": str(self.object_path), "helper": str(self.helper_path)}

    # [BESOIN A/B/P] Fonction `_clear_runtime_state` : fonction dédiée à l’opération
    # `_clear_runtime_state` dans le flux qui consiste à préparer, compiler, lancer et
    # surveiller le collecteur natif libbpf.
    def _clear_runtime_state(self) -> None:
        self.ready.clear()
        self.stderr_lines.clear()
        # [BESOIN A/B/P] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la condition
        # d’arrêt.
        while True:
            # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
            # explicite.
            try:
                self.event_queue.get_nowait()
            except queue.Empty:
                break
        self.userspace_queue_drops = 0
        self.json_decode_errors = 0
        self.unknown_record_types = 0
        self.invalid_stats_records = 0
        self.last_exit_code = None
        # [BESOIN A/B/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for key in self.kernel_stats:
            self.kernel_stats[key] = 0

    # [BESOIN A/B/P] Fonction `start` : démarre le composant de façon contrôlée et refuse les états
    # ambigus.
    def start(
        self,
        startup_timeout: float = 8.0,
        *,
        root_pid: Optional[int] = None,
        tracked_pids: Optional[Iterable[int]] = None,
    ) -> None:
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self.process and self.process.poll() is None:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise LiveEBPFError("native eBPF collector is already running")
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if self.process is not None:
            self.stop()
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if startup_timeout <= 0:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("startup_timeout must be positive")
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if root_pid is not None and root_pid <= 0:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("root_pid must be positive")
        normalized_tracked = list(tracked_pids or [])
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if any(pid <= 0 for pid in normalized_tracked):
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("tracked_pids must contain only positive PIDs")
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if len(set(normalized_tracked)) > 4095:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("at most 4095 additional tracked PIDs are supported")
        status = self.preflight()
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not status["ok"]:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise LiveEBPFError(str(status["reason"]))
        self._clear_runtime_state()
        self.root_pid = root_pid
        self.tracked_pids = list(dict.fromkeys(normalized_tracked))
        self.build()

        command = [str(self.helper_path), str(self.object_path)]
        supplied: List[int] = []
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if root_pid is not None:
            command.extend(["--root-pid", str(root_pid)])
            supplied.append(root_pid)
        # [BESOIN A/B/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for pid in self.tracked_pids:
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if pid > 0 and pid not in supplied:
                command.extend(["--track-pid", str(pid)])
                supplied.append(pid)

        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            errors="replace",
        )
        self.reader_thread = threading.Thread(
            target=self._read_stdout,
            name="agentsight-ebpf-stdout",
            daemon=True,
        )
        self.stderr_thread = threading.Thread(
            target=self._read_stderr,
            name="agentsight-ebpf-stderr",
            daemon=True,
        )
        self.reader_thread.start()
        self.stderr_thread.start()

        deadline = time.monotonic() + startup_timeout
        # [BESOIN A/B/P] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la condition
        # d’arrêt.
        while time.monotonic() < deadline:
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if self.ready.wait(timeout=0.05):
                return
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if self.process.poll() is not None:
                break
        detail = "\n".join(self.stderr_lines[-30:])
        self.stop()
        # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire une
        # fausse preuve.
        raise LiveEBPFError(detail or "native eBPF collector did not become ready")

    # [BESOIN A/B/P] Fonction `_read_stdout` : fonction dédiée à l’opération `_read_stdout` dans le flux
    # qui consiste à préparer, compiler, lancer et surveiller le collecteur natif libbpf.
    def _read_stdout(self) -> None:
        # [BESOIN A/B/P] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
        # besoin.
        assert self.process and self.process.stdout
        known = {
            "exec",
            "fork",
            "exit",
            "file_open",
            "file_write",
            "file_delete",
            "network_connect",
        }
        # [BESOIN A/B/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for line in self.process.stdout:
            # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
            # explicite.
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                self.json_decode_errors += 1
                continue
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if not isinstance(record, dict):
                self.json_decode_errors += 1
                continue
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if record.get("record_type") == "stats":
                # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un
                # diagnostic explicite.
                try:
                    updated = {
                        key: int(record.get(key, self.kernel_stats[key]))
                        for key in self.kernel_stats
                    }
                except (TypeError, ValueError, OverflowError):
                    self.invalid_stats_records += 1
                    continue
                self.kernel_stats.update(updated)
                continue
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if record.get("record_type") not in known:
                self.unknown_record_types += 1
                continue
            # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
            # explicite.
            try:
                self.event_queue.put_nowait(record)
            except queue.Full:
                self.userspace_queue_drops += 1

    # [BESOIN A/B/P] Fonction `_read_stderr` : fonction dédiée à l’opération `_read_stderr` dans le flux
    # qui consiste à préparer, compiler, lancer et surveiller le collecteur natif libbpf.
    def _read_stderr(self) -> None:
        # [BESOIN A/B/P] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
        # besoin.
        assert self.process and self.process.stderr
        # [BESOIN A/B/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for line in self.process.stderr:
            text = line.rstrip()
            self.stderr_lines.append(text)
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if len(self.stderr_lines) > 400:
                del self.stderr_lines[:100]
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if text.startswith("READY "):
                self.ready.set()

    # [BESOIN A/B/P] Fonction `_raise_if_native_exited` : fonction dédiée à l’opération
    # `_raise_if_native_exited` dans le flux qui consiste à préparer, compiler, lancer et
    # surveiller le collecteur natif libbpf.
    def _raise_if_native_exited(self) -> None:
        process = self.process
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if process is None:
            return
        return_code = process.poll()
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if return_code is None:
            return
        self.last_exit_code = int(return_code)
        detail = "\n".join(self.stderr_lines[-30:]).strip()
        message = f"native eBPF collector exited unexpectedly with code {return_code}"
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if detail:
            message += f":\n{detail}"
        # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire une
        # fausse preuve.
        raise LiveEBPFError(message)

    # [BESOIN A/B/P] Fonction `poll` : récupère un lot borné d’événements sans bloquer indéfiniment le
    # runtime.
    def poll(self, timeout: float = 0.25, max_events: int = 512) -> List[Dict[str, Any]]:
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if timeout < 0:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("timeout must be non-negative")
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if max_events <= 0:
            # [BESOIN A/B/P] Échec explicite : refuse une donnée ou un état ambigu au lieu de produire
            # une fausse preuve.
            raise ValueError("max_events must be positive")
        events: List[Dict[str, Any]] = []
        # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
        # explicite.
        try:
            events.append(self.event_queue.get(timeout=timeout))
        except queue.Empty:
            self._raise_if_native_exited()
            return events
        # [BESOIN A/B/P] Boucle contrôlée : maintient la collecte ou l’attente jusqu’à la condition
        # d’arrêt.
        while len(events) < max_events:
            # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
            # explicite.
            try:
                events.append(self.event_queue.get_nowait())
            except queue.Empty:
                break
        return events

    # [BESOIN A/B/P] Fonction `metrics` : expose les compteurs de fonctionnement, d’erreur et de perte
    # nécessaires à l’observabilité.
    def metrics(self) -> Dict[str, Any]:
        process = self.process
        return_code = process.poll() if process is not None else self.last_exit_code
        return {
            **self.kernel_stats,
            "userspace_queue_drops": self.userspace_queue_drops,
            "json_decode_errors": self.json_decode_errors,
            "unknown_record_types": self.unknown_record_types,
            "invalid_stats_records": self.invalid_stats_records,
            "queued_events": self.event_queue.qsize(),
            "collector_running": int(bool(process and return_code is None)),
            "native_exit_code": return_code,
            "sensor_root_pid": self.root_pid,
            "seeded_tracked_pids": len(self.tracked_pids),
        }

    # [BESOIN A/B/P] Fonction `stop` : arrête proprement le composant et libère les ressources
    # associées.
    def stop(self) -> None:
        process = self.process
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if not process:
            self.ready.clear()
            return
        # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
        # fonctionnel.
        if process.poll() is None:
            process.terminate()
            # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un diagnostic
            # explicite.
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        return_code = process.poll()
        self.last_exit_code = int(return_code) if return_code is not None else None
        # [BESOIN A/B/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for stream in (process.stdout, process.stderr):
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if stream is not None:
                # [BESOIN A/B/P] Gestion d’erreur : isole les dépendances externes et conserve un
                # diagnostic explicite.
                try:
                    stream.close()
                except OSError:
                    pass
        current = threading.current_thread()
        # [BESOIN A/B/P] Boucle de traitement : parcourt chaque élément de manière déterministe et
        # traçable.
        for thread in (self.reader_thread, self.stderr_thread):
            # [BESOIN A/B/P] Condition de garde : valide le cas courant avant de poursuivre le flux
            # fonctionnel.
            if thread and thread is not current and thread.is_alive():
                thread.join(timeout=1.0)
        self.process = None
        self.reader_thread = None
        self.stderr_thread = None
        self.ready.clear()

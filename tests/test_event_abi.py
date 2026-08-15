from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : prouver l’unicité et la compatibilité de l’ABI partagée kernel/userspace.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import shutil
import subprocess
from pathlib import Path

import pytest

# [TESTS / BESOIN B/P/T] Constante `ROOT` : fixe un paramètre stable et auditable utilisé par ce module.
ROOT = Path(__file__).resolve().parents[1]
# [TESTS / BESOIN B/P/T] Constante `EVENT_H` : fixe un paramètre stable et auditable utilisé par ce
# module.
EVENT_H = ROOT / "src" / "ebpf" / "event.h"
# [TESTS / BESOIN B/P/T] Constante `PROBE_C` : fixe un paramètre stable et auditable utilisé par ce
# module.
PROBE_C = ROOT / "src" / "ebpf" / "probe.c"
# [TESTS / BESOIN B/P/T] Constante `COLLECTOR_C` : fixe un paramètre stable et auditable utilisé par ce
# module.
COLLECTOR_C = ROOT / "src" / "ebpf" / "native" / "collector.c"


# [TESTS / BESOIN B/P/T] Fonction `test_event_header_is_the_single_shared_abi_source` : prouve
# automatiquement le scénario `test_event_header_is_the_single_shared_abi_source`
# et protège le comportement contre les régressions.
def test_event_header_is_the_single_shared_abi_source() -> None:
    header = EVENT_H.read_text(encoding="utf-8")
    probe = PROBE_C.read_text(encoding="utf-8")
    collector = COLLECTOR_C.read_text(encoding="utf-8")

    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "#define AGENTSIGHT_SCHEMA_VERSION 2" in header
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "#define AGENTSIGHT_MAX_ARGS 6" in header
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert '#include "event.h"' in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert '#include "../event.h"' in collector
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "struct agentsight_kernel_event {" not in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "struct agentsight_kernel_event {" not in collector
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert 'SEC("raw_tracepoint/sched_process_fork")' in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "child_pid == parent_pid" in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "thread-group leader" in probe


# [TESTS / BESOIN B/P/T] Fonction `test_native_abi_size_and_offsets_match_static_contract` : prouve
# automatiquement le scénario
# `test_native_abi_size_and_offsets_match_static_contract` et protège le
# comportement contre les régressions.
def test_native_abi_size_and_offsets_match_static_contract(tmp_path: Path) -> None:
    cc = shutil.which("cc")
    # [TESTS / BESOIN B/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if not cc:
        pytest.skip("C compiler is unavailable")

    source = tmp_path / "abi_check.c"
    binary = tmp_path / "abi_check"
    source.write_text(
        """
#include <stddef.h>
#include <stdio.h>
#include \"event.h\"
int main(void) {
    printf(\"%zu %zu %zu %zu %zu\\n\",
        sizeof(struct agentsight_event_header),
        sizeof(struct agentsight_exec_payload),
        sizeof(struct agentsight_kernel_event),
        offsetof(struct agentsight_event_header, timestamp_ns),
        offsetof(struct agentsight_kernel_event, payload));
    return 0;
}
""",
        encoding="utf-8",
    )
    compile_result = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(EVENT_H.parent), str(source), "-o", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert compile_result.returncode == 0, compile_result.stderr
    output = subprocess.check_output([str(binary)], text=True).strip()
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert output == "72 1040 1112 24 72"


# [TESTS / BESOIN B/P/T] Fonction `test_native_collector_emits_each_event_once` : prouve automatiquement
# le scénario `test_native_collector_emits_each_event_once` et protège le
# comportement contre les régressions.
def test_native_collector_emits_each_event_once() -> None:
    source = COLLECTOR_C.read_text(encoding="utf-8")
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert source.count('print_file(event, "file_write");') == 1
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert source.count('print_exec(event);') == 1
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert source.count('print_network(event);') == 1
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "missing required tracepoint" in source
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "SKIP unavailable optional tracepoint" in source
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "raw_tracepoint/sched_process_fork" in source


# [TESTS / BESOIN B/P/T] Fonction `test_procfs_and_kernel_process_identity_use_one_clock_basis` : prouve
# automatiquement le scénario
# `test_procfs_and_kernel_process_identity_use_one_clock_basis` et protège le
# comportement contre les régressions.
def test_procfs_and_kernel_process_identity_use_one_clock_basis() -> None:
    header = EVENT_H.read_text(encoding="utf-8")
    probe = PROBE_C.read_text(encoding="utf-8")
    collector = COLLECTOR_C.read_text(encoding="utf-8")

    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "start_boottime" in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "clock_tick_ns" in header
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "config.clock_tick_ns" in collector
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "_SC_CLK_TCK" in collector
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "start_ns / clock_tick_ns" in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "return BPF_CORE_READ(task, start_time);" not in probe


# [TESTS / BESOIN B/P/T] Fonction
# `test_optional_openat2_is_variable_size_safe_and_close_is_result_aware` :
# prouve automatiquement le scénario
# `test_optional_openat2_is_variable_size_safe_and_close_is_result_aware` et
# protège le comportement contre les régressions.
def test_optional_openat2_is_variable_size_safe_and_close_is_result_aware() -> None:
    probe = PROBE_C.read_text(encoding="utf-8")

    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert 'SEC("tracepoint/syscalls/sys_enter_openat2")' in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "how_size = ctx->args[3]" in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "how_size >= sizeof(flags)" in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "struct user_open_how" not in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert 'SEC("tracepoint/syscalls/sys_enter_close")' in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert 'SEC("tracepoint/syscalls/sys_exit_close")' in probe
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert "ctx->ret == 0" in probe


# [TESTS / BESOIN B/P/T] Fonction `test_ring_reader_exists_before_any_probe_is_attached` : prouve
# automatiquement le scénario
# `test_ring_reader_exists_before_any_probe_is_attached` et protège le
# comportement contre les régressions.
def test_ring_reader_exists_before_any_probe_is_attached() -> None:
    collector = COLLECTOR_C.read_text(encoding="utf-8")
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert collector.index("ring_buffer__new") < collector.index("bpf_program__attach")


# [TESTS / BESOIN B/P/T] Fonction `test_loss_metrics_cover_transport_and_pending_state` : prouve
# automatiquement le scénario
# `test_loss_metrics_cover_transport_and_pending_state` et protège le
# comportement contre les régressions.
def test_loss_metrics_cover_transport_and_pending_state() -> None:
    header = EVENT_H.read_text(encoding="utf-8")
    collector = COLLECTOR_C.read_text(encoding="utf-8")
    # [TESTS / BESOIN B/P/T] Boucle de traitement : parcourt chaque élément de manière déterministe et
    # traçable.
    for field in (
        "ringbuf_drops",
        "missing_pending",
        "missing_file_pending",
        "missing_network_pending",
        "tracking_state_failures",
        "file_state_failures",
        "network_state_failures",
        "emitted_events",
    ):
        # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
        # le besoin.
        assert field in header
        # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par
        # le besoin.
        assert field in collector

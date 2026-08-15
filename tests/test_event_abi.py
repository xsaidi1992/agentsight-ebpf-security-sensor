from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVENT_H = ROOT / "src" / "ebpf" / "event.h"
PROBE_C = ROOT / "src" / "ebpf" / "probe.c"
COLLECTOR_C = ROOT / "src" / "ebpf" / "native" / "collector.c"


def test_event_header_is_the_single_shared_abi_source() -> None:
    header = EVENT_H.read_text(encoding="utf-8")
    probe = PROBE_C.read_text(encoding="utf-8")
    collector = COLLECTOR_C.read_text(encoding="utf-8")

    assert "#define AGENTSIGHT_SCHEMA_VERSION 2" in header
    assert "#define AGENTSIGHT_MAX_ARGS 6" in header
    assert '#include "event.h"' in probe
    assert '#include "../event.h"' in collector
    assert "struct agentsight_kernel_event {" not in probe
    assert "struct agentsight_kernel_event {" not in collector
    assert 'SEC("raw_tracepoint/sched_process_fork")' in probe
    assert "child_pid == parent_pid" in probe
    assert "thread-group leader" in probe


def test_native_abi_size_and_offsets_match_static_contract(tmp_path: Path) -> None:
    cc = shutil.which("cc")
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
    assert compile_result.returncode == 0, compile_result.stderr
    output = subprocess.check_output([str(binary)], text=True).strip()
    assert output == "72 1040 1112 24 72"


def test_native_collector_emits_each_event_once() -> None:
    source = COLLECTOR_C.read_text(encoding="utf-8")
    assert source.count('print_file(event, "file_write");') == 1
    assert source.count('print_exec(event);') == 1
    assert source.count('print_network(event);') == 1
    assert "missing required tracepoint" in source
    assert "SKIP unavailable optional tracepoint" in source
    assert "raw_tracepoint/sched_process_fork" in source


def test_procfs_and_kernel_process_identity_use_one_clock_basis() -> None:
    header = EVENT_H.read_text(encoding="utf-8")
    probe = PROBE_C.read_text(encoding="utf-8")
    collector = COLLECTOR_C.read_text(encoding="utf-8")

    assert "start_boottime" in probe
    assert "clock_tick_ns" in header
    assert "config.clock_tick_ns" in collector
    assert "_SC_CLK_TCK" in collector
    assert "start_ns / clock_tick_ns" in probe
    assert "return BPF_CORE_READ(task, start_time);" not in probe


def test_optional_openat2_is_variable_size_safe_and_close_is_result_aware() -> None:
    probe = PROBE_C.read_text(encoding="utf-8")

    assert 'SEC("tracepoint/syscalls/sys_enter_openat2")' in probe
    assert "how_size = ctx->args[3]" in probe
    assert "how_size >= sizeof(flags)" in probe
    assert "struct user_open_how" not in probe
    assert 'SEC("tracepoint/syscalls/sys_enter_close")' in probe
    assert 'SEC("tracepoint/syscalls/sys_exit_close")' in probe
    assert "ctx->ret == 0" in probe


def test_ring_reader_exists_before_any_probe_is_attached() -> None:
    collector = COLLECTOR_C.read_text(encoding="utf-8")
    assert collector.index("ring_buffer__new") < collector.index("bpf_program__attach")


def test_loss_metrics_cover_transport_and_pending_state() -> None:
    header = EVENT_H.read_text(encoding="utf-8")
    collector = COLLECTOR_C.read_text(encoding="utf-8")
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
        assert field in header
        assert field in collector

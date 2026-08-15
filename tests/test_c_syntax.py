from __future__ import annotations

# =============================================================================
# TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
# [BESOIN B] Partie B - probe eBPF, capture des événements système et transport par ring buffer.
# [BESOIN P] Section 10 - performance, scalabilité, backpressure et observabilité des pertes.
# [BESOIN T] Section 11 - démonstration reproductible, tests et livrables.
# Rôle du module : vérifier la syntaxe C des composants eBPF et libbpf sans privilège kernel.
# Les commentaires [BESOIN ...] relient chaque fonction et bloc logique à la partie concernée.
# =============================================================================


import shutil
import subprocess
from pathlib import Path

import pytest

# [TESTS / BESOIN B/P/T] Constante `ROOT` : fixe un paramètre stable et auditable utilisé par ce module.
ROOT = Path(__file__).resolve().parents[1]
# [TESTS / BESOIN B/P/T] Constante `EBPF` : fixe un paramètre stable et auditable utilisé par ce module.
EBPF = ROOT / "src" / "ebpf"


# [TESTS / BESOIN B/P/T] Fonction `_write` : fonction dédiée à l’opération `_write` dans le flux qui
# consiste à vérifier la syntaxe C des composants eBPF et libbpf sans privilège
# kernel.
def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# [TESTS / BESOIN B/P/T] Fonction `test_probe_and_native_collector_are_c_syntax_clean` : prouve
# automatiquement le scénario
# `test_probe_and_native_collector_are_c_syntax_clean` et protège le comportement
# contre les régressions.
def test_probe_and_native_collector_are_c_syntax_clean(tmp_path: Path) -> None:
    clang = shutil.which("clang") or shutil.which("cc")
    # [TESTS / BESOIN B/P/T] Condition de garde : valide le cas courant avant de poursuivre le flux
    # fonctionnel.
    if not clang:
        pytest.skip("C compiler is unavailable")

    include = tmp_path / "include"
    _write(
        include / "vmlinux.h",
        r'''#ifndef TEST_VMLINUX_H
#define TEST_VMLINUX_H
#include <linux/types.h>
#include <linux/bpf.h>
struct task_struct {
    struct task_struct *real_parent;
    __u32 tgid;
    __u64 start_boottime;
    __u64 start_time;
    __s32 exit_code;
    char comm[16];
};
struct trace_event_raw_sys_enter { __u64 args[6]; };
struct trace_event_raw_sys_exit { __s64 ret; };
struct trace_event_raw_sched_process_exec { __u64 unused; };
struct trace_event_raw_sched_process_template { __u64 unused; };
#endif
''',
    )
    _write(
        include / "bpf" / "bpf_helpers.h",
        r'''#ifndef TEST_BPF_HELPERS_H
#define TEST_BPF_HELPERS_H
#include <linux/bpf.h>
#include <stddef.h>
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
extern void *bpf_map_lookup_elem(const void *, const void *);
extern long bpf_map_update_elem(const void *, const void *, const void *, __u64);
extern long bpf_map_delete_elem(const void *, const void *);
extern __u64 bpf_get_current_pid_tgid(void);
extern __u64 bpf_get_current_uid_gid(void);
extern void *bpf_get_current_task(void);
extern __u64 bpf_ktime_get_ns(void);
extern long bpf_get_current_comm(void *, __u32);
extern long bpf_probe_read_user(void *, __u32, const void *);
extern long bpf_probe_read_user_str(void *, __u32, const void *);
extern void *bpf_ringbuf_reserve(const void *, __u64, __u64);
extern void bpf_ringbuf_submit(void *, __u64);
#endif
''',
    )
    _write(
        include / "bpf" / "bpf_core_read.h",
        r'''#ifndef TEST_BPF_CORE_READ_H
#define TEST_BPF_CORE_READ_H
#define BPF_CORE_READ(source, field) ((source)->field)
#define bpf_core_field_exists(field) (1)
#define BPF_CORE_READ_STR_INTO(destination, source, field) \
    ({ __builtin_memcpy((destination), (source)->field, sizeof(*(destination))); 0; })
#endif
''',
    )
    _write(
        include / "bpf" / "bpf_endian.h",
        r'''#ifndef TEST_BPF_ENDIAN_H
#define TEST_BPF_ENDIAN_H
#define bpf_ntohs(value) __builtin_bswap16((unsigned short)(value))
#endif
''',
    )
    _write(
        include / "bpf" / "bpf.h",
        r'''#ifndef TEST_BPF_H
#define TEST_BPF_H
#include <linux/bpf.h>
int bpf_map_lookup_elem(int fd, const void *key, void *value);
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
#endif
''',
    )
    _write(
        include / "bpf" / "libbpf.h",
        r'''#ifndef TEST_LIBBPF_H
#define TEST_LIBBPF_H
#include <stdbool.h>
#include <stddef.h>
struct bpf_object; struct bpf_program; struct bpf_link; struct ring_buffer;
struct bpf_object *bpf_object__open_file(const char *, const void *);
long libbpf_get_error(const void *);
int bpf_object__load(struct bpf_object *);
void bpf_object__close(struct bpf_object *);
int bpf_object__find_map_fd_by_name(const struct bpf_object *, const char *);
struct bpf_program *test_bpf_object_next_program(const struct bpf_object *, struct bpf_program *);
#define bpf_object__for_each_program(pos, obj) \
    for ((pos) = test_bpf_object_next_program((obj), NULL); (pos); \
         (pos) = test_bpf_object_next_program((obj), (pos)))
const char *bpf_program__section_name(const struct bpf_program *);
const char *bpf_program__name(const struct bpf_program *);
int bpf_program__set_autoload(struct bpf_program *, bool);
int bpf_program__fd(const struct bpf_program *);
struct bpf_link *bpf_program__attach(const struct bpf_program *);
void bpf_link__destroy(struct bpf_link *);
typedef int (*ring_buffer_sample_fn)(void *, void *, size_t);
struct ring_buffer *ring_buffer__new(int, ring_buffer_sample_fn, void *, const void *);
int ring_buffer__poll(struct ring_buffer *, int);
void ring_buffer__free(struct ring_buffer *);
#endif
''',
    )

    common = [clang, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsyntax-only"]
    probe = subprocess.run(
        [*common, "-I", str(include), "-I", str(EBPF), str(EBPF / "probe.c")],
        capture_output=True,
        text=True,
        check=False,
    )
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert probe.returncode == 0, probe.stderr

    native = subprocess.run(
        [*common, "-I", str(include), "-I", str(EBPF), str(EBPF / "native" / "collector.c")],
        capture_output=True,
        text=True,
        check=False,
    )
    # [TESTS / BESOIN B/P/T] Assertion de preuve : vérifie automatiquement l’invariant attendu par le
    # besoin.
    assert native.returncode == 0, native.stderr

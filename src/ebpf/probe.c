// SPDX-License-Identifier: Dual BSD/GPL
/*
 * AgentSight assessment sensor.
 *
 * Primary event: successful process execution with bounded argv capture.
 * Additional events: fork, exit, successful open/write/delete, and connect.
 * A root-PID filter is populated by the userspace loader and propagated to
 * descendants at sched_process_fork, which limits kernel and userspace load.
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "event.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef EINPROGRESS
#define EINPROGRESS 115
#endif

#define AGENTSIGHT_MAX_ANCESTRY_DEPTH 16

struct pending_exec {
    char filename[AGENTSIGHT_PATH_LEN];
    char argv[AGENTSIGHT_MAX_ARGS][AGENTSIGHT_ARG_LEN];
    __u32 argc;
    __u32 argv_truncated;
    __u32 syscall_kind;
    __u32 filename_truncated;
};

struct pending_file {
    char path[AGENTSIGHT_PATH_LEN];
    __s32 dirfd;
    __u32 open_flags;
    __u32 path_truncated;
};

struct open_file_key {
    __u32 tgid;
    __s32 fd;
};

struct open_file_value {
    char path[AGENTSIGHT_PATH_LEN];
    __s32 dirfd;
    __u32 open_flags;
    __u32 path_truncated;
};

struct pending_write {
    __s32 fd;
};

struct pending_close {
    __s32 fd;
};

struct pending_delete {
    char path[AGENTSIGHT_PATH_LEN];
    __s32 dirfd;
    __u32 path_truncated;
};

struct pending_network {
    __u16 family;
    __u16 port;
    __u8 address[16];
};

struct user_sockaddr_in {
    __u16 family;
    __u16 port;
    __u32 address;
    __u8 zero[8];
};

struct user_in6_addr {
    __u8 bytes[16];
};

struct user_sockaddr_in6 {
    __u16 family;
    __u16 port;
    __u32 flowinfo;
    struct user_in6_addr address;
    __u32 scope_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_exec);
} exec_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct pending_exec);
} pending_execs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_file);
} pending_files SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct open_file_key);
    __type(value, struct open_file_value);
} open_files SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_write);
} pending_writes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_close);
} pending_closes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct pending_delete);
} pending_deletes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_network);
} pending_networks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __u64);
} tracked_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agentsight_sensor_config);
} sensor_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sequence_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agentsight_sensor_stats);
} sensor_stats SEC(".maps");

static __always_inline struct agentsight_sensor_stats *get_stats(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&sensor_stats, &key);
}

static __always_inline void increment_stat(__u64 *counter)
{
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline __u64 next_sequence(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&sequence_map, &key);

    if (!value)
        return 0;
    return __sync_fetch_and_add(value, 1) + 1;
}

static __always_inline struct agentsight_sensor_config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&sensor_config, &key);
}

static __always_inline __u64 task_start_ns_with_tick(
    struct task_struct *task, __u64 clock_tick_ns)
{
    __u64 start_ns;

    if (!task)
        return 0;
    /* /proc/<pid>/stat field 22 is derived from start_boottime and rounded to
     * userspace clock ticks. Quantizing the kernel value with the loader's
     * clock period makes procfs seeds and eBPF events one stable identity. */
    start_ns = BPF_CORE_READ(task, start_boottime);
    if (clock_tick_ns)
        start_ns = (start_ns / clock_tick_ns) * clock_tick_ns;
    return start_ns;
}

static __always_inline __u64 task_start_ns(struct task_struct *task)
{
    struct agentsight_sensor_config *config = get_config();
    return task_start_ns_with_tick(task, config ? config->clock_tick_ns : 0);
}

static __always_inline int task_belongs_to_root(
    struct task_struct *task, const struct agentsight_sensor_config *config)
{
    int i;

    if (!task || !config || !config->root_pid)
        return 0;
#pragma unroll
    for (i = 0; i < AGENTSIGHT_MAX_ANCESTRY_DEPTH; i++) {
        __u32 candidate_pid;
        __u64 candidate_start;
        struct task_struct *parent;

        if (!task)
            return 0;
        candidate_pid = BPF_CORE_READ(task, tgid);
        candidate_start = task_start_ns_with_tick(task, config->clock_tick_ns);
        if (candidate_pid == config->root_pid) {
            if (!config->root_start_ns || candidate_start == config->root_start_ns)
                return 1;
            return 0;
        }
        parent = BPF_CORE_READ(task, real_parent);
        if (!parent || parent == task)
            return 0;
        task = parent;
    }
    return 0;
}

static __always_inline int should_trace(__u32 tgid)
{
    struct agentsight_sensor_config *config = get_config();
    struct task_struct *task;
    __u64 *tracked;

    if (!config || !config->filter_enabled)
        return 1;
    tracked = bpf_map_lookup_elem(&tracked_pids, &tgid);
    if (tracked)
        return 1;

    /* Recover an existing/racing descendant that was not present when the
     * userspace seed snapshot was taken. The expensive walk only happens on a
     * cache miss; successful recovery is cached in tracked_pids. */
    task = (struct task_struct *)bpf_get_current_task();
    if (task_belongs_to_root(task, config)) {
        __u64 start_ns = task_start_ns(task);
        if (bpf_map_update_elem(&tracked_pids, &tgid, &start_ns, BPF_ANY) < 0) {
            struct agentsight_sensor_stats *stats = get_stats();
            if (stats)
                increment_stat(&stats->tracking_state_failures);
        }
        return 1;
    }
    return 0;
}

static __always_inline __u64 tracked_start(__u32 tgid)
{
    __u64 *value = bpf_map_lookup_elem(&tracked_pids, &tgid);
    return value ? *value : 0;
}

static __always_inline void current_identity(__u32 *pid, __u32 *ppid,
                                              __u64 *start_ns, __u64 *parent_start_ns)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    *pid = bpf_get_current_pid_tgid() >> 32;
    *ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
    *start_ns = task_start_ns(task);
    *parent_start_ns = task_start_ns(parent);
}

static __always_inline struct agentsight_kernel_event *reserve_event(
    __u8 event_type, __u32 pid, __u32 ppid, __u64 start_ns, __u64 parent_start_ns)
{
    struct agentsight_sensor_stats *stats;
    struct agentsight_kernel_event *event;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u64 sequence = next_sequence();

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        stats = get_stats();
        if (stats)
            increment_stat(&stats->ringbuf_drops);
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->header.version = AGENTSIGHT_SCHEMA_VERSION;
    event->header.event_type = event_type;
    event->header.pid = pid;
    event->header.ppid = ppid;
    event->header.uid = (__u32)uid_gid;
    event->header.gid = (__u32)(uid_gid >> 32);
    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.sequence = sequence;
    event->header.process_start_ns = start_ns;
    event->header.parent_start_ns = parent_start_ns;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));
    return event;
}

static __always_inline void submit_event(struct agentsight_kernel_event *event)
{
    struct agentsight_sensor_stats *stats = get_stats();

    if (stats)
        increment_stat(&stats->emitted_events);
    bpf_ringbuf_submit(event, 0);
}

static __always_inline int capture_exec_entry(const char *filename,
                                               const char *const *argv,
                                               __u32 syscall_kind)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 zero = 0;
    struct pending_exec *value;
    struct agentsight_sensor_stats *stats;
    int i;

    if (!should_trace(tgid))
        return 0;
    value = bpf_map_lookup_elem(&exec_scratch, &zero);
    if (!value)
        return 0;

    __builtin_memset(value, 0, sizeof(*value));
    if (filename) {
        long filename_size = bpf_probe_read_user_str(
            value->filename, sizeof(value->filename), filename);
        if (filename_size >= (__s64)sizeof(value->filename))
            value->filename_truncated = 1;
    }
    value->syscall_kind = syscall_kind;

    if (argv) {
#pragma unroll
        for (i = 0; i < AGENTSIGHT_MAX_ARGS; i++) {
            const char *argp = 0;

            long read_size;

            if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0 || !argp)
                break;
            read_size = bpf_probe_read_user_str(
                value->argv[i], sizeof(value->argv[i]), argp);
            if (read_size > 0) {
                value->argc++;
                if (read_size >= (__s64)sizeof(value->argv[i]))
                    value->argv_truncated = 1;
            }
        }
        {
            const char *extra = 0;
            if (bpf_probe_read_user(&extra, sizeof(extra), &argv[AGENTSIGHT_MAX_ARGS]) == 0 && extra)
                value->argv_truncated = 1;
        }
    }

    if (bpf_map_update_elem(&pending_execs, &tgid, value, BPF_ANY) < 0) {
        stats = get_stats();
        if (stats)
            increment_stat(&stats->pending_update_failures);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int capture_execve(struct trace_event_raw_sys_enter *ctx)
{
    return capture_exec_entry((const char *)ctx->args[0],
                              (const char *const *)ctx->args[1],
                              AGENTSIGHT_SYSCALL_EXECVE);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int capture_execveat(struct trace_event_raw_sys_enter *ctx)
{
    return capture_exec_entry((const char *)ctx->args[1],
                              (const char *const *)ctx->args[2],
                              AGENTSIGHT_SYSCALL_EXECVEAT);
}

static __always_inline int cleanup_failed_exec(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct agentsight_sensor_stats *stats;

    if ((__s64)ctx->ret >= 0)
        return 0;
    if (bpf_map_lookup_elem(&pending_execs, &tgid)) {
        bpf_map_delete_elem(&pending_execs, &tgid);
        stats = get_stats();
        if (stats)
            increment_stat(&stats->failed_execs);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int cleanup_failed_execve(struct trace_event_raw_sys_exit *ctx)
{
    return cleanup_failed_exec(ctx);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int cleanup_failed_execveat(struct trace_event_raw_sys_exit *ctx)
{
    return cleanup_failed_exec(ctx);
}

SEC("tracepoint/sched/sched_process_exec")
int emit_successful_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid;
    __u32 ppid;
    __u64 start_ns;
    __u64 parent_start_ns;
    struct pending_exec *saved;
    struct agentsight_kernel_event *event;
    struct agentsight_sensor_stats *stats;

    (void)ctx;
    current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
    if (!should_trace(pid))
        return 0;
    saved = bpf_map_lookup_elem(&pending_execs, &pid);
    if (!saved) {
        stats = get_stats();
        if (stats)
            increment_stat(&stats->missing_pending);
        return 0;
    }

    {
        struct agentsight_sensor_config *config = get_config();
        if (config && config->filter_enabled &&
            bpf_map_update_elem(&tracked_pids, &pid, &start_ns, BPF_ANY) < 0) {
            stats = get_stats();
            if (stats)
                increment_stat(&stats->tracking_state_failures);
        }
    }
    event = reserve_event(AGENTSIGHT_EVENT_EXEC, pid, ppid, start_ns, parent_start_ns);
    if (!event) {
        bpf_map_delete_elem(&pending_execs, &pid);
        return 0;
    }
    event->payload.exec.argc = saved->argc;
    event->payload.exec.argv_truncated = saved->argv_truncated;
    event->payload.exec.syscall_kind = saved->syscall_kind;
    event->payload.exec.filename_truncated = saved->filename_truncated;
    __builtin_memcpy(event->payload.exec.filename, saved->filename,
                     sizeof(event->payload.exec.filename));
    __builtin_memcpy(event->payload.exec.argv, saved->argv,
                     sizeof(event->payload.exec.argv));
    submit_event(event);
    bpf_map_delete_elem(&pending_execs, &pid);
    return 0;
}

SEC("raw_tracepoint/sched_process_fork")
int emit_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];
    __u32 parent_pid;
    __u32 child_pid;
    __u64 tracked_parent_start;
    __u64 parent_start_ns;
    __u64 child_start_ns;
    struct agentsight_sensor_config *config = get_config();
    struct agentsight_kernel_event *event;

    if (!parent || !child)
        return 0;
    parent_pid = BPF_CORE_READ(parent, tgid);
    child_pid = BPF_CORE_READ(child, tgid);
    /* CLONE_THREAD creates a task, not a new process/session node. */
    if (!parent_pid || !child_pid || child_pid == parent_pid)
        return 0;
    tracked_parent_start = tracked_start(parent_pid);
    parent_start_ns = task_start_ns(parent);
    if (config && config->filter_enabled && !tracked_parent_start) {
        if (!task_belongs_to_root(parent, config))
            return 0;
        if (bpf_map_update_elem(&tracked_pids, &parent_pid,
                                &parent_start_ns, BPF_ANY) < 0) {
            struct agentsight_sensor_stats *stats = get_stats();
            if (stats)
                increment_stat(&stats->tracking_state_failures);
        }
    }

    child_start_ns = task_start_ns(child);
    if (config && config->filter_enabled &&
        bpf_map_update_elem(&tracked_pids, &child_pid, &child_start_ns, BPF_ANY) < 0) {
        struct agentsight_sensor_stats *stats = get_stats();
        if (stats)
            increment_stat(&stats->tracking_state_failures);
    }

    event = reserve_event(AGENTSIGHT_EVENT_FORK, child_pid, parent_pid,
                          child_start_ns, parent_start_ns);
    if (!event)
        return 0;
    BPF_CORE_READ_STR_INTO(&event->header.comm, child, comm);
    event->payload.fork.child_pid = child_pid;
    event->payload.fork.parent_pid = parent_pid;
    event->payload.fork.child_start_ns = child_start_ns;
    event->payload.fork.parent_start_ns = parent_start_ns;
    BPF_CORE_READ_STR_INTO(&event->payload.fork.child_comm, child, comm);
    submit_event(event);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int emit_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid;
    __u32 ppid;
    __u64 start_ns;
    __u64 parent_start_ns;
    __s32 raw_exit;
    struct task_struct *task;
    struct agentsight_kernel_event *event;

    (void)ctx;
    /* sched_process_exit fires for every thread; emit process exit only for
     * the thread-group leader to avoid premature session termination. */
    if ((__u32)pid_tgid != (__u32)(pid_tgid >> 32))
        return 0;
    current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
    if (!should_trace(pid))
        return 0;
    task = (struct task_struct *)bpf_get_current_task();
    raw_exit = BPF_CORE_READ(task, exit_code);

    event = reserve_event(AGENTSIGHT_EVENT_EXIT, pid, ppid, start_ns, parent_start_ns);
    if (event) {
        event->payload.exit.exit_code = (raw_exit >> 8) & 0xff;
        event->payload.exit.signal = raw_exit & 0x7f;
        event->payload.exit.duration_ns =
            start_ns && event->header.timestamp_ns > start_ns
                ? event->header.timestamp_ns - start_ns
                : 0;
        submit_event(event);
    }
    {
        struct agentsight_sensor_config *config = get_config();
        if (config && config->filter_enabled)
            bpf_map_delete_elem(&tracked_pids, &pid);
    }
    return 0;
}

static __always_inline int capture_open_entry(const char *path, __s32 dirfd,
                                               __u32 open_flags)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    struct pending_file value = {};
    struct agentsight_sensor_stats *stats;

    if (!should_trace(tgid))
        return 0;
    value.dirfd = dirfd;
    value.open_flags = open_flags;
    if (path) {
        long path_size = bpf_probe_read_user_str(value.path, sizeof(value.path), path);
        if (path_size >= (__s64)sizeof(value.path))
            value.path_truncated = 1;
    }
    if (bpf_map_update_elem(&pending_files, &pid_tgid, &value, BPF_ANY) < 0) {
        stats = get_stats();
        if (stats)
            increment_stat(&stats->file_state_failures);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int capture_openat(struct trace_event_raw_sys_enter *ctx)
{
    return capture_open_entry((const char *)ctx->args[1],
                              (__s32)ctx->args[0],
                              (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int capture_openat2(struct trace_event_raw_sys_enter *ctx)
{
    const void *how_ptr = (const void *)ctx->args[2];
    __u64 how_size = ctx->args[3];
    __u64 flags = 0;

    /* openat2 accepts versioned, variable-sized open_how structures.  Reading
     * only the first 64-bit flags field is compatible with both the current
     * structure and future extensions, and avoids a failed full-structure
     * read when userspace deliberately passes a smaller size. */
    if (how_ptr && how_size >= sizeof(flags))
        bpf_probe_read_user(&flags, sizeof(flags), how_ptr);
    return capture_open_entry((const char *)ctx->args[1],
                              (__s32)ctx->args[0],
                              (__u32)flags);
}

static __always_inline int emit_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid;
    __u32 ppid;
    __u64 start_ns;
    __u64 parent_start_ns;
    struct pending_file *saved;
    struct open_file_key key;
    struct open_file_value file_value = {};
    struct agentsight_kernel_event *event;
    __s64 result = (__s64)ctx->ret;

    saved = bpf_map_lookup_elem(&pending_files, &pid_tgid);
    if (!saved) {
        if (should_trace((__u32)(pid_tgid >> 32))) {
            struct agentsight_sensor_stats *stats = get_stats();
            if (stats)
                increment_stat(&stats->missing_file_pending);
        }
        return 0;
    }
    if (result >= 0) {
        current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
        event = reserve_event(AGENTSIGHT_EVENT_FILE_OPEN, pid, ppid,
                              start_ns, parent_start_ns);
        if (event) {
            __builtin_memcpy(event->payload.file.path, saved->path,
                             sizeof(event->payload.file.path));
            event->payload.file.fd = (__s32)result;
            event->payload.file.dirfd = saved->dirfd;
            event->payload.file.open_flags = saved->open_flags;
            event->payload.file.operation = AGENTSIGHT_FILE_OPERATION_OPEN;
            event->payload.file.result = result;
            event->payload.file.path_truncated = saved->path_truncated;
            submit_event(event);
        }
        key.tgid = pid;
        key.fd = (__s32)result;
        __builtin_memcpy(file_value.path, saved->path, sizeof(file_value.path));
        file_value.dirfd = saved->dirfd;
        file_value.open_flags = saved->open_flags;
        file_value.path_truncated = saved->path_truncated;
        if (bpf_map_update_elem(&open_files, &key, &file_value, BPF_ANY) < 0) {
            struct agentsight_sensor_stats *stats = get_stats();
            if (stats)
                increment_stat(&stats->file_state_failures);
        }
    }
    bpf_map_delete_elem(&pending_files, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int emit_openat(struct trace_event_raw_sys_exit *ctx)
{
    return emit_open_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int emit_openat2(struct trace_event_raw_sys_exit *ctx)
{
    return emit_open_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_write")
int capture_write(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    struct pending_write value = {};

    if (!should_trace(tgid))
        return 0;
    value.fd = (__s32)ctx->args[0];
    if (bpf_map_update_elem(&pending_writes, &pid_tgid, &value, BPF_ANY) < 0) {
        struct agentsight_sensor_stats *stats = get_stats();
        if (stats)
            increment_stat(&stats->file_state_failures);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int emit_write(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid;
    __u32 ppid;
    __u64 start_ns;
    __u64 parent_start_ns;
    struct pending_write *pending_write_value;
    struct open_file_key key;
    struct open_file_value *file_value;
    struct agentsight_kernel_event *event;
    __s64 result = (__s64)ctx->ret;

    pending_write_value = bpf_map_lookup_elem(&pending_writes, &pid_tgid);
    if (!pending_write_value) {
        if (should_trace((__u32)(pid_tgid >> 32))) {
            struct agentsight_sensor_stats *stats = get_stats();
            if (stats)
                increment_stat(&stats->missing_file_pending);
        }
        return 0;
    }
    if (result > 0) {
        pid = pid_tgid >> 32;
        key.tgid = pid;
        key.fd = pending_write_value->fd;
        file_value = bpf_map_lookup_elem(&open_files, &key);
        current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
        event = reserve_event(AGENTSIGHT_EVENT_FILE_WRITE, pid, ppid,
                              start_ns, parent_start_ns);
        if (event) {
            event->payload.file.fd = pending_write_value->fd;
            event->payload.file.dirfd = -100;
            if (file_value) {
                __builtin_memcpy(event->payload.file.path, file_value->path,
                                 sizeof(event->payload.file.path));
                event->payload.file.dirfd = file_value->dirfd;
                event->payload.file.open_flags = file_value->open_flags;
                event->payload.file.path_truncated = file_value->path_truncated;
            }
            event->payload.file.operation = AGENTSIGHT_FILE_OPERATION_WRITE;
            event->payload.file.result = result;
            event->payload.file.bytes = (__u64)result;
            submit_event(event);
        }
    }
    bpf_map_delete_elem(&pending_writes, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int capture_close(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    struct pending_close value = {};

    if (!should_trace(tgid))
        return 0;
    value.fd = (__s32)ctx->args[0];
    if (bpf_map_update_elem(&pending_closes, &pid_tgid, &value, BPF_ANY) < 0) {
        struct agentsight_sensor_stats *stats = get_stats();
        if (stats)
            increment_stat(&stats->file_state_failures);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int cleanup_closed_fd(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_close *saved = bpf_map_lookup_elem(&pending_closes, &pid_tgid);

    if (!saved) {
        if (should_trace((__u32)(pid_tgid >> 32))) {
            struct agentsight_sensor_stats *stats = get_stats();
            if (stats)
                increment_stat(&stats->missing_file_pending);
        }
        return 0;
    }
    if ((__s64)ctx->ret == 0) {
        struct open_file_key key = {};
        key.tgid = pid_tgid >> 32;
        key.fd = saved->fd;
        bpf_map_delete_elem(&open_files, &key);
    }
    bpf_map_delete_elem(&pending_closes, &pid_tgid);
    return 0;
}

static __always_inline int capture_delete_entry(const char *path, __s32 dirfd)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    struct pending_delete value = {};

    if (!should_trace(tgid))
        return 0;
    value.dirfd = dirfd;
    if (path) {
        long path_size = bpf_probe_read_user_str(value.path, sizeof(value.path), path);
        if (path_size >= (__s64)sizeof(value.path))
            value.path_truncated = 1;
    }
    if (bpf_map_update_elem(&pending_deletes, &pid_tgid, &value, BPF_ANY) < 0) {
        struct agentsight_sensor_stats *stats = get_stats();
        if (stats)
            increment_stat(&stats->file_state_failures);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int capture_unlink(struct trace_event_raw_sys_enter *ctx)
{
    return capture_delete_entry((const char *)ctx->args[0], -100);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int capture_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    return capture_delete_entry((const char *)ctx->args[1], (__s32)ctx->args[0]);
}

static __always_inline int emit_delete_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid;
    __u32 ppid;
    __u64 start_ns;
    __u64 parent_start_ns;
    struct pending_delete *saved;
    struct agentsight_kernel_event *event;
    __s64 result = (__s64)ctx->ret;

    saved = bpf_map_lookup_elem(&pending_deletes, &pid_tgid);
    if (!saved) {
        if (should_trace((__u32)(pid_tgid >> 32))) {
            struct agentsight_sensor_stats *stats = get_stats();
            if (stats)
                increment_stat(&stats->missing_file_pending);
        }
        return 0;
    }
    if (result == 0) {
        current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
        event = reserve_event(AGENTSIGHT_EVENT_FILE_DELETE, pid, ppid,
                              start_ns, parent_start_ns);
        if (event) {
            __builtin_memcpy(event->payload.file.path, saved->path,
                             sizeof(event->payload.file.path));
            event->payload.file.dirfd = saved->dirfd;
            event->payload.file.fd = -1;
            event->payload.file.operation = AGENTSIGHT_FILE_OPERATION_DELETE;
            event->payload.file.result = result;
            event->payload.file.path_truncated = saved->path_truncated;
            submit_event(event);
        }
    }
    bpf_map_delete_elem(&pending_deletes, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int emit_unlink(struct trace_event_raw_sys_exit *ctx)
{
    return emit_delete_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int emit_unlinkat(struct trace_event_raw_sys_exit *ctx)
{
    return emit_delete_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int capture_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    const void *address = (const void *)ctx->args[1];
    struct pending_network value = {};
    __u16 family = 0;
    struct agentsight_sensor_stats *stats;

    if (!should_trace(tgid) || !address)
        return 0;
    if (bpf_probe_read_user(&family, sizeof(family), address) < 0)
        return 0;
    value.family = family;
    if (family == AF_INET) {
        struct user_sockaddr_in addr4 = {};
        if (bpf_probe_read_user(&addr4, sizeof(addr4), address) < 0)
            return 0;
        value.port = bpf_ntohs(addr4.port);
        __builtin_memcpy(value.address, &addr4.address, sizeof(addr4.address));
    } else if (family == AF_INET6) {
        struct user_sockaddr_in6 addr6 = {};
        if (bpf_probe_read_user(&addr6, sizeof(addr6), address) < 0)
            return 0;
        value.port = bpf_ntohs(addr6.port);
        __builtin_memcpy(value.address, addr6.address.bytes, sizeof(value.address));
    } else {
        return 0;
    }
    if (bpf_map_update_elem(&pending_networks, &pid_tgid, &value, BPF_ANY) < 0) {
        stats = get_stats();
        if (stats)
            increment_stat(&stats->network_state_failures);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int emit_connect(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid;
    __u32 ppid;
    __u64 start_ns;
    __u64 parent_start_ns;
    struct pending_network *saved;
    struct agentsight_kernel_event *event;
    __s64 result = (__s64)ctx->ret;

    saved = bpf_map_lookup_elem(&pending_networks, &pid_tgid);
    if (!saved) {
        if (should_trace((__u32)(pid_tgid >> 32))) {
            struct agentsight_sensor_stats *stats = get_stats();
            if (stats)
                increment_stat(&stats->missing_network_pending);
        }
        return 0;
    }
    if (result == 0 || result == -EINPROGRESS) {
        current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
        event = reserve_event(AGENTSIGHT_EVENT_NETWORK_CONNECT, pid, ppid,
                              start_ns, parent_start_ns);
        if (event) {
            event->payload.network.family = saved->family;
            event->payload.network.port = saved->port;
            __builtin_memcpy(event->payload.network.address, saved->address,
                             sizeof(event->payload.network.address));
            event->payload.network.result = (__s32)result;
            submit_event(event);
        }
    }
    bpf_map_delete_elem(&pending_networks, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

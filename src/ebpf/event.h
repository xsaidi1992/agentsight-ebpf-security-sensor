#ifndef AGENTSIGHT_EVENT_H
#define AGENTSIGHT_EVENT_H

/* bpftool-generated vmlinux.h already defines the kernel integer types.
 * Userspace compilation still needs linux/types.h. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define AGENTSIGHT_SCHEMA_VERSION 2

#define AGENTSIGHT_EVENT_EXEC 1
#define AGENTSIGHT_EVENT_FORK 2
#define AGENTSIGHT_EVENT_EXIT 3
#define AGENTSIGHT_EVENT_FILE_OPEN 4
#define AGENTSIGHT_EVENT_FILE_WRITE 5
#define AGENTSIGHT_EVENT_FILE_DELETE 6
#define AGENTSIGHT_EVENT_NETWORK_CONNECT 7

#define AGENTSIGHT_SYSCALL_EXECVE 1
#define AGENTSIGHT_SYSCALL_EXECVEAT 2

#define AGENTSIGHT_FILE_OPERATION_OPEN 1
#define AGENTSIGHT_FILE_OPERATION_WRITE 2
#define AGENTSIGHT_FILE_OPERATION_DELETE 3

#define AGENTSIGHT_COMM_LEN 16
#define AGENTSIGHT_PATH_LEN 256
#define AGENTSIGHT_ARG_LEN 128
#define AGENTSIGHT_MAX_ARGS 6

struct agentsight_event_header {
    __u8 version;
    __u8 event_type;
    __u16 flags;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp_ns;
    __u64 sequence;
    __u64 process_start_ns;
    __u64 parent_start_ns;
    char comm[AGENTSIGHT_COMM_LEN];
};

struct agentsight_exec_payload {
    char filename[AGENTSIGHT_PATH_LEN];
    char argv[AGENTSIGHT_MAX_ARGS][AGENTSIGHT_ARG_LEN];
    __u32 argc;
    __u32 argv_truncated;
    __u32 syscall_kind;
    __u32 filename_truncated;
};

struct agentsight_fork_payload {
    __u32 child_pid;
    __u32 parent_pid;
    __u64 child_start_ns;
    __u64 parent_start_ns;
    char child_comm[AGENTSIGHT_COMM_LEN];
};

struct agentsight_exit_payload {
    __s32 exit_code;
    __s32 signal;
    __u64 duration_ns;
};

struct agentsight_file_payload {
    char path[AGENTSIGHT_PATH_LEN];
    __s32 fd;
    __s32 dirfd;
    __u32 open_flags;
    __u32 operation;
    __s64 result;
    __u64 bytes;
    __u32 path_truncated;
    __u32 reserved;
};

struct agentsight_network_payload {
    __u16 family;
    __u16 port;
    __u8 address[16];
    __s32 result;
    __u32 reserved;
};

struct agentsight_kernel_event {
    struct agentsight_event_header header;
    union {
        struct agentsight_exec_payload exec;
        struct agentsight_fork_payload fork;
        struct agentsight_exit_payload exit;
        struct agentsight_file_payload file;
        struct agentsight_network_payload network;
    } payload;
};

struct agentsight_sensor_config {
    __u32 filter_enabled;
    __u32 root_pid;
    __u64 root_start_ns;
    __u64 clock_tick_ns;
};

struct agentsight_sensor_stats {
    __u64 ringbuf_drops;
    __u64 pending_update_failures;
    __u64 failed_execs;
    __u64 missing_pending;
    __u64 tracking_state_failures;
    __u64 file_state_failures;
    __u64 network_state_failures;
    __u64 missing_file_pending;
    __u64 missing_network_pending;
    __u64 emitted_events;
};

#endif

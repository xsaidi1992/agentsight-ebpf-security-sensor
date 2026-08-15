// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../event.h"

/*
 * =============================================================================
 * TRACEABILITE DETAILLEE AVEC LE TECHNICAL ASSESSMENT
 * [BESOIN A] Ce binaire est le collecteur userspace relié directement au ring buffer.
 * [BESOIN B] Il valide l’ABI et transforme chaque record kernel en JSONL structuré.
 * [BESOIN C] Il amorce le PID racine et les PID déjà suivis avant l’attachement.
 * [BESOIN P] Il publie les métriques de perte, gère les tracepoints optionnels et nettoie les ressources.
 * =============================================================================
 */


_Static_assert(sizeof(struct agentsight_event_header) == 72,
               "unexpected event-header ABI size");
_Static_assert(sizeof(struct agentsight_kernel_event) == 1112,
               "unexpected kernel-event ABI size");

#define MAX_TRACKED_ARGUMENTS 4096

static volatile sig_atomic_t stop;

/* [BESOIN A/P] Fonction `on_signal` : convertit SIGINT/SIGTERM en arrêt propre de la boucle de collecte. */
static void on_signal(int signo)
{
    (void)signo;
    stop = 1;
}

/* [BESOIN A/B] Fonction `json_string_n` : échappe une chaîne bornée pour produire un JSONL valide sans
 * lecture hors limites. */
static void json_string_n(const char *s, size_t max_len)
{
    size_t i;

    putchar('"');
    /* [BESOIN A/B/C/P] Boucle bornée : parcourt les éléments sans violer les contraintes du vérificateur
     * ou de mémoire. */
    for (i = 0; i < max_len && s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (c == '"' || c == '\\') {
            putchar('\\');
            putchar(c);
        } else if (c == '\n') {
            fputs("\\n", stdout);
        } else if (c == '\r') {
            fputs("\\r", stdout);
        } else if (c == '\t') {
            fputs("\\t", stdout);
        } else if (c < 0x20) {
            printf("\\u%04x", c);
        } else {
            putchar(c);
        }
    }
    putchar('"');
}

/* [BESOIN A/B/C] Fonction `print_common` : sérialise les champs communs de l’ABI kernel/userspace. */
static void print_common(const struct agentsight_kernel_event *event,
                         const char *record_type)
{
    const struct agentsight_event_header *header = &event->header;

    printf("{\"record_type\":\"%s\",\"version\":%u,\"event_type\":%u,"
           "\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"gid\":%u,"
           "\"timestamp_ns\":%llu,\"sequence\":%llu,"
           "\"process_start_ns\":%llu,\"parent_start_ns\":%llu,\"comm\":",
           record_type, header->version, header->event_type,
           header->pid, header->ppid, header->uid, header->gid,
           (unsigned long long)header->timestamp_ns,
           (unsigned long long)header->sequence,
           (unsigned long long)header->process_start_ns,
           (unsigned long long)header->parent_start_ns);
    json_string_n(header->comm, sizeof(header->comm));
}

/* [BESOIN A/B] Fonction `print_exec` : sérialise l’exécution, le chemin et argv pour le collecteur
 * Python. */
static void print_exec(const struct agentsight_kernel_event *event)
{
    unsigned int i;

    print_common(event, "exec");
    fputs(",\"filename\":", stdout);
    json_string_n(event->payload.exec.filename,
                  sizeof(event->payload.exec.filename));
    fputs(",\"argv\":[", stdout);
    /* [BESOIN A/B/C/P] Boucle bornée : parcourt les éléments sans violer les contraintes du vérificateur
     * ou de mémoire. */
    for (i = 0; i < event->payload.exec.argc && i < AGENTSIGHT_MAX_ARGS; i++) {
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (i)
            putchar(',');
        json_string_n(event->payload.exec.argv[i],
                      sizeof(event->payload.exec.argv[i]));
    }
    printf("],\"argv_truncated\":%s,\"filename_truncated\":%s,"
           "\"syscall_kind\":%u}\n",
           event->payload.exec.argv_truncated ? "true" : "false",
           event->payload.exec.filename_truncated ? "true" : "false",
           event->payload.exec.syscall_kind);
}

/* [BESOIN A/C] Fonction `print_fork` : sérialise la relation parent-enfant. */
static void print_fork(const struct agentsight_kernel_event *event)
{
    print_common(event, "fork");
    fputs(",\"child_comm\":", stdout);
    json_string_n(event->payload.fork.child_comm,
                  sizeof(event->payload.fork.child_comm));
    printf(",\"child_pid\":%u,\"parent_pid\":%u,"
           "\"child_start_ns\":%llu}\n",
           event->payload.fork.child_pid,
           event->payload.fork.parent_pid,
           (unsigned long long)event->payload.fork.child_start_ns);
}

/* [BESOIN A/C] Fonction `print_exit` : sérialise la terminaison et la durée du processus. */
static void print_exit(const struct agentsight_kernel_event *event)
{
    print_common(event, "exit");
    printf(",\"exit_code\":%d,\"signal\":%d,\"duration_ns\":%llu}\n",
           event->payload.exit.exit_code,
           event->payload.exit.signal,
           (unsigned long long)event->payload.exit.duration_ns);
}

/* [BESOIN A/B/D] Fonction `print_file` : sérialise open, write ou delete avec chemin et résultat. */
static void print_file(const struct agentsight_kernel_event *event,
                       const char *record_type)
{
    print_common(event, record_type);
    fputs(",\"path\":", stdout);
    json_string_n(event->payload.file.path,
                  sizeof(event->payload.file.path));
    printf(",\"fd\":%d,\"dirfd\":%d,\"open_flags\":%u,"
           "\"operation\":%u,\"result\":%lld,\"bytes\":%llu,"
           "\"path_truncated\":%s}\n",
           event->payload.file.fd,
           event->payload.file.dirfd,
           event->payload.file.open_flags,
           event->payload.file.operation,
           (long long)event->payload.file.result,
           (unsigned long long)event->payload.file.bytes,
           event->payload.file.path_truncated ? "true" : "false");
}

/* [BESOIN A/B/D] Fonction `print_network` : convertit l’adresse binaire en texte IPv4/IPv6 puis
 * sérialise connect. */
static void print_network(const struct agentsight_kernel_event *event)
{
    char address[INET6_ADDRSTRLEN] = "unknown";
    const void *source = event->payload.network.address;

    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (event->payload.network.family == AF_INET)
        (void)inet_ntop(AF_INET, source, address, sizeof(address));
    /* [BESOIN A/B/C/P] Branche alternative : traite explicitement un second cas supporté. */
    else if (event->payload.network.family == AF_INET6)
        (void)inet_ntop(AF_INET6, source, address, sizeof(address));

    print_common(event, "network_connect");
    fputs(",\"remote_addr\":", stdout);
    json_string_n(address, sizeof(address));
    printf(",\"remote_port\":%u,\"family\":%u,\"result\":%d}\n",
           event->payload.network.port,
           event->payload.network.family,
           event->payload.network.result);
}

/* [BESOIN A/B/P] Fonction `handle_event` : valide version et taille de l’ABI puis route chaque record du
 * ring buffer. */
static int handle_event(void *ctx, void *data, size_t size)
{
    const struct agentsight_kernel_event *event = data;

    (void)ctx;
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (size != sizeof(*event) ||
        event->header.version != AGENTSIGHT_SCHEMA_VERSION)
        return 0;

    /* [BESOIN A/B/C/P] Dispatch : sélectionne le traitement correspondant au type d’événement de l’ABI. */
    switch (event->header.event_type) {
    case AGENTSIGHT_EVENT_EXEC:
        print_exec(event);
        break;
    case AGENTSIGHT_EVENT_FORK:
        print_fork(event);
        break;
    case AGENTSIGHT_EVENT_EXIT:
        print_exit(event);
        break;
    case AGENTSIGHT_EVENT_FILE_OPEN:
        print_file(event, "file_open");
        break;
    case AGENTSIGHT_EVENT_FILE_WRITE:
        print_file(event, "file_write");
        break;
    case AGENTSIGHT_EVENT_FILE_DELETE:
        print_file(event, "file_delete");
        break;
    case AGENTSIGHT_EVENT_NETWORK_CONNECT:
        print_network(event);
        break;
    default:
        return 0;
    }
    fflush(stdout);
    return 0;
}

/* [BESOIN P] Fonction `emit_stats_if_changed` : publie les métriques kernel uniquement lorsqu’elles
 * changent. */
static void emit_stats_if_changed(int stats_fd,
                                  struct agentsight_sensor_stats *previous)
{
    __u32 key = 0;
    struct agentsight_sensor_stats current = {};

    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (stats_fd < 0 || bpf_map_lookup_elem(stats_fd, &key, &current) != 0)
        return;
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (memcmp(previous, &current, sizeof(current)) == 0)
        return;

    printf("{\"record_type\":\"stats\",\"kernel_ringbuf_drops\":%llu,"
           "\"pending_update_failures\":%llu,\"failed_execs\":%llu,"
           "\"missing_pending\":%llu,"
           "\"tracking_state_failures\":%llu,"
           "\"file_state_failures\":%llu,"
           "\"network_state_failures\":%llu,"
           "\"missing_file_pending\":%llu,"
           "\"missing_network_pending\":%llu,"
           "\"emitted_events\":%llu}\n",
           (unsigned long long)current.ringbuf_drops,
           (unsigned long long)current.pending_update_failures,
           (unsigned long long)current.failed_execs,
           (unsigned long long)current.missing_pending,
           (unsigned long long)current.tracking_state_failures,
           (unsigned long long)current.file_state_failures,
           (unsigned long long)current.network_state_failures,
           (unsigned long long)current.missing_file_pending,
           (unsigned long long)current.missing_network_pending,
           (unsigned long long)current.emitted_events);
    fflush(stdout);
    *previous = current;
}

/* [BESOIN C] Fonction `read_process_start_ns` : lit /proc/PID/stat pour produire la même identité
 * temporelle que le probe. */
static __u64 read_process_start_ns(__u32 pid)
{
    char path[64];
    char buffer[8192];
    char *right_paren;
    char *save = NULL;
    char *token;
    unsigned long long ticks = 0;
    long hz;
    int index = 0;
    FILE *handle;

    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    handle = fopen(path, "r");
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!handle)
        return 0;
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!fgets(buffer, sizeof(buffer), handle)) {
        fclose(handle);
        return 0;
    }
    fclose(handle);
    right_paren = strrchr(buffer, ')');
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!right_paren || right_paren[1] != ' ')
        return 0;
    token = strtok_r(right_paren + 2, " ", &save);
    /* [BESOIN A/B/C/P] Boucle contrôlée : maintient la collecte jusqu’à l’arrêt ou à une erreur
     * explicite. */
    while (token) {
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (index == 19) {
            char *end = NULL;
            errno = 0;
            ticks = strtoull(token, &end, 10);
            /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de
             * poursuivre. */
            if (errno || !end || (*end != '\0' && *end != '\n'))
                return 0;
            break;
        }
        index++;
        token = strtok_r(NULL, " ", &save);
    }
    hz = sysconf(_SC_CLK_TCK);
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!ticks || hz <= 0)
        return 0;
    return (__u64)(ticks / (unsigned long long)hz) * 1000000000ULL +
           (__u64)(ticks % (unsigned long long)hz) * 1000000000ULL /
               (unsigned long long)hz;
}

/* [BESOIN C] Fonction `parse_pid` : valide les PID fournis en ligne de commande. */
static int parse_pid(const char *value, __u32 *pid)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (errno || !end || *end != '\0' || parsed == 0 || parsed > 0xffffffffUL)
        return -1;
    *pid = (__u32)parsed;
    return 0;
}

/* [BESOIN B/T] Fonction `is_required_section` : distingue les tracepoints indispensables des extensions
 * optionnelles. */
static int is_required_section(const char *section)
{
    static const char *required[] = {
        "tracepoint/syscalls/sys_enter_execve",
        "tracepoint/syscalls/sys_exit_execve",
        "tracepoint/sched/sched_process_exec",
        "raw_tracepoint/sched_process_fork",
        "tracepoint/sched/sched_process_exit",
    };
    size_t i;

    /* [BESOIN A/B/C/P] Boucle bornée : parcourt les éléments sans violer les contraintes du vérificateur
     * ou de mémoire. */
    for (i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (section && strcmp(section, required[i]) == 0)
            return 1;
    }
    return 0;
}

/* [BESOIN B/T] Fonction `tracepoint_exists_for_section` : vérifie la présence réelle du tracepoint dans
 * tracefs/debugfs. */
static int tracepoint_exists_for_section(const char *section)
{
    const char *tracepoint_prefix = "tracepoint/";
    const char *raw_prefix = "raw_tracepoint/";
    const char *group;
    const char *name;
    const char *slash;
    char path[512];
    char raw_group[64] = {};
    size_t group_len;

    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!section)
        return 0;
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (strncmp(section, tracepoint_prefix, strlen(tracepoint_prefix)) == 0) {
        group = section + strlen(tracepoint_prefix);
        slash = strchr(group, '/');
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (!slash || !slash[1])
            return 0;
        group_len = (size_t)(slash - group);
        name = slash + 1;
    } else if (strncmp(section, raw_prefix, strlen(raw_prefix)) == 0) {
        name = section + strlen(raw_prefix);
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (strncmp(name, "sched_", 6) == 0)
            snprintf(raw_group, sizeof(raw_group), "sched");
        else
            return 1; /* no portable tracefs group inference */
        group = raw_group;
        group_len = strlen(group);
    } else {
        return 1;
    }

    snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%.*s/%s/id",
             (int)group_len, group, name);
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (access(path, R_OK) == 0)
        return 1;
    snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/%.*s/%s/id",
             (int)group_len, group, name);
    return access(path, R_OK) == 0;
}

/* [BESOIN B/T] Fonction `disable_unavailable_tracepoints` : désactive les probes optionnels
 * indisponibles et bloque si un probe requis manque. */
static int disable_unavailable_tracepoints(struct bpf_object *object)
{
    struct bpf_program *program;
    int missing_required = 0;

    /* [BESOIN A/B/C/P] Boucle bornée : parcourt les éléments sans violer les contraintes du vérificateur
     * ou de mémoire. */
    bpf_object__for_each_program(program, object) {
        const char *section = bpf_program__section_name(program);
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (tracepoint_exists_for_section(section))
            continue;
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (is_required_section(section)) {
            fprintf(stderr, "missing required tracepoint for section %s\n", section);
            missing_required = 1;
            continue;
        }
        fprintf(stderr, "SKIP unavailable optional tracepoint section %s\n", section);
        bpf_program__set_autoload(program, false);
    }
    return missing_required ? -1 : 0;
}

/* [BESOIN B/C/P] Fonction `configure_filter` : écrit la configuration et amorce les PID suivis avant
 * l’attachement. */
static int configure_filter(struct bpf_object *object,
                            const __u32 *tracked, size_t tracked_count,
                            __u32 root_pid)
{
    int config_fd = bpf_object__find_map_fd_by_name(object, "sensor_config");
    int tracked_fd = bpf_object__find_map_fd_by_name(object, "tracked_pids");
    struct agentsight_sensor_config config = {};
    __u32 key = 0;
    size_t i;

    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (config_fd < 0 || tracked_fd < 0) {
        fprintf(stderr, "sensor filter maps not found\n");
        return -1;
    }
    {
        long clock_ticks = sysconf(_SC_CLK_TCK);
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (clock_ticks <= 0) {
            fprintf(stderr, "unable to determine userspace clock tick rate\n");
            return -1;
        }
        config.clock_tick_ns = 1000000000ULL / (__u64)clock_ticks;
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (!config.clock_tick_ns) {
            fprintf(stderr, "invalid userspace clock tick rate: %ld\n", clock_ticks);
            return -1;
        }
    }
    config.filter_enabled = tracked_count > 0 ? 1 : 0;
    config.root_pid = root_pid;
    config.root_start_ns = root_pid ? read_process_start_ns(root_pid) : 0;
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (bpf_map_update_elem(config_fd, &key, &config, BPF_ANY) != 0) {
        fprintf(stderr, "failed to configure sensor filter: %s\n", strerror(errno));
        return -1;
    }
    /* [BESOIN A/B/C/P] Boucle bornée : parcourt les éléments sans violer les contraintes du vérificateur
     * ou de mémoire. */
    for (i = 0; i < tracked_count; i++) {
        __u64 marker = read_process_start_ns(tracked[i]);
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (!marker)
            marker = 1;
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (bpf_map_update_elem(tracked_fd, &tracked[i], &marker, BPF_ANY) != 0) {
            fprintf(stderr, "failed to seed tracked PID %u: %s\n",
                    tracked[i], strerror(errno));
            return -1;
        }
    }
    return 0;
}

/* [BESOIN T] Fonction `usage` : documente la syntaxe du collecteur natif. */
static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s <probe.o> [--root-pid PID] [--track-pid PID ...]\n",
            program);
}

/* [BESOIN A/B/C/P/T] Fonction `main` : orchestre ouverture, chargement, filtrage, ring buffer,
 * attachement, polling et nettoyage. */
int main(int argc, char **argv)
{
    const char *object_path;
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_link **links = NULL;
    struct ring_buffer *ring = NULL;
    struct agentsight_sensor_stats previous_stats = {};
    struct rlimit rlimit = {RLIM_INFINITY, RLIM_INFINITY};
    __u32 tracked[MAX_TRACKED_ARGUMENTS] = {};
    __u32 root_pid = 0;
    size_t tracked_count = 0;
    int link_count = 0;
    int link_capacity = 0;
    int events_fd;
    int stats_fd;
    int result = 1;
    int i;

    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    object_path = argv[1];
    /* [BESOIN A/B/C/P] Boucle bornée : parcourt les éléments sans violer les contraintes du vérificateur
     * ou de mémoire. */
    for (i = 2; i < argc; i++) {
        __u32 pid;
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if ((!strcmp(argv[i], "--root-pid") || !strcmp(argv[i], "--track-pid")) &&
            i + 1 < argc) {
            int is_root = !strcmp(argv[i], "--root-pid");
            /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de
             * poursuivre. */
            if (parse_pid(argv[++i], &pid) != 0 ||
                tracked_count >= MAX_TRACKED_ARGUMENTS) {
                usage(argv[0]);
                return 2;
            }
            tracked[tracked_count++] = pid;
            /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de
             * poursuivre. */
            if (is_root)
                root_pid = pid;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (setrlimit(RLIMIT_MEMLOCK, &rlimit) != 0)
        fprintf(stderr, "WARN unable to raise RLIMIT_MEMLOCK: %s\n", strerror(errno));

    /* [BESOIN A/B/C/P] Chargement libbpf : ouvre l’objet compilé avant validation et attachement. */
    object = bpf_object__open_file(object_path, NULL);
    {
        long open_error = libbpf_get_error(object);
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (open_error) {
            fprintf(stderr, "failed to open BPF object %s: %s (%ld)\n",
                    object_path, strerror((int)-open_error), open_error);
            object = NULL;
            goto cleanup;
        }
    }
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (disable_unavailable_tracepoints(object) != 0)
        goto cleanup;
    {
        int load_error = bpf_object__load(object);
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (load_error != 0) {
            fprintf(stderr,
                    "failed to load BPF object: %s (%d); check verifier output, privileges, BTF, and kernel support\n",
                    strerror(-load_error), load_error);
            goto cleanup;
        }
    }
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (configure_filter(object, tracked, tracked_count, root_pid) != 0)
        goto cleanup;

    /* Create the consumer before attaching probes.  This removes the startup
     * interval in which kernel programs could emit records without a reader,
     * which matters when attaching to an already-running agent. */
    events_fd = bpf_object__find_map_fd_by_name(object, "events");
    stats_fd = bpf_object__find_map_fd_by_name(object, "sensor_stats");
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (events_fd < 0 || stats_fd < 0) {
        fprintf(stderr, "required events/stats maps not found\n");
        goto cleanup;
    }
    /* [BESOIN A/B/C/P] Initialisation userspace : crée le lecteur du ring buffer avant l’attachement des
     * probes. */
    ring = ring_buffer__new(events_fd, handle_event, NULL, NULL);
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!ring) {
        fprintf(stderr, "failed to create ring-buffer reader: %s\n",
                strerror(errno));
        goto cleanup;
    }

    /* [BESOIN A/B/C/P] Boucle bornée : parcourt les éléments sans violer les contraintes du vérificateur
     * ou de mémoire. */
    bpf_object__for_each_program(program, object) {
        struct bpf_link *link;
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (bpf_program__fd(program) < 0)
            continue;
        /* [BESOIN A/B/C/P] Attachement libbpf : relie le programme chargé à son tracepoint kernel. */
        link = bpf_program__attach(program);
        {
            long attach_error = libbpf_get_error(link);
            /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de
             * poursuivre. */
            if (attach_error) {
                const char *section = bpf_program__section_name(program);
                /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de
                 * poursuivre. */
                if (!is_required_section(section)) {
                    fprintf(stderr, "SKIP optional program %s (%s): %s (%ld)\n",
                            bpf_program__name(program),
                            section ? section : "unknown",
                            strerror((int)-attach_error), attach_error);
                    continue;
                }
                fprintf(stderr, "failed to attach required program %s (%s): %s (%ld)\n",
                        bpf_program__name(program),
                        section ? section : "unknown",
                        strerror((int)-attach_error), attach_error);
                goto cleanup;
            }
        }
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (link_count == link_capacity) {
            int new_capacity = link_capacity ? link_capacity * 2 : 8;
            void *new_links = realloc(links,
                                      (size_t)new_capacity * sizeof(*links));
            /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de
             * poursuivre. */
            if (!new_links) {
                bpf_link__destroy(link);
                goto cleanup;
            }
            links = new_links;
            link_capacity = new_capacity;
        }
        links[link_count++] = link;
    }

    fprintf(stderr,
            "READY AgentSight eBPF collector attached filter=%s root_pid=%u root_start_ns=%llu tracked=%zu\n",
            tracked_count ? "root-tree" : "all", root_pid,
            (unsigned long long)read_process_start_ns(root_pid), tracked_count);
    fflush(stderr);
    result = 0;
    /* [BESOIN A/B/C/P] Boucle contrôlée : maintient la collecte jusqu’à l’arrêt ou à une erreur
     * explicite. */
    while (!stop) {
        /* [BESOIN A/B/C/P] Polling : consomme les événements kernel par lots avec un timeout borné. */
        int rc = ring_buffer__poll(ring, 250);
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (rc == -EINTR)
            break;
        /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (rc < 0) {
            fprintf(stderr, "ring-buffer poll failed: %s (%d)\n",
                    strerror(-rc), rc);
            result = 1;
            break;
        }
        emit_stats_if_changed(stats_fd, &previous_stats);
    }
    emit_stats_if_changed(stats_fd, &previous_stats);

cleanup:
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (ring)
        ring_buffer__free(ring);
    /* [BESOIN A/B/C/P] Boucle contrôlée : maintient la collecte jusqu’à l’arrêt ou à une erreur
     * explicite. */
    while (link_count > 0)
        bpf_link__destroy(links[--link_count]);
    free(links);
    /* [BESOIN A/B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (object)
        bpf_object__close(object);
    return result;
}

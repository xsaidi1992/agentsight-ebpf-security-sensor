// SPDX-License-Identifier: Dual BSD/GPL
/*
 * AgentSight assessment sensor.
 *
 * Primary event: successful process execution with bounded argv capture.
 * Additional events: fork, exit, successful open/write/delete, and connect.
 * A root-PID filter is populated by the userspace loader and propagated to
 * descendants at sched_process_fork, which limits kernel and userspace load.
 */
/*
 * =============================================================================
 * TRACEABILITE DETAILLEE AVEC LE TECHNICAL ASSESSMENT
 * [BESOIN A] Ce programme constitue la couche kernel de la chaîne d’observation.
 * [BESOIN B] Il capture exec/fork/exit/fichier/réseau et publie les records par ring buffer.
 * [BESOIN C] Il filtre un PID racine, propage le suivi aux descendants et conserve start_ns.
 * [BESOIN D] Les événements fichier, réseau et commande alimentent les règles sensibles.
 * [BESOIN P] Les maps sont bornées, le filtrage est fait dans le kernel et chaque perte est comptée.
 * =============================================================================
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

/* [BESOIN B/P] Structure `pending_exec` : conserve les arguments d’un exec entre l’entrée du syscall et
 * la confirmation de réussite. */
struct pending_exec {
    char filename[AGENTSIGHT_PATH_LEN];
    char argv[AGENTSIGHT_MAX_ARGS][AGENTSIGHT_ARG_LEN];
    __u32 argc;
    __u32 argv_truncated;
    __u32 syscall_kind;
    __u32 filename_truncated;
};

/* [BESOIN B/P] Structure `pending_file` : conserve le chemin et les flags d’un openat/openat2 jusqu’à la
 * sortie du syscall. */
struct pending_file {
    char path[AGENTSIGHT_PATH_LEN];
    __s32 dirfd;
    __u32 open_flags;
    __u32 path_truncated;
};

/* [BESOIN B/P] Structure `open_file_key` : identifie de manière bornée un descripteur par le couple
 * processus/fd. */
struct open_file_key {
    __u32 tgid;
    __s32 fd;
};

/* [BESOIN B/D/P] Structure `open_file_value` : mémorise le chemin associé à un fd afin d’expliquer les
 * écritures ultérieures. */
struct open_file_value {
    char path[AGENTSIGHT_PATH_LEN];
    __s32 dirfd;
    __u32 open_flags;
    __u32 path_truncated;
};

/* [BESOIN B/P] Structure `pending_write` : mémorise le fd d’un write jusqu’à sa valeur de retour. */
struct pending_write {
    __s32 fd;
};

/* [BESOIN B/P] Structure `pending_close` : mémorise le fd fermé afin de nettoyer correctement la table
 * des fichiers ouverts. */
struct pending_close {
    __s32 fd;
};

/* [BESOIN B/D/P] Structure `pending_delete` : mémorise le chemin d’un unlink/unlinkat jusqu’à la
 * confirmation de réussite. */
struct pending_delete {
    char path[AGENTSIGHT_PATH_LEN];
    __s32 dirfd;
    __u32 path_truncated;
};

/* [BESOIN B/D/P] Structure `pending_network` : mémorise la destination de connect jusqu’à la sortie du
 * syscall. */
struct pending_network {
    __u16 family;
    __u16 port;
    __u8 address[16];
};

/* [BESOIN B] Structure `user_sockaddr_in` : représente sockaddr_in en mémoire utilisateur sans dépendre
 * des en-têtes libc. */
struct user_sockaddr_in {
    __u16 family;
    __u16 port;
    __u32 address;
    __u8 zero[8];
};

/* [BESOIN B] Structure `user_in6_addr` : représente l’adresse IPv6 copiée depuis la mémoire utilisateur. */
struct user_in6_addr {
    __u8 bytes[16];
};

/* [BESOIN B] Structure `user_sockaddr_in6` : représente sockaddr_in6 en mémoire utilisateur pour la
 * capture IPv6. */
struct user_sockaddr_in6 {
    __u16 family;
    __u16 port;
    __u32 flowinfo;
    struct user_in6_addr address;
    __u32 scope_id;
};

/* [BESOIN B/P] Map eBPF `exec_scratch` : scratch per-CPU qui évite de dépasser la pile eBPF lors de la
 * copie des arguments. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_exec);
} exec_scratch SEC(".maps");

/* [BESOIN B/P] Map eBPF `pending_execs` : états exec en attente, bornés par une LRU map. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct pending_exec);
} pending_execs SEC(".maps");

/* [BESOIN B/P] Map eBPF `pending_files` : états openat/openat2 entre entrée et sortie du syscall. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_file);
} pending_files SEC(".maps");

/* [BESOIN B/D/P] Map eBPF `open_files` : association processus/fd vers chemin pour expliquer write et
 * close. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct open_file_key);
    __type(value, struct open_file_value);
} open_files SEC(".maps");

/* [BESOIN B/P] Map eBPF `pending_writes` : états write temporaires, séparés pour gérer les syscalls
 * concurrents. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_write);
} pending_writes SEC(".maps");

/* [BESOIN B/P] Map eBPF `pending_closes` : états close temporaires nécessaires au nettoyage des fd
 * suivis. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_close);
} pending_closes SEC(".maps");

/* [BESOIN B/D/P] Map eBPF `pending_deletes` : états unlink/unlinkat temporaires. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct pending_delete);
} pending_deletes SEC(".maps");

/* [BESOIN B/D/P] Map eBPF `pending_networks` : états connect temporaires pour IPv4 et IPv6. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_network);
} pending_networks SEC(".maps");

/* [BESOIN C/P] Map eBPF `tracked_pids` : ensemble kernel des PID appartenant au processus racine ou à
 * ses descendants. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __u64);
} tracked_pids SEC(".maps");

/* [BESOIN B/C/P] Map eBPF `sensor_config` : configuration du filtre racine et de la base temporelle
 * écrite par userspace. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agentsight_sensor_config);
} sensor_config SEC(".maps");

/* [BESOIN A/B/P] Map eBPF `events` : ring buffer de 4 MiB qui transporte les événements kernel vers
 * userspace. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

/* [BESOIN B/P] Map eBPF `sequence_map` : compteur global monotone utilisé pour détecter les trous de
 * séquence. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sequence_map SEC(".maps");

/* [BESOIN P] Map eBPF `sensor_stats` : compteurs kernel des pertes, échecs d’état et événements émis. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agentsight_sensor_stats);
} sensor_stats SEC(".maps");

/* [BESOIN P] Fonction helper `get_stats` : retrouve la structure de métriques kernel. */
static __always_inline struct agentsight_sensor_stats *get_stats(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&sensor_stats, &key);
}

/* [BESOIN P] Fonction helper `increment_stat` : incrémente atomiquement un compteur de perte ou
 * d’erreur. */
static __always_inline void increment_stat(__u64 *counter)
{
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

/* [BESOIN B/P] Fonction helper `next_sequence` : attribue un numéro de séquence à chaque événement émis. */
static __always_inline __u64 next_sequence(void)
{
    __u32 key = 0;
    /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
    __u64 *value = bpf_map_lookup_elem(&sequence_map, &key);

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!value)
        return 0;
    return __sync_fetch_and_add(value, 1) + 1;
}

/* [BESOIN B/C/P] Fonction helper `get_config` : lit la configuration du filtre chargée par userspace. */
static __always_inline struct agentsight_sensor_config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&sensor_config, &key);
}

/* [BESOIN C] Fonction helper `task_start_ns_with_tick` : normalise start_boottime sur la granularité de
 * /proc pour une identité PID stable. */
static __always_inline __u64 task_start_ns_with_tick(
    struct task_struct *task, __u64 clock_tick_ns)
{
    __u64 start_ns;

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!task)
        return 0;
    /* /proc/<pid>/stat field 22 is derived from start_boottime and rounded to
     * userspace clock ticks. Quantizing the kernel value with the loader's
     * clock period makes procfs seeds and eBPF events one stable identity. */
    /* [BESOIN A/B/C/P] Lecture CO-RE : récupère un champ kernel en restant compatible avec les
     * variations de structure. */
    start_ns = BPF_CORE_READ(task, start_boottime);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (clock_tick_ns)
        start_ns = (start_ns / clock_tick_ns) * clock_tick_ns;
    return start_ns;
}

/* [BESOIN C] Fonction helper `task_start_ns` : calcule le temps de démarrage normalisé d’une tâche
 * kernel. */
static __always_inline __u64 task_start_ns(struct task_struct *task)
{
    struct agentsight_sensor_config *config = get_config();
    return task_start_ns_with_tick(task, config ? config->clock_tick_ns : 0);
}

/* [BESOIN C/P] Fonction helper `task_belongs_to_root` : remonte une ascendance bornée pour rattacher une
 * tâche au PID racine. */
static __always_inline int task_belongs_to_root(
    struct task_struct *task, const struct agentsight_sensor_config *config)
{
    int i;

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!task || !config || !config->root_pid)
        return 0;
#pragma unroll
    /* [BESOIN B/C/P] Boucle bornée : parcourt les éléments sans violer les contraintes du vérificateur
     * ou de mémoire. */
    for (i = 0; i < AGENTSIGHT_MAX_ANCESTRY_DEPTH; i++) {
        __u32 candidate_pid;
        __u64 candidate_start;
        struct task_struct *parent;

        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (!task)
            return 0;
        /* [BESOIN A/B/C/P] Lecture CO-RE : récupère un champ kernel en restant compatible avec les
         * variations de structure. */
        candidate_pid = BPF_CORE_READ(task, tgid);
        candidate_start = task_start_ns_with_tick(task, config->clock_tick_ns);
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (candidate_pid == config->root_pid) {
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (!config->root_start_ns || candidate_start == config->root_start_ns)
                return 1;
            return 0;
        }
        /* [BESOIN A/B/C/P] Lecture CO-RE : récupère un champ kernel en restant compatible avec les
         * variations de structure. */
        parent = BPF_CORE_READ(task, real_parent);
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (!parent || parent == task)
            return 0;
        task = parent;
    }
    return 0;
}

/* [BESOIN B/C/P] Fonction helper `should_trace` : filtre au plus tôt les événements ne provenant pas de
 * la session surveillée. */
static __always_inline int should_trace(__u32 tgid)
{
    struct agentsight_sensor_config *config = get_config();
    struct task_struct *task;
    __u64 *tracked;

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!config || !config->filter_enabled)
        return 1;
    /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
    tracked = bpf_map_lookup_elem(&tracked_pids, &tgid);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (tracked)
        return 1;

    /* Recover an existing/racing descendant that was not present when the
     * userspace seed snapshot was taken. The expensive walk only happens on a
     * cache miss; successful recovery is cached in tracked_pids. */
    task = (struct task_struct *)bpf_get_current_task();
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (task_belongs_to_root(task, config)) {
        __u64 start_ns = task_start_ns(task);
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (bpf_map_update_elem(&tracked_pids, &tgid, &start_ns, BPF_ANY) < 0) {
            struct agentsight_sensor_stats *stats = get_stats();
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (stats)
                /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie
                 * ou perte. */
                increment_stat(&stats->tracking_state_failures);
        }
        return 1;
    }
    return 0;
}

/* [BESOIN C] Fonction helper `tracked_start` : retrouve le temps de démarrage associé à un PID déjà
 * suivi. */
static __always_inline __u64 tracked_start(__u32 tgid)
{
    /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
    __u64 *value = bpf_map_lookup_elem(&tracked_pids, &tgid);
    return value ? *value : 0;
}

/* [BESOIN B/C] Fonction helper `current_identity` : collecte PID, PPID et temps de démarrage du
 * processus courant et de son parent. */
static __always_inline void current_identity(__u32 *pid, __u32 *ppid,
                                              __u64 *start_ns, __u64 *parent_start_ns)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    /* [BESOIN A/B/C/P] Lecture CO-RE : récupère un champ kernel en restant compatible avec les
     * variations de structure. */
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    *pid = bpf_get_current_pid_tgid() >> 32;
    *ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
    *start_ns = task_start_ns(task);
    *parent_start_ns = task_start_ns(parent);
}

/* [BESOIN A/B/P] Fonction helper `reserve_event` : réserve une enveloppe dans le ring buffer et
 * renseigne l’en-tête commun. */
static __always_inline struct agentsight_kernel_event *reserve_event(
    __u8 event_type, __u32 pid, __u32 ppid, __u64 start_ns, __u64 parent_start_ns)
{
    struct agentsight_sensor_stats *stats;
    struct agentsight_kernel_event *event;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u64 sequence = next_sequence();

    /* [BESOIN A/B/C/P] Réservation ring buffer : alloue un record ; un échec est comptabilisé comme
     * perte kernel. */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!event) {
        stats = get_stats();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (stats)
            /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
             * perte. */
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

/* [BESOIN A/B/P] Fonction helper `submit_event` : soumet l’événement au ring buffer et incrémente le
 * compteur d’émission. */
static __always_inline void submit_event(struct agentsight_kernel_event *event)
{
    struct agentsight_sensor_stats *stats = get_stats();

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (stats)
        /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
         * perte. */
        increment_stat(&stats->emitted_events);
    /* [BESOIN A/B/C/P] Soumission ring buffer : rend le record visible au collecteur userspace. */
    bpf_ringbuf_submit(event, 0);
}

/* [BESOIN B/P] Fonction helper `capture_exec_entry` : capture de manière bornée filename et argv à
 * l’entrée d’execve/execveat. */
static __always_inline int capture_exec_entry(const char *filename,
                                               const char *const *argv,
                                               __u32 syscall_kind)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 zero = 0;
    struct pending_exec *value;
    struct agentsight_sensor_stats *stats;
    int i;

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!should_trace(tgid))
        return 0;
    /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
    value = bpf_map_lookup_elem(&exec_scratch, &zero);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!value)
        return 0;

    __builtin_memset(value, 0, sizeof(*value));
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (filename) {
        /* [BESOIN A/B/C/P] Lecture mémoire utilisateur : copie une donnée bornée et vérifiée depuis les
         * arguments du syscall. */
        long filename_size = bpf_probe_read_user_str(
            value->filename, sizeof(value->filename), filename);
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (filename_size >= (__s64)sizeof(value->filename))
            value->filename_truncated = 1;
    }
    value->syscall_kind = syscall_kind;

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (argv) {
#pragma unroll
        /* [BESOIN B/C/P] Boucle bornée : parcourt les éléments sans violer les contraintes du
         * vérificateur ou de mémoire. */
        for (i = 0; i < AGENTSIGHT_MAX_ARGS; i++) {
            const char *argp = 0;

            long read_size;

            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0 || !argp)
                break;
            /* [BESOIN A/B/C/P] Lecture mémoire utilisateur : copie une donnée bornée et vérifiée depuis
             * les arguments du syscall. */
            read_size = bpf_probe_read_user_str(
                value->argv[i], sizeof(value->argv[i]), argp);
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (read_size > 0) {
                value->argc++;
                /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de
                 * poursuivre. */
                if (read_size >= (__s64)sizeof(value->argv[i]))
                    value->argv_truncated = 1;
            }
        }
        {
            const char *extra = 0;
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (bpf_probe_read_user(&extra, sizeof(extra), &argv[AGENTSIGHT_MAX_ARGS]) == 0 && extra)
                value->argv_truncated = 1;
        }
    }

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (bpf_map_update_elem(&pending_execs, &tgid, value, BPF_ANY) < 0) {
        stats = get_stats();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (stats)
            /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
             * perte. */
            increment_stat(&stats->pending_update_failures);
    }
    return 0;
}

/* [BESOIN B] Fonction `capture_execve` : point d’attachement sys_enter_execve demandé pour observer le
 * lancement de processus. */
SEC("tracepoint/syscalls/sys_enter_execve")
int capture_execve(struct trace_event_raw_sys_enter *ctx)
{
    return capture_exec_entry((const char *)ctx->args[0],
                              (const char *const *)ctx->args[1],
                              AGENTSIGHT_SYSCALL_EXECVE);
}

/* [BESOIN B] Fonction `capture_execveat` : variante execveat activée lorsque le tracepoint existe. */
SEC("tracepoint/syscalls/sys_enter_execveat")
int capture_execveat(struct trace_event_raw_sys_enter *ctx)
{
    return capture_exec_entry((const char *)ctx->args[1],
                              (const char *const *)ctx->args[2],
                              AGENTSIGHT_SYSCALL_EXECVEAT);
}

/* [BESOIN B/P] Fonction helper `cleanup_failed_exec` : supprime l’état d’un exec échoué afin de ne
 * publier que les exécutions réussies. */
static __always_inline int cleanup_failed_exec(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct agentsight_sensor_stats *stats;

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if ((__s64)ctx->ret >= 0)
        return 0;
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (bpf_map_lookup_elem(&pending_execs, &tgid)) {
        /* [BESOIN A/B/C/P] Nettoyage de map eBPF : supprime l’état consommé pour limiter la mémoire et
         * les faux rattachements. */
        bpf_map_delete_elem(&pending_execs, &tgid);
        stats = get_stats();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (stats)
            /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
             * perte. */
            increment_stat(&stats->failed_execs);
    }
    return 0;
}

/* [BESOIN B/P] Fonction `cleanup_failed_execve` : traite la sortie négative d’execve. */
SEC("tracepoint/syscalls/sys_exit_execve")
int cleanup_failed_execve(struct trace_event_raw_sys_exit *ctx)
{
    return cleanup_failed_exec(ctx);
}

/* [BESOIN B/P] Fonction `cleanup_failed_execveat` : traite la sortie négative d’execveat. */
SEC("tracepoint/syscalls/sys_exit_execveat")
int cleanup_failed_execveat(struct trace_event_raw_sys_exit *ctx)
{
    return cleanup_failed_exec(ctx);
}

/* [BESOIN B/C] Fonction `emit_successful_exec` : confirme l’exécution via sched_process_exec, complète
 * l’identité et émet l’événement. */
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
    /* [BESOIN A/B/C/P] Enrichissement d’identité : ajoute PID, PPID et temps de démarrage avant
     * publication. */
    current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!should_trace(pid))
        return 0;
    /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
    saved = bpf_map_lookup_elem(&pending_execs, &pid);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!saved) {
        stats = get_stats();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (stats)
            /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
             * perte. */
            increment_stat(&stats->missing_pending);
        return 0;
    }

    {
        struct agentsight_sensor_config *config = get_config();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (config && config->filter_enabled &&
            /* [BESOIN A/B/C/P] Mise à jour de map eBPF : persiste un état borné nécessaire à la
             * corrélation entrée/sortie. */
            bpf_map_update_elem(&tracked_pids, &pid, &start_ns, BPF_ANY) < 0) {
            stats = get_stats();
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (stats)
                /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie
                 * ou perte. */
                increment_stat(&stats->tracking_state_failures);
        }
    }
    event = reserve_event(AGENTSIGHT_EVENT_EXEC, pid, ppid, start_ns, parent_start_ns);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!event) {
        /* [BESOIN A/B/C/P] Nettoyage de map eBPF : supprime l’état consommé pour limiter la mémoire et
         * les faux rattachements. */
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
    /* [BESOIN A/B/C/P] Publication : envoie l’événement normalisé vers le ring buffer. */
    submit_event(event);
    /* [BESOIN A/B/C/P] Nettoyage de map eBPF : supprime l’état consommé pour limiter la mémoire et les
     * faux rattachements. */
    bpf_map_delete_elem(&pending_execs, &pid);
    return 0;
}

/* [BESOIN C/P] Fonction `emit_process_fork` : propage le suivi du parent vers l’enfant et publie la
 * relation de filiation. */
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

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!parent || !child)
        return 0;
    /* [BESOIN A/B/C/P] Lecture CO-RE : récupère un champ kernel en restant compatible avec les
     * variations de structure. */
    parent_pid = BPF_CORE_READ(parent, tgid);
    /* [BESOIN A/B/C/P] Lecture CO-RE : récupère un champ kernel en restant compatible avec les
     * variations de structure. */
    child_pid = BPF_CORE_READ(child, tgid);
    /* CLONE_THREAD creates a task, not a new process/session node. */
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!parent_pid || !child_pid || child_pid == parent_pid)
        return 0;
    tracked_parent_start = tracked_start(parent_pid);
    parent_start_ns = task_start_ns(parent);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (config && config->filter_enabled && !tracked_parent_start) {
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (!task_belongs_to_root(parent, config))
            return 0;
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (bpf_map_update_elem(&tracked_pids, &parent_pid,
                                &parent_start_ns, BPF_ANY) < 0) {
            struct agentsight_sensor_stats *stats = get_stats();
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (stats)
                /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie
                 * ou perte. */
                increment_stat(&stats->tracking_state_failures);
        }
    }

    child_start_ns = task_start_ns(child);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (config && config->filter_enabled &&
        /* [BESOIN A/B/C/P] Mise à jour de map eBPF : persiste un état borné nécessaire à la corrélation
         * entrée/sortie. */
        bpf_map_update_elem(&tracked_pids, &child_pid, &child_start_ns, BPF_ANY) < 0) {
        struct agentsight_sensor_stats *stats = get_stats();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (stats)
            /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
             * perte. */
            increment_stat(&stats->tracking_state_failures);
    }

    event = reserve_event(AGENTSIGHT_EVENT_FORK, child_pid, parent_pid,
                          child_start_ns, parent_start_ns);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!event)
        return 0;
    /* [BESOIN A/B/C/P] Lecture CO-RE : récupère un champ kernel en restant compatible avec les
     * variations de structure. */
    BPF_CORE_READ_STR_INTO(&event->header.comm, child, comm);
    event->payload.fork.child_pid = child_pid;
    event->payload.fork.parent_pid = parent_pid;
    event->payload.fork.child_start_ns = child_start_ns;
    event->payload.fork.parent_start_ns = parent_start_ns;
    /* [BESOIN A/B/C/P] Lecture CO-RE : récupère un champ kernel en restant compatible avec les
     * variations de structure. */
    BPF_CORE_READ_STR_INTO(&event->payload.fork.child_comm, child, comm);
    /* [BESOIN A/B/C/P] Publication : envoie l’événement normalisé vers le ring buffer. */
    submit_event(event);
    return 0;
}

/* [BESOIN C] Fonction `emit_process_exit` : publie la fin du processus et retire son PID de la table de
 * suivi. */
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
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if ((__u32)pid_tgid != (__u32)(pid_tgid >> 32))
        return 0;
    /* [BESOIN A/B/C/P] Enrichissement d’identité : ajoute PID, PPID et temps de démarrage avant
     * publication. */
    current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!should_trace(pid))
        return 0;
    task = (struct task_struct *)bpf_get_current_task();
    /* [BESOIN A/B/C/P] Lecture CO-RE : récupère un champ kernel en restant compatible avec les
     * variations de structure. */
    raw_exit = BPF_CORE_READ(task, exit_code);

    event = reserve_event(AGENTSIGHT_EVENT_EXIT, pid, ppid, start_ns, parent_start_ns);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (event) {
        event->payload.exit.exit_code = (raw_exit >> 8) & 0xff;
        event->payload.exit.signal = raw_exit & 0x7f;
        event->payload.exit.duration_ns =
            start_ns && event->header.timestamp_ns > start_ns
                ? event->header.timestamp_ns - start_ns
                : 0;
        /* [BESOIN A/B/C/P] Publication : envoie l’événement normalisé vers le ring buffer. */
        submit_event(event);
    }
    {
        struct agentsight_sensor_config *config = get_config();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (config && config->filter_enabled)
            /* [BESOIN A/B/C/P] Nettoyage de map eBPF : supprime l’état consommé pour limiter la mémoire
             * et les faux rattachements. */
            bpf_map_delete_elem(&tracked_pids, &pid);
    }
    return 0;
}

/* [BESOIN B/P] Fonction helper `capture_open_entry` : capture les paramètres de openat/openat2 avant
 * exécution. */
static __always_inline int capture_open_entry(const char *path, __s32 dirfd,
                                               __u32 open_flags)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    struct pending_file value = {};
    struct agentsight_sensor_stats *stats;

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!should_trace(tgid))
        return 0;
    value.dirfd = dirfd;
    value.open_flags = open_flags;
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (path) {
        /* [BESOIN A/B/C/P] Lecture mémoire utilisateur : copie une donnée bornée et vérifiée depuis les
         * arguments du syscall. */
        long path_size = bpf_probe_read_user_str(value.path, sizeof(value.path), path);
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (path_size >= (__s64)sizeof(value.path))
            value.path_truncated = 1;
    }
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (bpf_map_update_elem(&pending_files, &pid_tgid, &value, BPF_ANY) < 0) {
        stats = get_stats();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (stats)
            /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
             * perte. */
            increment_stat(&stats->file_state_failures);
    }
    return 0;
}

/* [BESOIN B] Fonction `capture_openat` : attache la capture à sys_enter_openat. */
SEC("tracepoint/syscalls/sys_enter_openat")
int capture_openat(struct trace_event_raw_sys_enter *ctx)
{
    return capture_open_entry((const char *)ctx->args[1],
                              (__s32)ctx->args[0],
                              (__u32)ctx->args[2]);
}

/* [BESOIN B] Fonction `capture_openat2` : attache la capture optionnelle à sys_enter_openat2. */
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
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (how_ptr && how_size >= sizeof(flags))
        /* [BESOIN A/B/C/P] Lecture mémoire utilisateur : copie une donnée bornée et vérifiée depuis les
         * arguments du syscall. */
        bpf_probe_read_user(&flags, sizeof(flags), how_ptr);
    return capture_open_entry((const char *)ctx->args[1],
                              (__s32)ctx->args[0],
                              (__u32)flags);
}

/* [BESOIN B/D] Fonction helper `emit_open_exit` : publie uniquement les ouvertures réussies et mémorise
 * le chemin associé au fd. */
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

    /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
    saved = bpf_map_lookup_elem(&pending_files, &pid_tgid);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!saved) {
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (should_trace((__u32)(pid_tgid >> 32))) {
            struct agentsight_sensor_stats *stats = get_stats();
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (stats)
                /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie
                 * ou perte. */
                increment_stat(&stats->missing_file_pending);
        }
        return 0;
    }
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (result >= 0) {
        /* [BESOIN A/B/C/P] Enrichissement d’identité : ajoute PID, PPID et temps de démarrage avant
         * publication. */
        current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
        event = reserve_event(AGENTSIGHT_EVENT_FILE_OPEN, pid, ppid,
                              start_ns, parent_start_ns);
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (event) {
            __builtin_memcpy(event->payload.file.path, saved->path,
                             sizeof(event->payload.file.path));
            event->payload.file.fd = (__s32)result;
            event->payload.file.dirfd = saved->dirfd;
            event->payload.file.open_flags = saved->open_flags;
            event->payload.file.operation = AGENTSIGHT_FILE_OPERATION_OPEN;
            event->payload.file.result = result;
            event->payload.file.path_truncated = saved->path_truncated;
            /* [BESOIN A/B/C/P] Publication : envoie l’événement normalisé vers le ring buffer. */
            submit_event(event);
        }
        key.tgid = pid;
        key.fd = (__s32)result;
        __builtin_memcpy(file_value.path, saved->path, sizeof(file_value.path));
        file_value.dirfd = saved->dirfd;
        file_value.open_flags = saved->open_flags;
        file_value.path_truncated = saved->path_truncated;
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (bpf_map_update_elem(&open_files, &key, &file_value, BPF_ANY) < 0) {
            struct agentsight_sensor_stats *stats = get_stats();
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (stats)
                /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie
                 * ou perte. */
                increment_stat(&stats->file_state_failures);
        }
    }
    /* [BESOIN A/B/C/P] Nettoyage de map eBPF : supprime l’état consommé pour limiter la mémoire et les
     * faux rattachements. */
    bpf_map_delete_elem(&pending_files, &pid_tgid);
    return 0;
}

/* [BESOIN B/D] Fonction `emit_openat` : traite la sortie de openat. */
SEC("tracepoint/syscalls/sys_exit_openat")
int emit_openat(struct trace_event_raw_sys_exit *ctx)
{
    return emit_open_exit(ctx);
}

/* [BESOIN B/D] Fonction `emit_openat2` : traite la sortie de openat2. */
SEC("tracepoint/syscalls/sys_exit_openat2")
int emit_openat2(struct trace_event_raw_sys_exit *ctx)
{
    return emit_open_exit(ctx);
}

/* [BESOIN B] Fonction `capture_write` : mémorise le fd ciblé à l’entrée de write. */
SEC("tracepoint/syscalls/sys_enter_write")
int capture_write(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    struct pending_write value = {};

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!should_trace(tgid))
        return 0;
    value.fd = (__s32)ctx->args[0];
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (bpf_map_update_elem(&pending_writes, &pid_tgid, &value, BPF_ANY) < 0) {
        struct agentsight_sensor_stats *stats = get_stats();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (stats)
            /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
             * perte. */
            increment_stat(&stats->file_state_failures);
    }
    return 0;
}

/* [BESOIN B/D] Fonction `emit_write` : résout fd vers chemin et publie une écriture réussie. */
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

    /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
    pending_write_value = bpf_map_lookup_elem(&pending_writes, &pid_tgid);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!pending_write_value) {
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (should_trace((__u32)(pid_tgid >> 32))) {
            struct agentsight_sensor_stats *stats = get_stats();
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (stats)
                /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie
                 * ou perte. */
                increment_stat(&stats->missing_file_pending);
        }
        return 0;
    }
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (result > 0) {
        pid = pid_tgid >> 32;
        key.tgid = pid;
        key.fd = pending_write_value->fd;
        /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
        file_value = bpf_map_lookup_elem(&open_files, &key);
        /* [BESOIN A/B/C/P] Enrichissement d’identité : ajoute PID, PPID et temps de démarrage avant
         * publication. */
        current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
        event = reserve_event(AGENTSIGHT_EVENT_FILE_WRITE, pid, ppid,
                              start_ns, parent_start_ns);
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (event) {
            event->payload.file.fd = pending_write_value->fd;
            event->payload.file.dirfd = -100;
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
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
            /* [BESOIN A/B/C/P] Publication : envoie l’événement normalisé vers le ring buffer. */
            submit_event(event);
        }
    }
    /* [BESOIN A/B/C/P] Nettoyage de map eBPF : supprime l’état consommé pour limiter la mémoire et les
     * faux rattachements. */
    bpf_map_delete_elem(&pending_writes, &pid_tgid);
    return 0;
}

/* [BESOIN B/P] Fonction `capture_close` : mémorise le fd à nettoyer lors d’un close réussi. */
SEC("tracepoint/syscalls/sys_enter_close")
int capture_close(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    struct pending_close value = {};

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!should_trace(tgid))
        return 0;
    value.fd = (__s32)ctx->args[0];
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (bpf_map_update_elem(&pending_closes, &pid_tgid, &value, BPF_ANY) < 0) {
        struct agentsight_sensor_stats *stats = get_stats();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (stats)
            /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
             * perte. */
            increment_stat(&stats->file_state_failures);
    }
    return 0;
}

/* [BESOIN B/P] Fonction `cleanup_closed_fd` : retire l’association fd/chemin uniquement après succès de
 * close. */
SEC("tracepoint/syscalls/sys_exit_close")
int cleanup_closed_fd(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
    struct pending_close *saved = bpf_map_lookup_elem(&pending_closes, &pid_tgid);

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!saved) {
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (should_trace((__u32)(pid_tgid >> 32))) {
            struct agentsight_sensor_stats *stats = get_stats();
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (stats)
                /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie
                 * ou perte. */
                increment_stat(&stats->missing_file_pending);
        }
        return 0;
    }
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if ((__s64)ctx->ret == 0) {
        struct open_file_key key = {};
        key.tgid = pid_tgid >> 32;
        key.fd = saved->fd;
        /* [BESOIN A/B/C/P] Nettoyage de map eBPF : supprime l’état consommé pour limiter la mémoire et
         * les faux rattachements. */
        bpf_map_delete_elem(&open_files, &key);
    }
    /* [BESOIN A/B/C/P] Nettoyage de map eBPF : supprime l’état consommé pour limiter la mémoire et les
     * faux rattachements. */
    bpf_map_delete_elem(&pending_closes, &pid_tgid);
    return 0;
}

/* [BESOIN B/D/P] Fonction helper `capture_delete_entry` : capture le chemin de suppression à l’entrée du
 * syscall. */
static __always_inline int capture_delete_entry(const char *path, __s32 dirfd)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    struct pending_delete value = {};

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!should_trace(tgid))
        return 0;
    value.dirfd = dirfd;
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (path) {
        /* [BESOIN A/B/C/P] Lecture mémoire utilisateur : copie une donnée bornée et vérifiée depuis les
         * arguments du syscall. */
        long path_size = bpf_probe_read_user_str(value.path, sizeof(value.path), path);
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (path_size >= (__s64)sizeof(value.path))
            value.path_truncated = 1;
    }
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (bpf_map_update_elem(&pending_deletes, &pid_tgid, &value, BPF_ANY) < 0) {
        struct agentsight_sensor_stats *stats = get_stats();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (stats)
            /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
             * perte. */
            increment_stat(&stats->file_state_failures);
    }
    return 0;
}

/* [BESOIN B/D] Fonction `capture_unlink` : attache la capture à sys_enter_unlink. */
SEC("tracepoint/syscalls/sys_enter_unlink")
int capture_unlink(struct trace_event_raw_sys_enter *ctx)
{
    return capture_delete_entry((const char *)ctx->args[0], -100);
}

/* [BESOIN B/D] Fonction `capture_unlinkat` : attache la capture à sys_enter_unlinkat. */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int capture_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    return capture_delete_entry((const char *)ctx->args[1], (__s32)ctx->args[0]);
}

/* [BESOIN B/D] Fonction helper `emit_delete_exit` : publie uniquement une suppression confirmée par une
 * valeur de retour non négative. */
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

    /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
    saved = bpf_map_lookup_elem(&pending_deletes, &pid_tgid);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!saved) {
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (should_trace((__u32)(pid_tgid >> 32))) {
            struct agentsight_sensor_stats *stats = get_stats();
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (stats)
                /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie
                 * ou perte. */
                increment_stat(&stats->missing_file_pending);
        }
        return 0;
    }
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (result == 0) {
        /* [BESOIN A/B/C/P] Enrichissement d’identité : ajoute PID, PPID et temps de démarrage avant
         * publication. */
        current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
        event = reserve_event(AGENTSIGHT_EVENT_FILE_DELETE, pid, ppid,
                              start_ns, parent_start_ns);
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (event) {
            __builtin_memcpy(event->payload.file.path, saved->path,
                             sizeof(event->payload.file.path));
            event->payload.file.dirfd = saved->dirfd;
            event->payload.file.fd = -1;
            event->payload.file.operation = AGENTSIGHT_FILE_OPERATION_DELETE;
            event->payload.file.result = result;
            event->payload.file.path_truncated = saved->path_truncated;
            /* [BESOIN A/B/C/P] Publication : envoie l’événement normalisé vers le ring buffer. */
            submit_event(event);
        }
    }
    /* [BESOIN A/B/C/P] Nettoyage de map eBPF : supprime l’état consommé pour limiter la mémoire et les
     * faux rattachements. */
    bpf_map_delete_elem(&pending_deletes, &pid_tgid);
    return 0;
}

/* [BESOIN B/D] Fonction `emit_unlink` : traite la sortie de unlink. */
SEC("tracepoint/syscalls/sys_exit_unlink")
int emit_unlink(struct trace_event_raw_sys_exit *ctx)
{
    return emit_delete_exit(ctx);
}

/* [BESOIN B/D] Fonction `emit_unlinkat` : traite la sortie de unlinkat. */
SEC("tracepoint/syscalls/sys_exit_unlinkat")
int emit_unlinkat(struct trace_event_raw_sys_exit *ctx)
{
    return emit_delete_exit(ctx);
}

/* [BESOIN B/D] Fonction `capture_connect` : copie de manière bornée la destination IPv4/IPv6 de connect. */
SEC("tracepoint/syscalls/sys_enter_connect")
int capture_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    const void *address = (const void *)ctx->args[1];
    struct pending_network value = {};
    __u16 family = 0;
    struct agentsight_sensor_stats *stats;

    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!should_trace(tgid) || !address)
        return 0;
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (bpf_probe_read_user(&family, sizeof(family), address) < 0)
        return 0;
    value.family = family;
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (family == AF_INET) {
        struct user_sockaddr_in addr4 = {};
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (bpf_probe_read_user(&addr4, sizeof(addr4), address) < 0)
            return 0;
        value.port = bpf_ntohs(addr4.port);
        __builtin_memcpy(value.address, &addr4.address, sizeof(addr4.address));
    } else if (family == AF_INET6) {
        struct user_sockaddr_in6 addr6 = {};
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (bpf_probe_read_user(&addr6, sizeof(addr6), address) < 0)
            return 0;
        value.port = bpf_ntohs(addr6.port);
        __builtin_memcpy(value.address, addr6.address.bytes, sizeof(value.address));
    } else {
        return 0;
    }
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (bpf_map_update_elem(&pending_networks, &pid_tgid, &value, BPF_ANY) < 0) {
        stats = get_stats();
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (stats)
            /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie ou
             * perte. */
            increment_stat(&stats->network_state_failures);
    }
    return 0;
}

/* [BESOIN B/D] Fonction `emit_connect` : publie une connexion réussie ou en cours selon la sémantique
 * non bloquante Linux. */
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

    /* [BESOIN A/B/C/P] Lecture de map eBPF : récupère un état partagé sans inventer de valeur. */
    saved = bpf_map_lookup_elem(&pending_networks, &pid_tgid);
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (!saved) {
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (should_trace((__u32)(pid_tgid >> 32))) {
            struct agentsight_sensor_stats *stats = get_stats();
            /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
            if (stats)
                /* [BESOIN A/B/C/P] Observabilité : incrémente le compteur correspondant à cette anomalie
                 * ou perte. */
                increment_stat(&stats->missing_network_pending);
        }
        return 0;
    }
    /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
    if (result == 0 || result == -EINPROGRESS) {
        /* [BESOIN A/B/C/P] Enrichissement d’identité : ajoute PID, PPID et temps de démarrage avant
         * publication. */
        current_identity(&pid, &ppid, &start_ns, &parent_start_ns);
        event = reserve_event(AGENTSIGHT_EVENT_NETWORK_CONNECT, pid, ppid,
                              start_ns, parent_start_ns);
        /* [BESOIN B/C/P] Condition de garde : contrôle un état kernel/userspace avant de poursuivre. */
        if (event) {
            event->payload.network.family = saved->family;
            event->payload.network.port = saved->port;
            __builtin_memcpy(event->payload.network.address, saved->address,
                             sizeof(event->payload.network.address));
            event->payload.network.result = (__s32)result;
            /* [BESOIN A/B/C/P] Publication : envoie l’événement normalisé vers le ring buffer. */
            submit_event(event);
        }
    }
    /* [BESOIN A/B/C/P] Nettoyage de map eBPF : supprime l’état consommé pour limiter la mémoire et les
     * faux rattachements. */
    bpf_map_delete_elem(&pending_networks, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

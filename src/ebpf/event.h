#ifndef AGENTSIGHT_EVENT_H
#define AGENTSIGHT_EVENT_H

/*
 * =============================================================================
 * TRACEABILITE AVEC LE TECHNICAL ASSESSMENT
 * =============================================================================
 * [BESOIN A] Ce fichier est le contrat de données unique entre le programme
 *             eBPF exécuté dans le kernel et le collecteur libbpf userspace.
 * [BESOIN B] Il décrit tous les champs exigés pour identifier le processus,
 *             l’action observée et son contexte (PID, PPID, UID, commande...).
 * [BESOIN C] Les temps de démarrage du processus et du parent permettent de
 *             construire un arbre robuste même lorsque Linux réutilise un PID.
 * [BESOIN P] Les numéros de séquence et compteurs de pertes rendent les pertes
 *             du ring buffer et des états temporaires explicitement mesurables.
 *
 * IMPORTANT : les structures ci-dessous sont incluses à la fois par probe.c et
 * native/collector.c. Elles constituent donc l’unique ABI kernel/userspace.
 * Modifier un champ exige de mettre à jour la version de schéma et les tests ABI.
 * =============================================================================
 */

/* [BESOIN B] vmlinux.h fournit déjà les types entiers côté eBPF ; le collecteur
 * userspace doit, lui, inclure linux/types.h pour compiler le même contrat. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* [BESOIN B/P] Version de l’ABI contrôlée par le collecteur avant tout décodage. */
#define AGENTSIGHT_SCHEMA_VERSION 2

/* [BESOIN B] Types d’événements transportés du kernel vers userspace. */
#define AGENTSIGHT_EVENT_EXEC 1
#define AGENTSIGHT_EVENT_FORK 2
#define AGENTSIGHT_EVENT_EXIT 3
#define AGENTSIGHT_EVENT_FILE_OPEN 4
#define AGENTSIGHT_EVENT_FILE_WRITE 5
#define AGENTSIGHT_EVENT_FILE_DELETE 6
#define AGENTSIGHT_EVENT_NETWORK_CONNECT 7

/* [BESOIN B] Origine précise d’une exécution afin d’expliquer execve/execveat. */
#define AGENTSIGHT_SYSCALL_EXECVE 1
#define AGENTSIGHT_SYSCALL_EXECVEAT 2

/* [BESOIN B/D] Nature de l’opération fichier utilisée par la timeline et les règles. */
#define AGENTSIGHT_FILE_OPERATION_OPEN 1
#define AGENTSIGHT_FILE_OPERATION_WRITE 2
#define AGENTSIGHT_FILE_OPERATION_DELETE 3

/* [BESOIN B/P] Bornes statiques nécessaires au vérificateur eBPF et à la maîtrise mémoire. */
#define AGENTSIGHT_COMM_LEN 16
#define AGENTSIGHT_PATH_LEN 256
#define AGENTSIGHT_ARG_LEN 128
#define AGENTSIGHT_MAX_ARGS 6

/* [BESOIN B/C/P] En-tête commun à tous les événements : identité, ordre et filiation. */
struct agentsight_event_header {
    /* [BESOIN B] Version de l’ABI attendue par le collecteur. */
    __u8 version;
    /* [BESOIN B] Type d’événement permettant le dispatch userspace. */
    __u8 event_type;
    /* [BESOIN B/P] Drapeaux réservés aux états de troncature ou extensions futures. */
    __u16 flags;
    /* [BESOIN B/C] PID du processus qui a réellement effectué l’action. */
    __u32 pid;
    /* [BESOIN B/C] PPID utilisé pour relier l’enfant à son parent. */
    __u32 ppid;
    /* [BESOIN B] UID Linux du processus. */
    __u32 uid;
    /* [BESOIN B] GID Linux du processus. */
    __u32 gid;
    /* [BESOIN B/E] Horodatage monotone kernel de l’action. */
    __u64 timestamp_ns;
    /* [BESOIN P] Séquence globale utilisée pour détecter les trous de transport. */
    __u64 sequence;
    /* [BESOIN C] Temps de démarrage du processus : protège contre le PID reuse. */
    __u64 process_start_ns;
    /* [BESOIN C] Temps de démarrage du parent : sécurise la filiation. */
    __u64 parent_start_ns;
    /* [BESOIN B] Nom court du processus fourni par le kernel. */
    char comm[AGENTSIGHT_COMM_LEN];
};

/* [BESOIN B] Données propres à une exécution réussie de processus. */
struct agentsight_exec_payload {
    /* [BESOIN B] Chemin de l’exécutable observé au niveau syscall/kernel. */
    char filename[AGENTSIGHT_PATH_LEN];
    /* [BESOIN B] Arguments bornés permettant de reconstruire la commande. */
    char argv[AGENTSIGHT_MAX_ARGS][AGENTSIGHT_ARG_LEN];
    /* [BESOIN B] Nombre d’arguments effectivement copiés. */
    __u32 argc;
    /* [BESOIN B/P] Indique qu’au moins un argument n’a pas pu être capturé. */
    __u32 argv_truncated;
    /* [BESOIN B] Distingue execve de execveat. */
    __u32 syscall_kind;
    /* [BESOIN B/P] Indique que le chemin de l’exécutable a été tronqué. */
    __u32 filename_truncated;
};

/* [BESOIN C] Données nécessaires à la propagation du suivi parent -> enfant. */
struct agentsight_fork_payload {
    /* [BESOIN C] PID du processus enfant nouvellement créé. */
    __u32 child_pid;
    /* [BESOIN C] PID du processus parent. */
    __u32 parent_pid;
    /* [BESOIN C] Temps de démarrage de l’enfant pour son identité stable. */
    __u64 child_start_ns;
    /* [BESOIN C] Temps de démarrage du parent pour une liaison non ambiguë. */
    __u64 parent_start_ns;
    /* [BESOIN C] Nom initial de l’enfant avant son éventuel exec. */
    char child_comm[AGENTSIGHT_COMM_LEN];
};

/* [BESOIN C] Données marquant la fin de vie d’un processus de la session. */
struct agentsight_exit_payload {
    /* [BESOIN C] Code de sortie Linux. */
    __s32 exit_code;
    /* [BESOIN C] Signal éventuel à l’origine de la terminaison. */
    __s32 signal;
    /* [BESOIN C/P] Durée de vie calculée depuis process_start_ns. */
    __u64 duration_ns;
};

/* [BESOIN B/C/D] Données communes aux ouvertures, écritures et suppressions de fichiers. */
struct agentsight_file_payload {
    /* [BESOIN B/D] Chemin observé, cible potentielle d’une règle sensible. */
    char path[AGENTSIGHT_PATH_LEN];
    /* [BESOIN B] Descripteur concerné par open/write. */
    __s32 fd;
    /* [BESOIN B] Répertoire de base utilisé par openat/unlinkat. */
    __s32 dirfd;
    /* [BESOIN B/D] Drapeaux d’ouverture, notamment l’intention d’écriture. */
    __u32 open_flags;
    /* [BESOIN B/D] OPEN, WRITE ou DELETE. */
    __u32 operation;
    /* [BESOIN B] Valeur de retour du syscall ; seules les réussites sont publiées. */
    __s64 result;
    /* [BESOIN B/P] Nombre d’octets écrits lorsque l’action est write. */
    __u64 bytes;
    /* [BESOIN B/P] Signale une troncature du chemin. */
    __u32 path_truncated;
    /* [BESOIN P] Réserve d’alignement et d’évolution sans casser immédiatement l’ABI. */
    __u32 reserved;
};

/* [BESOIN B/D] Données d’une connexion réseau observée par connect. */
struct agentsight_network_payload {
    /* [BESOIN B] Famille d’adresse AF_INET ou AF_INET6. */
    __u16 family;
    /* [BESOIN B/D] Port distant, utilisable par les règles de sécurité. */
    __u16 port;
    /* [BESOIN B/D] Adresse distante IPv4/IPv6 sur 16 octets. */
    __u8 address[16];
    /* [BESOIN B] Résultat du syscall connect. */
    __s32 result;
    /* [BESOIN P] Réserve d’alignement pour conserver une ABI stable. */
    __u32 reserved;
};

/* [BESOIN A/B] Enveloppe de taille fixe réservée dans le BPF ring buffer. */
struct agentsight_kernel_event {
    /* [BESOIN B/C/P] Métadonnées communes à tous les événements. */
    struct agentsight_event_header header;
    /* [BESOIN B/P] Union : une seule charge utile est active, ce qui borne la taille mémoire. */
    union {
        /* [BESOIN B] Charge utile d’exécution. */
        struct agentsight_exec_payload exec;
        /* [BESOIN C] Charge utile de fork. */
        struct agentsight_fork_payload fork;
        /* [BESOIN C] Charge utile de sortie. */
        struct agentsight_exit_payload exit;
        /* [BESOIN B/D] Charge utile fichier. */
        struct agentsight_file_payload file;
        /* [BESOIN B/D] Charge utile réseau. */
        struct agentsight_network_payload network;
    } payload;
};

/* [BESOIN B/C/P] Configuration écrite par userspace avant l’attachement des probes. */
struct agentsight_sensor_config {
    /* [BESOIN P] Active le filtrage kernel pour réduire CPU et volume d’événements. */
    __u32 filter_enabled;
    /* [BESOIN C] PID racine de l’agent surveillé. */
    __u32 root_pid;
    /* [BESOIN C] Temps de démarrage du PID racine pour détecter sa réutilisation. */
    __u64 root_start_ns;
    /* [BESOIN C] Durée d’un tick /proc utilisée pour normaliser l’identité processus. */
    __u64 clock_tick_ns;
};

/* [BESOIN P] Compteurs kernel exposant explicitement pertes et états manquants. */
struct agentsight_sensor_stats {
    /* [BESOIN P] Événements rejetés faute de place dans le ring buffer. */
    __u64 ringbuf_drops;
    /* [BESOIN P] Échecs d’enregistrement d’un exec en attente. */
    __u64 pending_update_failures;
    /* [BESOIN B/P] Execve/execveat ayant échoué et volontairement non publiés. */
    __u64 failed_execs;
    /* [BESOIN B/P] Confirmation exec reçue sans état d’entrée correspondant. */
    __u64 missing_pending;
    /* [BESOIN C/P] Échecs de mise à jour du suivi des descendants. */
    __u64 tracking_state_failures;
    /* [BESOIN B/P] Échecs de mémorisation des états fichier. */
    __u64 file_state_failures;
    /* [BESOIN B/P] Échecs de mémorisation des états réseau. */
    __u64 network_state_failures;
    /* [BESOIN B/P] Sortie de syscall fichier sans entrée correspondante. */
    __u64 missing_file_pending;
    /* [BESOIN B/P] Sortie connect sans entrée correspondante. */
    __u64 missing_network_pending;
    /* [BESOIN P] Nombre d’événements effectivement soumis au ring buffer. */
    __u64 emitted_events;
};

#endif

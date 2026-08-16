# AgentSight eBPF — Capteur de sécurité au niveau OS

Une implémentation Linux ciblée pour le **Technical Assessment - AI Agent OS-Level Monitoring with eBPF & AgentSight**.

Le capteur observe l’arbre de processus d’un agent IA depuis la frontière du système d’exploitation, sans modifier l’application surveillée. Il capture de vrais événements kernel, les transmet à l’espace utilisateur via un ring buffer BPF, reconstruit une Agent Session, corrèle les enregistrements LLM AgentSight avec l’activité OS, détecte les actions sensibles, persiste les enregistrements au format JSONL et expose l’API backend requise.

## Version v2 - code commenté et traçabilité du besoin

Cette version ajoute une documentation directement dans le code afin qu’un évaluateur puisse relier chaque composant au Technical Assessment sans devoir deviner son rôle. Les commentaires sont volontairement structurés avec les tags suivants :

| Tag de commentaire | Partie du besoin couverte |
|---|---|
| `[BESOIN A]` | Architecture AgentSight et chaîne kernel vers userspace |
| `[BESOIN B]` | Probe eBPF, capture des événements et ring buffer |
| `[BESOIN C]` | Agent Session, arbre de processus et rattachement des descendants |
| `[BESOIN D]` | Détection des actions sensibles et explicabilité |
| `[BESOIN E]` | Corrélation entre interaction LLM et activité OS |
| `[BESOIN F]` | API backend et inspection des données collectées |
| `[BESOIN P]` | Performance, scalabilité, backpressure et pertes |
| `[BESOIN T]` | Démonstration, tests, build et livrables |

La couverture documentaire porte sur :

- chaque module Python et son rôle dans l’architecture ;
- chaque classe, fonction, route API et helper ;
- les principaux blocs conditionnels, boucles, gestionnaires d’erreur et assertions ;
- chaque modèle et champ structurant les événements ou les sessions ;
- chaque structure C, map eBPF, tracepoint, helper kernel et fonction du collecteur libbpf ;
- chaque cible du `Makefile`, dépendance Python, marqueur de test et exclusion Git ;
- chaque test, avec la partie du besoin qu’il prouve.

Les commentaires n’altèrent pas la logique d’exécution : ils servent de couche de lecture, de revue et de traçabilité. Le contrat partagé `src/ebpf/event.h` reste l’unique ABI kernel/userspace et les tests vérifient qu’il n’existe pas de structure concurrente.

## État de validation

Le dépôt contient l’ensemble des chemins d’implémentation demandés par l’assessment.

Éléments validés dans un environnement standard, sans privilèges particuliers :

- compilation Python ;
- tests des modèles, du collecteur, des sessions, de la sécurité, de la persistance, de l’API, du service et de l’intégration AgentSight ;
- vérifications de l’ABI native partagée ;
- vérifications strictes de syntaxe C pour la source eBPF et le lecteur natif libbpf ;
- vérifications au niveau du code source concernant la couverture des hooks, la comptabilisation des pertes, l’ordre de démarrage et l’identité des processus.

Un test kernel de bout en bout nécessitant des privilèges est inclus. Il exécute réellement la chaîne suivante :

```text
processus agent
  -> tracepoints kernel
  -> maps eBPF et ring buffer
  -> lecteur natif libbpf
  -> collecteur Python
  -> Agent Session
  -> règle de sécurité
  -> requête FastAPI
```

Ce test ne peut s’exécuter que sur un hôte Linux compatible disposant du BTF kernel, d’un backend BPF Clang, de `bpftool`, des fichiers de développement libbpf, des tracepoints requis et des privilèges BPF. Si ces prérequis sont absents, le test est explicitement ignoré avec la raison complète ; il n’est jamais remplacé par un événement kernel synthétique.

## Couverture de l’assessment

| Domaine de l’assessment | Implémentation |
|---|---|
| Architecture AgentSight | Mapping des composants upstream et frontière entre réutilisation et implémentation documentés dans ce README |
| Exécution de processus | `execve` et `execveat` optionnel, arguments de commande bornés, confirmation de la réussite de l’exécution |
| Transport kernel → userspace | `BPF_MAP_TYPE_RINGBUF` avec lecteur natif libbpf |
| Arbre de processus | propagation via fork, récupération d’ascendance bornée, identité PID + temps de démarrage, suivi des sorties |
| Activité fichier sensible | `openat` réussi, `openat2` optionnel, `write`, `unlink` et `unlinkat` |
| Activité réseau | `connect` IPv4/IPv6 réussi ou en cours |
| Agent Session | graphe de processus, fichiers, réseau, interactions LLM, alertes, timeline chronologique |
| Événement de sécurité | commandes sensibles, chemins sensibles, suppression, metadata cloud, ports sensibles |
| Corrélation LLM/OS | import AgentSight avec corrélation temporelle/PID explicable et limitée à la session |
| Persistance | JSONL append-only thread-safe |
| API backend | tous les endpoints requis, plus santé, métriques, corrélation et import |
| Performance | filtrage kernel, maps/queues bornées, traitement par lots, compteurs de pertes, suivi des trous de séquence |
| Démonstration | processus réel, lecture de fichier sensible, connexion réseau locale, écriture/suppression de fichier, `rm --version`, alerte |
| Tests automatisés | suite sans privilèges et test E2E kernel privilégié |

## Architecture

```text
                         AgentSight record/report/export
                         prompts + audit + snapshot JSON
                                      |
                                      v
                           Normalisation AgentSight
                                      |
                                      v
+-----------------------+      +------+---------------------------+
| Kernel Linux          |      | Agent Session                    |
|                       |      |                                  |
| execve / execveat     |      | requête LLM                      |
| fork / sortie process |      |   -> arbre de processus          |
| openat / openat2      |----->|   -> activité fichier/réseau     |
| write / unlink        | ring |   -> corrélations explicables    |
| connect IPv4 / IPv6   |buffer|   -> résultats de sécurité       |
+-----------+-----------+      +---------------+------------------+
            |                                  |
            v                                  v
      Probe eBPF CO-RE                  JSONL + FastAPI
            |
            v
    Lecteur natif libbpf
            |
            v
 modèles d’événements Python validés
```

Chemin de données concret :

```text
tracepoint/raw tracepoint Linux
  -> src/ebpf/probe.c
  -> ABI partagée src/ebpf/event.h
  -> ring buffer BPF
  -> src/ebpf/native/collector.c
  -> enregistrements JSON séparés par des retours à la ligne
  -> queue userspace bornée
  -> src/collector/collector.py
  -> src/models/events.py
  -> src/models/session.py
  -> src/collector/security.py
  -> src/storage/jsonl.py
  -> src/api/server.py
```

## Relation avec AgentSight upstream

Références officielles :

- dépôt : `https://github.com/eunomia-bpf/agentsight`
- documentation : `https://eunomia.dev/agentsight/`

Le projet upstream constitue le point de départ architectural et conceptuel du modèle d’événements. Ce dépôt d’assessment ne copie volontairement ni l’ensemble du workspace Rust, ni le frontend, ni les assets générés, ni la base de données de production.

| Composant / préoccupation AgentSight upstream | Utilisation dans cet assessment |
|---|---|
| `bpf/` | référence pour l’observation indépendante au niveau kernel |
| `collector/` | référence pour le traitement userspace des événements et la corrélation |
| `agent-session/` | référence pour les vues orientées session : processus, prompts, fichiers et réseau |
| `agentsight-capture/` | référence pour les sources d’événements, modèles, analyseurs et sinks réutilisables |
| `agentsight report prompts --json` | importé sous forme d’interactions LLM |
| `agentsight report audit --json` | importé sous forme d’enregistrements d’audit process/file/network upstream lorsqu’ils sont disponibles |
| `agentsight report export -o ...` | accepté par l’adaptateur JSON/JSONL |
| concepts de report et timeline | exposés via la timeline de session et l’API |

Frontière de réutilisation :

- **Réutilisé directement :** JSON/JSONL produits par les commandes officielles `report` / `export` du CLI AgentSight.
- **Adapté conceptuellement :** chaîne kernel -> collector -> modèle d’événements -> session -> timeline/report, ainsi que la corrélation prompt ↔ effets système.
- **Implémenté localement :** programmes eBPF spécifiques à l’assessment, ABI, loader, validation des événements, identité des processus, gestionnaire de sessions, règles de sécurité, persistance, API, tests et démonstration.
- **Non revendiqué :** ce dépôt n’est ni un fork ni un remplacement de la stack complète de capture AgentSight, du TLS tracing, de l’UI, des parsers d’agents natifs ou du stockage de production.

Chaque enregistrement AgentSight importé est conservé dans les métadonnées de l’événement. Les identifiants d’import sont déterministes, les imports répétés sont idempotents, et les timestamps source absents ou malformés sont rejetés au lieu d’être remplacés par une heure inventée.

## Contenu du dépôt

```text
.
|-- README.md
|-- LICENSE
|-- Makefile
|-- requirements.txt
|-- pytest.ini
|-- scripts/
|   |-- demo_agent.py
|   |-- demo_live.py
|   `-- run_live_api.py
|-- src/
|   |-- api/
|   |   `-- server.py
|   |-- collector/
|   |   |-- collector.py
|   |   |-- live_ebpf.py
|   |   |-- runtime.py
|   |   `-- security.py
|   |-- ebpf/
|   |   |-- event.h
|   |   |-- probe.c
|   |   `-- native/collector.c
|   |-- integrations/
|   |   `-- agentsight.py
|   |-- models/
|   |   |-- events.py
|   |   `-- session.py
|   |-- storage/
|   |   `-- jsonl.py
|   `-- service.py
`-- tests/
```

L’archive source exclut les PDF de l’assessment, les probes dupliqués, les rapports de remédiation, les binaires générés, les caches, les bases de données, les environnements virtuels et les artefacts d’exécution.

## ABI événementielle partagée

`src/ebpf/event.h` est l’unique ABI C utilisée à la fois par le code kernel et le code userspace. Le collecteur Python consomme le JSON émis par le lecteur natif ; il n’existe donc pas de définition Python indépendante de `struct` susceptible de diverger silencieusement.

L’en-tête fixe de l’événement contient :

```text
version du schéma et type d’événement
PID / PPID
UID / GID
timestamp kernel monotone
numéro de séquence
identité de démarrage du processus
identité de démarrage du parent
comm
```

L’union de payload contient :

```text
EXEC
  nom du fichier, argv borné, troncation argument/fichier, type d’execve
FORK
  PID/identité de démarrage enfant et parent, comm de l’enfant
EXIT
  code de sortie, signal, durée observée
FILE_OPEN
  chemin, fd, dirfd, flags, résultat, troncation du chemin
FILE_WRITE
  chemin ou identité du descripteur, nombre d’octets, résultat, troncation du chemin
FILE_DELETE
  chemin, dirfd, résultat, troncation du chemin
NETWORK_CONNECT
  famille d’adresses, adresse IPv4/IPv6, port, résultat
```

L’ABI est versionnée. Des assertions statiques natives et des tests automatisés vérifient sa taille et ses offsets.

## Choix de conception eBPF

### Exécution de processus

Le capteur combine l’entrée du syscall avec une confirmation du scheduler :

1. `sys_enter_execve` ou `sys_enter_execveat` lit le nom du fichier et les pointeurs d’arguments bornés tant que la mémoire userspace est encore disponible.
2. L’état en attente est stocké dans une map LRU.
3. `sched_process_exec` confirme que l’exécution a réussi.
4. Seule une exécution confirmée est émise.
5. `sys_exit_execve` et `sys_exit_execveat` suppriment l’état en attente lorsque l’exécution échoue.

Cela évite de signaler un `execve` échoué comme une action réellement exécutée par le système d’exploitation.

La capture de la commande est limitée à six arguments et 128 octets par argument. `argv_truncated` couvre également un argument individuel tronqué. `filename_truncated` est signalé séparément. Le userspace tente de résoudre l’exécutable final via `/proc/<pid>/exe` et conserve le nom de fichier kernel dans les métadonnées.

### Arbre de processus et identité stable

- Le userspace initialise un PID racine de confiance ainsi que tous les descendants actuellement visibles.
- `sched_process_fork` propage l’appartenance aux futurs descendants.
- La création de threads est ignorée en comparant les TGID du parent et de l’enfant.
- En cas d’absence dans la map de suivi, le programme eBPF effectue une remontée d’ascendance bornée à 16 niveaux afin de récupérer un descendant ayant subi une course avec le snapshot userspace.
- Le PID racine est associé à son identité de démarrage afin qu’une réutilisation ultérieure du même PID numérique ne soit pas traitée comme la session d’origine.
- Les générations de processus sont conservées en userspace au lieu d’écraser l’historique.
- La sortie de processus n’est émise que pour le leader du groupe de threads.

Linux `/proc/<pid>/stat` expose le temps de démarrage du processus en ticks d’horloge userspace, tandis que le kernel stocke `task_struct::start_boottime` en nanosecondes. Le loader fournit la période d’un tick et le programme eBPF quantifie la valeur kernel avant comparaison. Les seeds procfs et les événements kernel utilisent ainsi la même identité de processus.

Pour une commande nouvellement lancée, `LiveSensorService` démarre un enfant temporaire qui s’arrête lui-même avec `SIGSTOP` immédiatement avant `exec`. Le capteur est entièrement chargé et le PID racine est configuré avant `SIGCONT`. Le programme cible lui-même reste inchangé et son tout premier `exec` réel devient observable sans dépendre d’une course basée sur un `sleep`.

### Événements fichier

L’extension fichier minimale observe :

- les `openat` réussis ;
- les `openat2` réussis lorsque le tracepoint est disponible ;
- les `write` réussis ;
- les `unlink` et `unlinkat` réussis ;
- les `close` réussis pour nettoyer l’état des descripteurs.

`openat2` est traité comme une structure de syscall versionnée : le probe lit uniquement le champ initial `flags` et vérifie la taille de structure fournie par le userspace au lieu de supposer une structure complète de taille fixe.

Les descripteurs ouverts sont indexés par TGID et FD. Les écritures via des descripteurs hérités ou préexistants sont également émises. Si la map kernel ne possède pas le chemin, le userspace effectue une résolution best-effort via `/proc/<pid>/fd/<fd>` ; si la résolution est impossible, l’événement reste visible sous la forme `fd:<number>` au lieu d’être supprimé.

Les chemins relatifs sont résolus via `/proc/<pid>/cwd` ou `/proc/<pid>/fd/<dirfd>` lorsque ces références sont encore disponibles. La troncation est explicite.

### Événements réseau

`sys_enter_connect` capture les informations de destination IPv4 ou IPv6. `sys_exit_connect` émet un événement lorsque l’appel réussit ou retourne `-EINPROGRESS`, résultat attendu pour une tentative de connexion non bloquante.

Le capteur enregistre l’adresse de destination, le port, la famille et la valeur de retour. Il n’inspecte pas le contenu des payloads réseau.

### Filtrage kernel

Lorsqu’un PID racine est configuré, les processus non liés sont rejetés avant la création d’un état pending ou d’un enregistrement dans le ring buffer. Cela réduit la consommation CPU, mémoire, la pression sur le ring buffer et la charge userspace par rapport à une capture globale de l’hôte suivie d’un filtrage en userspace.

Le filtre combine :

```text
PID racine / descendants courants initialisés
+ propagation par fork
+ récupération d’ascendance bornée
+ garde sur le temps de démarrage du PID racine
```

### Ring buffer, backpressure et pertes d’événements

L’implémentation utilise un `BPF_MAP_TYPE_RINGBUF` de 4 MiB.

Un numéro de séquence est attribué avant `bpf_ringbuf_reserve()`. Si la réservation échoue, le nouvel événement n’est pas écrit et `kernel_ringbuf_drops` est incrémenté. Un trou de séquence ultérieur fournit une estimation indépendante des enregistrements manquants. Les enregistrements existants ne sont pas décrits comme étant automatiquement évincés.

Métriques kernel :

```text
kernel_ringbuf_drops
pending_update_failures
failed_execs
missing_pending
tracking_state_failures
file_state_failures
network_state_failures
missing_file_pending
missing_network_pending
emitted_events
```

Métriques userspace :

```text
userspace_queue_drops
json_decode_errors
unknown_record_types
invalid_stats_records
invalid_records
sequence_gap_events
estimated_sequence_drops
out_of_order_records
profondeur de queue
```

Le lecteur natif du ring buffer est créé avant l’attachement des probes, ce qui supprime l’intervalle de démarrage évitable pendant lequel des programmes attachés pourraient émettre sans lecteur. Les hooks fichier/réseau optionnels sont désactivés avec un message de démarrage explicite lorsqu’ils sont indisponibles. Les hooks cœur exec, fork et exit sont obligatoires ; le démarrage échoue plutôt que de perdre silencieusement le chemin principal de l’assessment.

## Modèle Agent Session

Une `AgentSession` contient :

```text
ID de session et nom de l’agent
PID racine / PPID / exécutable / commande / heure de démarrage
générations de processus actuelles et historiques
graphe parent/enfant
interactions LLM
timeline chronologique
chemins de fichiers uniques
événements réseau
événements de sécurité
état de début/fin de session
```

### Association des événements

Pour chaque événement :

1. vérifier un mapping PID → session existant ;
2. valider l’identité de démarrage du processus lorsqu’elle est disponible ;
3. sinon, valider un PID parent connu et son identité de démarrage ;
4. enregistrer les descendants fork/exec acceptés pour permettre la corrélation transitive ;
5. supprimer les mappings PID actifs à la sortie tout en conservant les nœuds historiques.

Une identité de démarrage différente ne peut ni terminer ni modifier une ancienne génération du même PID. Un enfant observé avant son parent peut être adopté plus tard lorsque l’identité parent correspondante arrive.

Exemple d’arbre :

```text
python agent.py
|-- bash
|   `-- curl
|-- git
`-- python
```

### Corrélation LLM → OS

Les enregistrements de prompts/appels de modèles AgentSight deviennent des valeurs `LLMInteractionEvent`. Un événement OS ou de sécurité est associé à l’interaction LLM précédente la plus proche dans la même Agent Session lorsqu’elle se situe dans la fenêtre configurée, soit 300 secondes par défaut.

La corrélation enregistre :

```text
ID de l’événement LLM
ID de requête upstream lorsqu’il est disponible
delta temporel
méthode
confiance
justification lisible par un humain
causal_proof = false
```

Si un enregistrement AgentSight contient un PID correspondant au PID ou au PPID de l’événement OS, la méthode et la confiance reflètent à la fois la preuve PID et la preuve temporelle. Si les données LLM sont importées après les événements OS, les corrélations de la timeline en mémoire sont recalculées rétroactivement. Les IDs d’événements source et les enregistrements AgentSight bruts restent inchangés.

Il s’agit d’une association explicable, et non d’une affirmation selon laquelle la sémantique du prompt aurait causé un syscall.

## Import AgentSight

`src/integrations/agentsight.py` prend en charge :

- JSON et JSONL stricts ;
- enveloppes courantes telles que `data`, `payload`, `event` et `attributes` ;
- enregistrements LLM, processus, fichier et réseau ;
- enregistrements contenant à la fois une sémantique LLM et une sémantique OS ;
- timestamps en secondes, millisecondes, microsecondes, nanosecondes et ISO ;
- rejet des valeurs monotones `timestamp_ns` ne disposant pas d’un mapping boot → epoch ;
- IDs déterministes et réimport idempotent ;
- conservation de chaque enregistrement upstream brut ;
- variantes CLI pour `prompts`, `audit` et `export` ;
- polling live des prompts sans lecture des tables SQLite privées d’AgentSight.

L’utilisation du CLI officiel comme frontière de schéma laisse AgentSight responsable de l’interprétation de sa propre version de base de données.

Enregistrer un agent avec AgentSight upstream :

```bash
sudo agentsight record -- <your-agent-command>
```

Inspecter l’enregistrement :

```bash
agentsight report --db run.db
agentsight report --db run.db prompts --json
agentsight report --db run.db audit --json
agentsight report --db run.db export -o snapshot.json
```

Lorsque `scripts/run_live_api.py --agentsight-db ...` est utilisé, l’import initial demande à la fois les prompts et les données d’audit. Si une ancienne version d’AgentSight ne dispose pas du rapport d’audit, le service revient aux prompts uniquement et expose ce fallback dans les métriques. Le polling live importe ensuite les nouveaux enregistrements prompt/modèle de manière idempotente.

## Règles de sécurité

Les règles détectent et expliquent ; elles ne bloquent pas.

Les commandes sensibles incluent :

```text
curl wget ssh scp sftp sudo chmod chown rm dd nc ncat telnet gpg openssl
```

Les motifs de chemins sensibles incluent :

```text
/etc/passwd
/etc/shadow
/etc/sudoers
/root/.ssh/*
/home/*/.ssh/*
.env and .env.*
*/.aws/*
*/.kube/*
*/.config/gcloud/*
```

Règles supplémentaires :

- toute suppression de fichier réussie ;
- adresses de metadata d’instance cloud ;
- ports sensibles non-loopback configurés.

Exemple d’événement de sécurité :

```json
{
  "event_type": "AI_AGENT_SECURITY_EVENT",
  "type": "AI_AGENT_SECURITY_EVENT",
  "severity": "HIGH",
  "session_id": "agent-42",
  "pid": 4312,
  "action": "PROCESS_EXECUTION",
  "target": "/usr/bin/curl https://example.test/report",
  "rule_name": "SENSITIVE_COMMAND_EXECUTION",
  "rule_description": "The agent executed the configured sensitive command 'curl'."
}
```

## API backend

FastAPI fournit les endpoints requis :

```text
GET /agents
GET /agents/{id}
GET /agents/{id}/timeline
GET /agents/{id}/processes
GET /agents/{id}/security-events
GET /events?pid=4312
GET /events?severity=HIGH
```

Endpoints supplémentaires :

```text
GET  /health
GET  /metrics
GET  /agents/{id}/correlations
POST /agents/{id}/llm-interactions
POST /agents/{id}/imports/agentsight
```

`GET /events` prend également en charge :

```text
event_type
from / to
query
limit / offset
```

Les entrées sont validées. Les sévérités invalides, types d’événements inconnus, plages temporelles incohérentes et imports AgentSight malformés retournent des erreurs client explicites. La sérialisation des sessions utilise des snapshots profonds afin que les lectures API n’entrent pas en concurrence avec les mutations du collecteur.

## Prérequis Linux

Une exécution live avec privilèges nécessite :

- Linux avec eBPF et BTF kernel disponible dans `/sys/kernel/btf/vmlinux` ;
- les tracepoints syscall et scheduler requis ;
- Clang/LLVM avec la cible BPF ;
- `bpftool` ;
- les paquets de développement libbpf, libelf et zlib ;
- root ou les capacités `CAP_BPF` + `CAP_PERFMON`, ou `CAP_SYS_ADMIN` ;
- Python 3.10 ou plus récent.

Exemple Debian/Ubuntu :

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev \
  python3 python3-venv python3-pip
```

Monter `tracefs` si nécessaire :

```bash
sudo mount -t tracefs nodev /sys/kernel/tracing
```

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Préflight et build

```bash
make preflight
make build
```

`make preflight` liste tous les prérequis manquants. `make build` génère :

```text
.build/ebpf/vmlinux.h
.build/ebpf/agentsight_probe.o
.build/ebpf/agentsight-ebpf-collector
```

L’objet BPF est compilé avec les métadonnées CO-RE et une sélection `__TARGET_ARCH_*` spécifique à l’architecture. Le helper natif est construit avec libbpf.

## Tests

Exécuter tous les tests ne nécessitant pas de privilèges :

```bash
make test
```

Exécuter la compilation puis la suite sans privilèges :

```bash
make validate
```

La couverture comprend :

- une ABI native partagée unique et son layout attendu ;
- la syntaxe C stricte du probe et du lecteur natif ;
- la présence des hooks et le comportement des hooks optionnels ;
- tous les décodeurs des enregistrements natifs ;
- les métadonnées de troncation des chemins et arguments ;
- les trous de séquence, pertes kernel, pertes de queue et échecs d’état ;
- les contrats de filtrage racine et d’ordre de démarrage ;
- les générations de processus, la réutilisation des PID, l’identité parent, fork/exec/exit et la durée de vie de session ;
- la corrélation temporelle/PID LLM et le backfill tardif ;
- les règles de commandes sensibles, fichiers, suppression, adresse metadata et ports ;
- AgentSight JSON/JSONL, enregistrements mixtes, variantes CLI, polling, rejet des timestamps et chemins d’erreur ;
- la persistance et l’idempotence ;
- les endpoints API requis et les filtres ;
- le lancement contrôlé et l’attachement à un processus existant.

Exécuter le vrai test privilégié :

```bash
make test-kernel
```

Le test E2E kernel :

1. démarre un listener TCP local ;
2. crée une Agent Session avec un enregistrement LLM au format AgentSight ;
3. lance l’agent de démonstration derrière la barrière pré-exec ;
4. compile, charge et attache les vrais programmes eBPF ;
5. observe les activités processus, fichier sensible, écriture, suppression, réseau et sortie ;
6. capture un vrai descendant `rm --version` ;
7. vérifie une alerte de commande HIGH et l’arbre de processus ;
8. interroge la session et l’alerte obtenues via FastAPI ;
9. vérifie qu’il n’y a aucune perte dans le ring buffer kernel ni dans la queue userspace pour la démonstration.

## Démonstration live reproductible

```bash
make demo
```

Commande équivalente :

```bash
sudo -E .venv/bin/python scripts/demo_live.py
```

Utiliser une vraie source AgentSight :

```bash
sudo -E .venv/bin/python scripts/demo_live.py --agentsight-json prompts.json
sudo -E .venv/bin/python scripts/demo_live.py --agentsight-db run.db
```

Le workflow OS déterministe est :

```text
interaction LLM
  -> exec contrôlé de l’agent
  -> lecture de /etc/passwd
  -> connexion à un listener TCP local
  -> ouverture/écriture de artifacts/demo-result.txt
  -> création puis suppression d’un fichier jetable
  -> exec enfant de rm --version
  -> détections sur chemin sensible, suppression et commande
  -> événements de sortie des processus
  -> timeline chronologique et rapport JSONL
```

`rm --version` est sans danger et sert uniquement à démontrer la détection de commande. Le fichier jetable est créé par la démonstration immédiatement avant sa suppression ; aucune donnée utilisateur n’est supprimée.

Les sorties générées sont stockées sous `artifacts/`, répertoire exclu du ZIP source.

## Lancer l’API live

S’attacher à un processus existant :

```bash
sudo -E .venv/bin/python scripts/run_live_api.py \
  --root-pid 4312 \
  --session-id agent-42 \
  --agent-name example-agent \
  --host 127.0.0.1 \
  --port 8000
```

Lancer une commande sans manquer son premier exec :

```bash
sudo -E .venv/bin/python scripts/run_live_api.py \
  --session-id agent-42 \
  --agent-name example-agent \
  --host 127.0.0.1 \
  --port 8000 \
  -- python3 agent.py
```

Importer un rapport/export AgentSight :

```bash
sudo -E .venv/bin/python scripts/run_live_api.py \
  --root-pid 4312 \
  --session-id agent-42 \
  --agentsight-json snapshot.json
```

Suivre une base d’enregistrement AgentSight :

```bash
sudo -E .venv/bin/python scripts/run_live_api.py \
  --root-pid 4312 \
  --session-id agent-42 \
  --agentsight-db run.db \
  --agentsight-poll-interval 2
```

Requêtes utiles :

```bash
curl -s http://127.0.0.1:8000/agents | python -m json.tool
curl -s http://127.0.0.1:8000/agents/agent-42/timeline | python -m json.tool
curl -s http://127.0.0.1:8000/agents/agent-42/processes | python -m json.tool
curl -s http://127.0.0.1:8000/agents/agent-42/security-events | python -m json.tool
curl -s http://127.0.0.1:8000/agents/agent-42/correlations | python -m json.tool
curl -s 'http://127.0.0.1:8000/events?severity=HIGH' | python -m json.tool
curl -s http://127.0.0.1:8000/metrics | python -m json.tool
```

## Performance et scalabilité

Comportement actuel :

- filtrage de l’arbre du PID racine dans le kernel ;
- maps LRU bornées pour les états pending ;
- ring buffer borné à 4 MiB ;
- queue userspace bornée ;
- polling de queue par lots ;
- métriques explicites sur les trous de séquence et les pertes ;
- persistance append-only thread-safe ;
- snapshots API profonds pour garantir des lectures cohérentes ;
- IDs d’événements déterministes et imports AgentSight idempotents.

Sous charge, inspecter d’abord :

```text
kernel_ringbuf_drops
estimated_sequence_drops
userspace_queue_drops
missing_*_pending
compteurs d’échec des maps d’état
profondeur de queue
erreurs de décodage/validation JSON
erreurs de persistance du runtime
```

Les améliorations de production doivent être guidées par des mesures et peuvent inclure :

- dimensionnement du ring buffer à partir de benchmarks de bursts ;
- layouts d’enregistrements natifs séparés et plus petits pour les événements non-exec ;
- identité par cgroup, mount namespace et PID namespace ;
- plusieurs racines de session concurrentes ;
- persistance asynchrone par lots ou en base de données ;
- queue durable et politique de backpressure explicite ;
- métriques Prometheus/OpenTelemetry ;
- limitation de débit ou agrégation pour la télémétrie fichier de faible valeur tout en préservant les alertes ;
- couverture de `writev`, `pwrite*`, `rename*`, `truncate*`, `send*`, UDP et sockets acceptées ;
- propagation de table de descripteurs ou identité d’objet fichier kernel ;
- benchmarks de tempêtes fork/exec, churn de descripteurs et bursts réseau ;
- CI de vérification et d’intégration sur les versions de kernel supportées.

## Limites et hypothèses

- L’objet privilégié doit toujours être compilé, chargé par le verifier, attaché et exécuté sur le kernel cible. Les vérifications C statiques ne remplacent pas le verifier du kernel.
- L’événement principal requis est l’exécution de processus. La couverture fichier et réseau est volontairement utile, mais ne constitue pas un audit VFS ou réseau complet.
- Les hooks fichier couvrent `openat`, `openat2` optionnel, `write`, `close` réussi, `unlink` et `unlinkat` ; ils ne couvrent pas tous les syscalls de mutation.
- `write` peut cibler un fichier régulier, un pipe, un périphérique ou une socket. L’événement conserve les preuves liées au descripteur/chemin ; une classification production inspecterait le type de fichier kernel ou utiliserait un hook VFS plus riche.
- Les écritures via des descripteurs hérités/préexistants sont émises, mais la résolution `/proc/<pid>/fd/<fd>` peut échouer si le descripteur se ferme ou si le processus termine avant le traitement userspace de l’enregistrement.
- Un chemin relatif peut rester non résolu si le processus se termine avant la résolution cwd/dirfd.
- La couverture réseau concerne `connect` IPv4/IPv6 ; elle ne capture ni la sémantique DNS, ni les envois UDP, ni les sockets acceptées, ni les payloads.
- Les arguments et chemins sont bornés ; la troncation est explicite.
- L’attachement à un processus existant ne peut pas reconstruire les événements survenus avant l’attachement. Le fallback d’ascendance est limité à 16 niveaux parentaux.
- L’identité PID/temps de démarrage est orientée hôte. Les PID namespaces, time namespaces et cgroups nécessitent des règles d’identité supplémentaires en production.
- Des tentatives d’exec concurrentes depuis plusieurs threads d’un même TGID peuvent écraser l’unique enregistrement pending-exec ; la capture de commande réussie est conçue pour le comportement normal d’un processus agent.
- Les schémas AgentSight peuvent évoluer. L’importateur sémantique conserve les enregistrements bruts et signale les enregistrements inconnus/malformés, mais de nouveaux noms de champs upstream peuvent nécessiter des aliases.
- Les imports LLM tardifs recalculent les corrélations de l’API en mémoire. Les enregistrements source déjà ajoutés au JSONL restent immuables ; un stockage de production persisterait des mises à jour de corrélation ou des vues matérialisées séparées.
- Le verrouillage JSONL est local au processus et synchrone. Plusieurs processus writers ou une forte volumétrie nécessitent une base de données ou une queue durable.
- L’API locale n’a ni authentification ni TLS. Pour l’assessment, la lier au loopback ; en production, ajouter authentification, autorisation, chiffrement, rétention et redaction.
- La corrélation constitue une preuve temporelle et liée à la session, pas une preuve sémantique ou causale.
- Le capteur détecte et rapporte ; il ne bloque pas les actions.

## Traçabilité des exigences

| Exigence | Implémentation principale |
|---|---|
| Description de l’architecture | ce README |
| Programmes/probes eBPF | `src/ebpf/probe.c` |
| Modèle d’événement partagé | `src/ebpf/event.h` |
| Collecte via ring buffer | `src/ebpf/native/collector.c`, `src/collector/live_ebpf.py` |
| Normalisation userspace | `src/collector/collector.py` |
| Identification agent/session | `src/models/session.py`, `src/collector/runtime.py`, `src/service.py` |
| Intégration AgentSight et LLM | `src/integrations/agentsight.py` |
| Détection d’actions sensibles | `src/collector/security.py` |
| Persistance/export | `src/storage/jsonl.py` |
| API backend | `src/api/server.py` |
| Démonstration reproductible | `scripts/demo_agent.py`, `scripts/demo_live.py` |
| Runner API live | `scripts/run_live_api.py` |
| Tests automatisés | `tests/` |
| Performance, hypothèses, améliorations | ce README |

## Nettoyage

```bash
make clean
```

Cette commande supprime les sorties de build générées, les caches, les fichiers de couverture et les artefacts d’exécution, tout en conservant le code source et les tests.

## Licence

Voir `LICENSE`.
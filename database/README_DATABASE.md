# Couche PostgreSQL offline

## Architecture

```text
output/obj_applications.jsonl -> application
output/obj_servers.jsonl -> server (OS APM prioritaire)
output/application_server_relations.jsonl -> application_server_relation
output/obj_findings_enriched.jsonl -> server / vulnerability / finding
output/PARSER-Result-*.json -> pipeline_run / agent_run
output/parser_anomalies.json -> anomaly
        -> résolution application.auid vers finding.application_id
        -> repository SQL paramétré
        -> transaction PostgreSQL
```

La couche ne modifie ni le Parser, ni `obj_finding`, ni les règles KRI. Le mode
`--dry-run` n'importe pas le driver et n'ouvre aucune connexion.

## Tables

- `application`, `server`, `vulnerability`, `finding` portent les dimensions et les Findings ;
- `application_server_relation` conserve les couples AUID–hostname du flux APM ;
- `pipeline_run`, `agent`, `agent_run`, `anomaly`, `artifact` assurent la traçabilité.

Les concepts Analyst/remédiation futurs ne sont pas créés.

## Mapping obj_finding vers SQL

| Objet source | Destination principale |
|---|---|
| `obj_application` | `application` avec ses champs canoniques |
| `obj_server` | `server.operating_system`, `os_name`, `os_version` |
| `application_server_relations` | `application_server_relation` |
| `hostname`, `server.*` du Finding | environnement normalisé et attributs KRI de `server` |
| `cve`, `cve_detail.title`, `severity_level` | `vulnerability` |
| propriétés restantes du Finding | `finding` |
| objet JSON complet | `finding.source_payload` |

`application.auid` est conservé dans `finding.application_auid` pour la traçabilité
et résolu vers `finding.application_id`. Un finding sans AUID reste chargé avec
`application_id = NULL`; aucun AUID, nom ou statut fictif n'est créé. Le run validé
conserve ainsi les 39 findings sans AUID.

`obj_application.business_line` provient de `Business Lines` et reste dans
`application.business_line`. `finding.business_line` provient de `IT Sub Cluster` :
les deux valeurs ne sont ni comparées ni fusionnées. `code_app`,
`production_domain_manager`, `production_manager`, `trigram`, `application_name`
et `appsec` restent des attributs Application et ne sont pas dupliqués dans Finding.

`obj_servers.jsonl` est la source prioritaire de `operating_system`, `os_name` et
`os_version`. La valeur brute APM de `environment` n'est pas persistée dans la
catégorie normalisée : `environment`, `environment_detail`, `sensitive` et
`authenticated_scan` restent alimentés par les Findings. `description` et
`cvss_score` restent `NULL` car le modèle Parser actuel ne les fournit pas.

## Ordre d'insertion et transactions

Le loader valide d'abord le `ParserResult`, le nombre de Findings JSONL et les
compteurs du fichier d'anomalies. Il insère ensuite : `pipeline_run`, `agent`,
`agent_run`, toutes les anomalies Parser, les Applications canoniques, les
Servers APM, puis les dimensions issues des Findings, les findings, les
anomalies loader et tous les artifacts explicitement fournis au loader. Les relations
Application–Server APM sont insérées de façon idempotente. Psycopg démarre implicitement la
transaction au premier ordre SQL. Un succès appelle `COMMIT`; toute exception
appelle `ROLLBACK`, puis remonte l'erreur. Aucun batch partiel n'est accepté.

Le statut et les compteurs stockés dans `pipeline_run` viennent du
`ParserResult`; un chargement PostgreSQL réussi ne les remplace pas par
`SUCCESS`. Toutes les anomalies Parser, y compris `INFO`, sont reliées au même
`pipeline_run_id` et au même `agent_run_id`. Leur `finding_id` reste `NULL` car
le Parser ne fournit pas encore de clé de rattachement fiable.

Chaque artifact enregistré porte le `pipeline_run_id` du chargement, son SHA-256
et, pour les fichiers JSON/JSONL, un `row_count`. `ParserResult` et les anomalies
Parser portent aussi l'`agent_run_id` Parser. Les artifacts Application, Server,
relations et enrichissement gardent `agent_run_id = NULL`, car leur producteur
n'a pas encore de run Agent PostgreSQL dédié.

## Configuration

Copier `.env.example` vers un fichier local non versionné, puis exposer :

```text
POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER,
POSTGRES_PASSWORD, POSTGRES_SSLMODE
```

Les credentials ne sont ni affichés ni journalisés. `psycopg` est la seule
dépendance PostgreSQL ; aucun ORM n'est introduit.

## Commandes

Préparation offline :

```powershell
python scripts/load_obj_findings_to_postgres.py `
  --applications "output/obj_applications.jsonl" `
  --servers "output/obj_servers.jsonl" `
  --application-server-relations "output/application_server_relations.jsonl" `
  --findings "output/obj_findings_enriched.jsonl" `
  --parser-result "output/PARSER-Result-YYYYMMDD-HHMMSS.json" `
  --parser-anomalies "output/parser_anomalies.json" `
  --dry-run
```

Après accès au serveur :

```powershell
psql -f database/001_create_tables.sql
psql -f database/002_create_indexes.sql
psql -f database/003_server_dimension.sql
psql -f database/004_artifact_traceability.sql
python scripts/load_obj_findings_to_postgres.py `
  --applications "output/obj_applications.jsonl" `
  --servers "output/obj_servers.jsonl" `
  --application-server-relations "output/application_server_relations.jsonl" `
  --findings "output/obj_findings_enriched.jsonl" `
  --parser-result "output/PARSER-Result-YYYYMMDD-HHMMSS.json" `
  --parser-anomalies "output/parser_anomalies.json"
```

Vérifier ensuite au minimum `pipeline_run.output_findings` et
`count(*)` dans `finding`, `server`, `vulnerability` et `application`.

## Index et contraintes

Les PK, FK et contrôles numériques non négatifs sont définis dans le DDL.
`application.auid` est unique : l'AUID est l'identifiant métier Application
confirmé. PostgreSQL fournit donc directement l'index B-tree correspondant.
La tentative d'agent est unique par `(pipeline_run_id, agent_id, attempt_no)`.
Chaque artifact est unique par `(pipeline_run_id, artifact_type, storage_path)`.
Une FK composite empêche de lui associer un `agent_run_id` provenant d'un autre
pipeline. Une réutilisation du même chemin avec un SHA-256 différent est rejetée.
Un index unique partiel sur `vulnerability.cve_code IS NOT NULL` matérialise le
regroupement CVE confirmé. Il n'impose rien aux CVE absentes.

`server.hostname` est obligatoire, trimé, non vide et unique sans changement de
casse. Le couple `(application_id, server_id)` est la clé primaire de la table de
jonction. Il n'existe aucune unicité sur `unique_id` ou `remediation_id`, et aucune
obligation sur `application_id`, `remediation_id` ou `strategy_type`. Aucun index
GIN JSONB ni trigger KRI n'est créé.

## Idempotence et limites actuelles

`unique_id = CVE` n'est pas une clé d'occurrence. Le loader ne déduplique jamais
les findings. Chaque import reçoit un nouveau `pipeline_run_id`, ce qui rend les
rechargements visibles mais ne constitue pas une idempotence métier. Une clé
d'occurrence fiable doit être confirmée avant toute contrainte supplémentaire.

L'Application est retrouvée globalement par son AUID unique et le Server par son
hostname trimé. APM peut compléter ou remplacer les trois colonnes OS ; un
Finding peut actualiser les colonnes d'environnement et KRI, sans écraser l'OS
APM. Un AUID de finding absent du référentiel produit
`UNRESOLVED_APPLICATION_AUID` sans créer de fausse Application.
Les serveurs sans hostname ne sont jamais créés.

- PostgreSQL server access = **PENDING**
- CIB APM Server integration = **IMPLEMENTED**
- Stratégie d'idempotence métier Finding = **TO VALIDATE**
- Chargement du `ParserResult` et des anomalies Parser = **IMPLEMENTED**
- Traçabilité Artifact par pipeline run = **IMPLEMENTED**

## Future PostgreSQL access

1. renseigner les variables d'environnement ;
2. exécuter les quatre scripts SQL dans l'ordre ;
3. tester une connexion `psql`/psycopg ;
4. relancer le dry-run complet ;
5. lancer le loader sans `--dry-run` ;
6. rapprocher les compteurs du run et des tables.

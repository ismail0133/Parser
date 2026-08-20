# Couche PostgreSQL offline

## Architecture

```text
output/obj_applications.jsonl -> application
output/obj_findings_enriched.jsonl -> server / vulnerability / finding
        -> résolution application.auid vers finding.application_id
        -> repository SQL paramétré
        -> transaction PostgreSQL
```

La couche ne modifie ni le Parser, ni `obj_finding`, ni les règles KRI. Le mode
`--dry-run` n'importe pas le driver et n'ouvre aucune connexion.

## Tables

- `application`, `server`, `vulnerability`, `finding` normalisent les données du Finding ;
- `pipeline_run`, `agent`, `agent_run`, `anomaly`, `artifact` assurent la traçabilité.

Les concepts Analyst/remédiation futurs ne sont pas créés.

## Mapping obj_finding vers SQL

| Objet source | Destination principale |
|---|---|
| `obj_application` | `application` avec ses huit champs canoniques |
| `hostname`, `server.*` | `server` |
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

Les champs demandés pour la future intégration CIB APM existent et restent
`NULL` faute de source. `operating_system`, `description` et `cvss_score` restent
également `NULL` car le modèle Parser actuel ne les fournit pas.

## Ordre d'insertion et transactions

Le loader insère : `pipeline_run`, `agent`, `agent_run`, les Applications
canoniques, puis les dimensions, les findings, les anomalies loader et les deux
artifacts JSONL. Psycopg démarre implicitement la
transaction au premier ordre SQL. Un succès appelle `COMMIT`; toute exception
appelle `ROLLBACK`, puis remonte l'erreur. Aucun batch partiel n'est accepté.

Les anomalies peuvent être chargées avec `insert_anomaly` dès qu'un artifact
d'anomalies est fourni et relié au run. Le JSONL de Findings n'en contient pas :
le loader actuel n'en invente donc aucune.

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
  --findings "output/obj_findings_enriched.jsonl" `
  --dry-run
```

Après accès au serveur :

```powershell
psql -f database/001_create_tables.sql
psql -f database/002_create_indexes.sql
python scripts/load_obj_findings_to_postgres.py `
  --applications "output/obj_applications.jsonl" `
  --findings "output/obj_findings_enriched.jsonl"
```

Vérifier ensuite au minimum `pipeline_run.output_findings` et
`count(*)` dans `finding`, `server`, `vulnerability` et `application`.

## Index et contraintes

Les PK, FK et contrôles numériques non négatifs sont définis dans le DDL.
`application.auid` est unique : l'AUID est l'identifiant métier Application
confirmé. PostgreSQL fournit donc directement l'index B-tree correspondant.
La tentative d'agent est unique par `(pipeline_run_id, agent_id, attempt_no)`.
Un index unique partiel sur `vulnerability.cve_code IS NOT NULL` matérialise le
regroupement CVE confirmé. Il n'impose rien aux CVE absentes.

Il n'existe volontairement aucune unicité sur hostname, `unique_id` ou
`remediation_id`, et aucune obligation sur `application_id`, `remediation_id` ou
`strategy_type`. Aucun index GIN JSONB ni trigger KRI n'est créé.

## Idempotence et limites actuelles

`unique_id = CVE` n'est pas une clé d'occurrence. Le loader ne déduplique jamais
les findings. Chaque import reçoit un nouveau `pipeline_run_id`, ce qui rend les
rechargements visibles mais ne constitue pas une idempotence métier. Une clé
d'occurrence fiable doit être confirmée avant toute contrainte supplémentaire.

Dans un run, des dimensions ayant exactement le même contenu sont réutilisées en
mémoire. L'Application est retrouvée globalement par son AUID unique. Une ligne
déjà présente est conservée sans mise à jour silencieuse, faute de règle de
priorité source validée. Un AUID de finding absent du référentiel produit
`UNRESOLVED_APPLICATION_AUID` sans créer de fausse Application.
Cela n'affirme aucune unicité métier globale du hostname. Les serveurs sans
hostname ne sont pas inventés.

- PostgreSQL server access = **PENDING**
- CIB APM integration = **IN PROGRESS / PENDING**
- Stratégie d'idempotence métier Finding = **TO VALIDATE**
- Chargement automatique de l'artifact d'anomalies = **future extension**

## Future PostgreSQL access

1. renseigner les variables d'environnement ;
2. exécuter les deux scripts SQL dans l'ordre ;
3. tester une connexion `psql`/psycopg ;
4. relancer le dry-run complet ;
5. lancer le loader sans `--dry-run` ;
6. rapprocher les compteurs du run et des tables.

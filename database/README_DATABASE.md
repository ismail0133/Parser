# Couche PostgreSQL offline

## Architecture

```text
output/obj_findings.jsonl
        -> mapper Python pur
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
| `application.*` | `application` si des données descriptives sont disponibles |
| `hostname`, `server.*` | `server` |
| `cve`, `cve_detail.title`, `severity_level` | `vulnerability` |
| propriétés restantes du Finding | `finding` |
| objet JSON complet | `finding.source_payload` |

`application.auid` est aussi conservé dans `finding.application_auid` lorsque
l'Application n'est pas suffisamment renseignée. Dans ce cas,
`finding.application_id` reste `NULL`. Aucun nom ou statut fictif n'est créé.

Les champs demandés pour la future intégration CIB APM existent et restent
`NULL` faute de source. `operating_system`, `description` et `cvss_score` restent
également `NULL` car le modèle Parser actuel ne les fournit pas.

## Ordre d'insertion et transactions

Le loader insère : `pipeline_run`, `agent`, `agent_run`, puis les dimensions
disponibles, les findings et l'artifact JSONL. Psycopg démarre implicitement la
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
  --input "output/obj_findings.jsonl" `
  --dry-run
```

Après accès au serveur :

```powershell
psql -f database/001_create_tables.sql
psql -f database/002_create_indexes.sql
python scripts/load_obj_findings_to_postgres.py --input "output/obj_findings.jsonl"
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
mémoire. L'Application est aussi retrouvée globalement par son AUID confirmé.
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

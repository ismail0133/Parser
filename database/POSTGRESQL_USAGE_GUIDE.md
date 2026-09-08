# Guide pratique PostgreSQL du projet Parser

Ce guide rassemble les contrôles PostgreSQL que j'utilise pour explorer les données du Parser, vérifier un chargement et préparer une démonstration dans pgAdmin. Toutes les requêtes correspondent au schéma actuel du projet.

Dans les requêtes filtrées, je remplace toujours l'UUID d'exemple suivant par le `pipeline_run_id` que je veux contrôler :

```text
00000000-0000-0000-0000-000000000000
```

## Sommaire

1. [Présentation rapide de la base](#1-présentation-rapide-de-la-base)
2. [Naviguer dans pgAdmin sans SQL](#2-naviguer-dans-pgadmin-sans-sql)
3. [Vérifier les volumes](#3-vérifier-les-volumes)
4. [Voir les pipeline runs](#4-voir-les-pipeline-runs)
5. [Compter les findings par run](#5-compter-les-findings-par-run)
6. [Voir un finding avec tout son contexte](#6-voir-un-finding-avec-tout-son-contexte)
7. [Afficher les vulnérabilités](#7-afficher-les-vulnérabilités)
8. [Afficher les serveurs](#8-afficher-les-serveurs)
9. [Afficher les applications](#9-afficher-les-applications)
10. [Contrôler les relations](#10-contrôler-les-relations)
11. [Vérifier les doublons](#11-vérifier-les-doublons)
12. [KRI RAS 9](#12-kri-ras-9)
13. [Démo manager – 5 minutes](#13-démo-manager--5-minutes)
14. [Bonnes pratiques](#14-bonnes-pratiques)
15. [Cheat sheet finale](#15-cheat-sheet-finale)

## 1. Présentation rapide de la base

J'utilise cinq tables principales pour consulter les données métier et suivre leur chargement.

| Table | Rôle dans mon projet |
|---|---|
| `finding` | Contient une occurrence chargée par le pipeline, ses dates, sa sévérité, son statut hors SLA et les informations de remédiation. |
| `application` | Contient le contexte applicatif identifié par l'AUID. |
| `server` | Contient le hostname et le contexte technique du serveur. |
| `vulnerability` | Contient la CVE et les informations générales de vulnérabilité. |
| `pipeline_run` | Trace chaque exécution du chargement PostgreSQL. |

La table `finding` est le point central du modèle. Les relations réellement définies sont :

```text
application ── application_id ──┐
server ─────── server_id ───────┼──> finding
vulnerability ─ vulnerability_id┤
pipeline_run ─ pipeline_run_id ─┘
```

- `finding.application_id` référence `application.application_id` ; cette relation peut être `NULL`.
- `finding.server_id` référence `server.server_id` ; cette relation peut être `NULL`.
- `finding.vulnerability_id` référence `vulnerability.vulnerability_id` ; cette relation peut être `NULL`.
- `finding.pipeline_run_id` référence `pipeline_run.pipeline_run_id` et ne peut pas être `NULL`.

Je distingue trois identifiants importants :

- `finding_id` est l'identifiant technique généré par PostgreSQL pour une ligne de `finding`.
- `source_unique_id` conserve l'identifiant source lorsqu'il existe. Dans le flux actuel, il ne constitue pas une clé d'occurrence métier fiable.
- `pipeline_run_id` identifie le chargement qui a créé le finding et me permet de séparer les différentes exécutions.

## 2. Naviguer dans pgAdmin sans SQL

Pour parcourir rapidement les tables dans pgAdmin :

1. J'ouvre pgAdmin et je me connecte à mon serveur PostgreSQL.
2. Dans l'arborescence de gauche, j'ouvre `Servers`, puis mon serveur.
3. J'ouvre `Databases`, puis la base `vulnerability_ai`.
4. J'ouvre `Schemas`, `public`, puis `Tables`.
5. Je retrouve notamment `application`, `finding`, `server`, `vulnerability` et `pipeline_run`.
6. Je fais un clic droit sur une table, puis `View/Edit Data` et `First 100 Rows`.

Pour découvrir la base, je commence généralement par :

1. `pipeline_run`, pour identifier le chargement à analyser ;
2. `finding`, pour voir les données principales ;
3. `application`, `server` et `vulnerability`, pour comprendre les dimensions liées.

Dans la grille de données, je peux cliquer sur un en-tête de colonne pour trier les lignes. Selon la version de pgAdmin, les options de tri et de filtre sont accessibles depuis la barre d'outils de la grille ou depuis l'icône de filtre. Je vérifie toujours le filtre affiché avant d'interpréter le résultat.

Même si le menu s'appelle `View/Edit Data`, je l'utilise ici uniquement pour consulter. Je n'enregistre pas de modification manuelle dans la grille.

Pour exécuter les blocs SQL des sections suivantes, je sélectionne `vulnerability_ai`, j'ouvre `Tools` puis `Query Tool`, je colle la requête et je lance son exécution avec le bouton ▶ ou `F5`.

## 3. Vérifier les volumes

Pour voir les volumes physiques actuels des quatre tables métier, j'utilise :

```sql
SELECT
    (SELECT COUNT(*) FROM finding) AS total_findings,
    (SELECT COUNT(*) FROM application) AS total_applications,
    (SELECT COUNT(*) FROM server) AS total_servers,
    (SELECT COUNT(*) FROM vulnerability) AS total_vulnerabilities;
```

Ces compteurs n'ont pas tous le même périmètre. `application`, `server` et `vulnerability` sont des tables de dimension, tandis que chaque ligne de `finding` appartient à un `pipeline_run`.

Je conserve les différents runs afin de garder la traçabilité des chargements. Si je charge deux fois le même CSV, le total de la table `finding` peut donc augmenter, même si les deux runs portent des données similaires.

## 4. Voir les pipeline runs

Pour lister les chargements, j'utilise exactement cette requête :

```sql
SELECT
    pipeline_run_id,
    started_at,
    run_status,
    source_filename,
    input_rows,
    output_findings
FROM pipeline_run
ORDER BY started_at DESC;
```

La première ligne est normalement le run le plus récent, car le résultat est trié par `started_at DESC`. Avant de reprendre son UUID, je vérifie aussi `run_status`, `source_filename`, `input_rows` et `output_findings`.

Pour mes contrôles, je copie ensuite le `pipeline_run_id` exact et je l'utilise dans toutes les requêtes suivantes.

## 5. Compter les findings par run

Pour comparer les volumes chargés par exécution :

```sql
SELECT
    pipeline_run_id,
    COUNT(*) AS nb_findings
FROM finding
GROUP BY pipeline_run_id
ORDER BY nb_findings DESC;
```

Deux chargements du même CSV reçoivent deux `pipeline_run_id` différents. Les mêmes données peuvent donc apparaître dans deux runs sans constituer un doublon à l'intérieur d'une exécution. Cette séparation est volontaire : elle conserve l'historique des chargements.

Pour contrôler uniquement un run précis :

```sql
SELECT COUNT(*) AS nb_findings
FROM finding
WHERE pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid;
```

## 6. Voir un finding avec tout son contexte

Pour afficher un finding avec son application, son serveur, sa CVE et sa remédiation, j'utilise des `LEFT JOIN`. Je conserve ainsi le finding même si une relation optionnelle n'a pas été résolue.

```sql
SELECT
    f.finding_id,
    a.auid,
    s.hostname,
    v.cve_code,
    f.affected_component,
    f.severity_level,
    f.overdue,
    f.remediation_id,
    f.proposed_action,
    f.strategy_type,
    f.strategy_description,
    f.solution_links
FROM finding AS f
LEFT JOIN application AS a
    ON a.application_id = f.application_id
LEFT JOIN server AS s
    ON s.server_id = f.server_id
LEFT JOIN vulnerability AS v
    ON v.vulnerability_id = f.vulnerability_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
ORDER BY f.finding_id
LIMIT 20;
```

Les colonnes affichées correspondent aux informations suivantes :

| Colonne | Ce que je vérifie |
|---|---|
| `finding_id` | L'identifiant technique PostgreSQL du finding. |
| `auid` | L'identifiant de l'application liée, lorsqu'elle a été résolue. |
| `hostname` | Le serveur concerné par le finding. |
| `cve_code` | La CVE rattachée au finding. |
| `affected_component` | Le composant affecté conservé dans le finding. |
| `severity_level` | La sévérité portée par le finding. |
| `overdue` | Le résultat du contrôle `age_days > sla_days`, lorsqu'il est calculable. |
| `remediation_id` | L'identifiant de remédiation issu du payload Parser. |
| `proposed_action` | L'action proposée dans la source. |
| `strategy_type` | Le type de stratégie prévu pour une analyse ultérieure. |
| `strategy_description` | La description de la stratégie issue de `Action Plan`. |
| `solution_links` | Les liens de solution fournis avec le finding. |

### Pourquoi `strategy_type` peut être `NULL`

Dans le Parser actuel, aucune colonne RAW n'alimente `remediation_strategy.strategy_type`. Le Parser lui affecte volontairement `None`, puis le mapper PostgreSQL transfère cette valeur vers `finding.strategy_type`.

Ce champ est prévu pour être déterminé plus tard lors de l'analyse. La règle qui permettra de le renseigner reste **TO_VALIDATE**. En revanche, `strategy_description` est déjà alimentée par la colonne RAW `Action Plan` via `remediation_strategy.description`.

## 7. Afficher les vulnérabilités

### Voir le référentiel des vulnérabilités

```sql
SELECT
    vulnerability_id,
    cve_code,
    title,
    description,
    severity_level,
    cvss_score
FROM vulnerability
ORDER BY cve_code NULLS LAST
LIMIT 100;
```

Dans le mapping actuel, `description` et `cvss_score` peuvent être `NULL`, car le modèle Parser chargé ne les fournit pas.

### Voir les CVE les plus présentes dans un run

```sql
SELECT
    v.cve_code,
    v.title,
    COUNT(f.finding_id) AS nb_findings
FROM finding AS f
JOIN vulnerability AS v
    ON v.vulnerability_id = f.vulnerability_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
GROUP BY
    v.vulnerability_id,
    v.cve_code,
    v.title
ORDER BY nb_findings DESC, v.cve_code
LIMIT 20;
```

### Voir les findings Critical ou Very High

```sql
SELECT
    f.finding_id,
    v.cve_code,
    v.title,
    f.severity_level,
    f.overdue,
    f.false_positive
FROM finding AS f
LEFT JOIN vulnerability AS v
    ON v.vulnerability_id = f.vulnerability_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
  AND LOWER(f.severity_level) IN ('critical', 'very high')
ORDER BY f.severity_level, v.cve_code NULLS LAST;
```

### Voir uniquement les findings hors SLA

```sql
SELECT
    f.finding_id,
    v.cve_code,
    f.severity_level,
    f.age_days,
    f.sla_days,
    f.overdue,
    f.remediation_id
FROM finding AS f
LEFT JOIN vulnerability AS v
    ON v.vulnerability_id = f.vulnerability_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
  AND f.overdue IS TRUE
ORDER BY f.age_days DESC NULLS LAST;
```

Cette dernière requête n'exclut pas automatiquement les false positives. Si je veux appliquer cette règle supplémentaire, j'ajoute explicitement `AND f.false_positive IS NOT TRUE`.

## 8. Afficher les serveurs

La table `server` ne contient pas de `pipeline_run_id`. Pour analyser un run précis, je passe donc par la relation `finding.server_id`.

### Lister les serveurs liés à un run

```sql
SELECT DISTINCT
    s.hostname,
    s.sensitive,
    s.authenticated_scan,
    s.environment,
    s.environment_detail,
    s.operating_system,
    s.os_name,
    s.os_version
FROM finding AS f
JOIN server AS s
    ON s.server_id = f.server_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
ORDER BY s.hostname NULLS LAST;
```

Le schéma contient `operating_system`, `os_name` et `os_version`. Dans le mapping actuel, `operating_system` n'est pas alimenté et peut rester `NULL`, tandis que `os_name` et `os_version` peuvent être fournis par le Parser.

### Compter les hostnames distincts d'un run

```sql
SELECT
    COUNT(DISTINCT BTRIM(s.hostname)) AS distinct_hostnames
FROM finding AS f
JOIN server AS s
    ON s.server_id = f.server_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
  AND s.hostname IS NOT NULL
  AND BTRIM(s.hostname) <> '';
```

### Contrôler les attributs KRI des serveurs

```sql
SELECT
    BTRIM(s.hostname) AS hostname,
    BOOL_OR(s.sensitive IS TRUE) AS sensitive_on_at_least_one_row,
    BOOL_OR(s.authenticated_scan IS TRUE) AS authenticated_on_at_least_one_row,
    COUNT(*) AS nb_findings
FROM finding AS f
JOIN server AS s
    ON s.server_id = f.server_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
  AND s.hostname IS NOT NULL
  AND BTRIM(s.hostname) <> ''
GROUP BY BTRIM(s.hostname)
ORDER BY hostname;
```

Cette requête est un contrôle descriptif. Pour calculer l'éligibilité KRI exacte, j'utilise la requête complète de la section 12, qui évalue `sensitive` et `authenticated_scan` ensemble sur une même ligne avant l'agrégation par hostname.

## 9. Afficher les applications

Les colonnes demandées existent dans la table `application`. Pour afficher uniquement les applications liées à un run :

```sql
SELECT DISTINCT
    a.auid,
    a.trigram,
    a.application_name,
    a.appsec,
    a.vital,
    a.continuity_level,
    a.application_manager,
    a.production_manager
FROM finding AS f
JOIN application AS a
    ON a.application_id = f.application_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
ORDER BY a.auid;
```

Le loader PostgreSQL actuel alimente `auid`, `code_app`, `trigram`, `application_name`, `appsec`, `business_line`, `production_domain_manager` et `production_manager`. Les autres colonnes ne sont pas incluses dans son mapping actuel et restent donc `NULL` sur les lignes qu'il crée. Toute évolution de cette alimentation reste **TO_VALIDATE**.

## 10. Contrôler les relations

Pour vérifier la résolution des trois relations optionnelles sur un run précis :

```sql
SELECT
    COUNT(*) AS total_findings,
    COUNT(application_id) AS linked_applications,
    COUNT(server_id) AS linked_servers,
    COUNT(vulnerability_id) AS linked_vulnerabilities,
    COUNT(*) FILTER (WHERE application_id IS NULL) AS without_application,
    COUNT(*) FILTER (WHERE server_id IS NULL) AS without_server,
    COUNT(*) FILTER (WHERE vulnerability_id IS NULL) AS without_vulnerability
FROM finding
WHERE pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid;
```

J'interprète les résultats ainsi :

- `total_findings` est le nombre total de findings du run.
- `linked_applications`, `linked_servers` et `linked_vulnerabilities` comptent les findings ayant une clé étrangère renseignée. Il ne s'agit pas du nombre d'entités distinctes.
- `without_application`, `without_server` et `without_vulnerability` comptent les findings dont la relation correspondante est absente.
- Pour chaque relation, le compteur `linked_*` ajouté au compteur `without_*` doit être égal à `total_findings`.

Une relation absente n'implique pas que le finding a été perdu : le schéma autorise ces trois clés étrangères à être `NULL`.

## 11. Vérifier les doublons

Je distingue deux situations :

- Entre deux runs, une même donnée source peut réapparaître normalement, car chaque chargement possède son propre `pipeline_run_id`.
- Dans un même run, plusieurs lignes avec le même `source_unique_id` doivent être analysées pour déterminer s'il s'agit de répétitions attendues ou de doublons.

Pour rechercher les répétitions de `source_unique_id` à l'intérieur d'un run :

```sql
SELECT
    pipeline_run_id,
    source_unique_id,
    COUNT(*) AS occurrences,
    ARRAY_AGG(finding_id ORDER BY finding_id) AS finding_ids
FROM finding
WHERE pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
  AND source_unique_id IS NOT NULL
GROUP BY pipeline_run_id, source_unique_id
HAVING COUNT(*) > 1
ORDER BY occurrences DESC, source_unique_id;
```

Dans le flux actuel, `source_unique_id` reçoit la propriété `unique_id` de l'objet Finding, et le Parser alimente actuellement cette propriété avec la CVE. Il ne constitue donc pas à lui seul une clé d'occurrence fiable. Cette requête détecte surtout des répétitions à examiner ; elle ne prouve pas automatiquement un doublon métier. La définition finale d'une clé de déduplication Finding reste **TO_VALIDATE**.

Pour voir les identifiants présents dans plusieurs runs :

```sql
SELECT
    source_unique_id,
    COUNT(DISTINCT pipeline_run_id) AS nb_runs,
    COUNT(*) AS occurrences
FROM finding
WHERE source_unique_id IS NOT NULL
GROUP BY source_unique_id
HAVING COUNT(DISTINCT pipeline_run_id) > 1
ORDER BY nb_runs DESC, occurrences DESC;
```

## 12. KRI RAS 9

### Règle actuelle

Le KRI est calculé avec la formule suivante :

```text
KRI =
100 × nombre de hostnames distincts éligibles ayant au moins un finding
Critical/Very High hors SLA et non false-positive
÷ nombre de hostnames distincts éligibles
```

Un hostname est éligible lorsqu'au moins une ligne associée vérifie ensemble :

- `sensitive = true` ;
- `authenticated_scan = true`.

Un hostname est qualifiant lorsqu'au moins une ligne associée vérifie ensemble :

- `severity_level` vaut `Critical` ou `Very High`, sans distinction de casse ;
- `overdue = true` ;
- `false_positive` n'est pas `true`.

Le grain métier actuel est le hostname distinct après `BTRIM`. Je n'utilise pas `DISTINCT server_id` pour ce calcul. Je filtre toujours un `pipeline_run_id` précis afin de ne pas mélanger plusieurs exécutions.

### Requête PostgreSQL validée

```sql
WITH servers_by_hostname AS (
    SELECT
        BTRIM(s.hostname) AS hostname,
        BOOL_OR(
            s.sensitive IS TRUE
            AND s.authenticated_scan IS TRUE
        ) AS eligible,
        BOOL_OR(
            LOWER(f.severity_level) IN ('critical', 'very high')
            AND f.overdue IS TRUE
            AND f.false_positive IS NOT TRUE
        ) AS qualifying
    FROM finding AS f
    JOIN server AS s
        ON s.server_id = f.server_id
    WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
      AND s.hostname IS NOT NULL
      AND BTRIM(s.hostname) <> ''
    GROUP BY BTRIM(s.hostname)
),
counts AS (
    SELECT
        COUNT(*) FILTER (WHERE eligible AND qualifying) AS numerator,
        COUNT(*) FILTER (WHERE eligible) AS denominator
    FROM servers_by_hostname
)
SELECT
    numerator,
    denominator,
    ROUND(100.0 * numerator / NULLIF(denominator, 0), 4) AS kri_percentage
FROM counts;
```

`NULLIF(denominator, 0)` évite une division par zéro. Si aucun hostname n'est éligible, `kri_percentage` vaut `NULL`.

Les deux `BOOL_OR` sont calculés séparément au grain hostname. L'éligibilité et le finding qualifiant peuvent donc être portés par deux lignes différentes ayant exactement le même hostname, conformément au calcul agrégé actuel du Parser.

### Pourquoi un calcul par `server_id` peut être différent

`server_id` est l'identifiant technique d'une ligne de la table `server`, pas le grain métier retenu pour le KRI. Dans un même run, un hostname peut correspondre à plusieurs lignes `server` si leur contenu technique diffère. De nouveaux objets serveur peuvent également être créés lors de chargements distincts.

Une agrégation avec `COUNT(DISTINCT server_id)` peut donc compter plusieurs fois le même hostname. Avec `BTRIM(hostname)` puis `GROUP BY hostname`, je reproduis le grain exact du calcul actuel.

## 13. Démo manager – 5 minutes

Pour une démonstration courte, je garde toujours le même `pipeline_run_id` dans les étapes 2 à 6.

### 1. Montrer les tables

```sql
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_type = 'BASE TABLE'
ORDER BY table_name;
```

**Ce que je montre :** les tables métier et les tables de traçabilité disponibles dans le schéma `public`.

**Phrase orale :** « J'ai structuré les findings autour des applications, des serveurs et des vulnérabilités, avec une traçabilité séparée des exécutions. »

### 2. Montrer les volumes

```sql
SELECT
    COUNT(*) AS findings,
    COUNT(DISTINCT application_id) AS linked_applications,
    COUNT(DISTINCT server_id) AS linked_servers,
    COUNT(DISTINCT vulnerability_id) AS linked_vulnerabilities
FROM finding
WHERE pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid;
```

**Ce que je montre :** le volume du run sélectionné et le nombre d'entités techniques liées.

**Phrase orale :** « Je filtre la démonstration sur un seul run afin que tous les chiffres correspondent à la même exécution. »

### 3. Montrer un finding complet avec application, serveur, CVE et remédiation

```sql
SELECT
    f.finding_id,
    a.auid,
    a.application_name,
    s.hostname,
    v.cve_code,
    f.severity_level,
    f.overdue,
    f.remediation_id,
    f.proposed_action,
    f.strategy_type,
    f.strategy_description,
    f.solution_links
FROM finding AS f
LEFT JOIN application AS a
    ON a.application_id = f.application_id
LEFT JOIN server AS s
    ON s.server_id = f.server_id
LEFT JOIN vulnerability AS v
    ON v.vulnerability_id = f.vulnerability_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
ORDER BY f.finding_id
LIMIT 20;
```

**Ce que je montre :** une vue lisible qui rassemble les informations réparties dans les quatre tables métier.

**Phrase orale :** « À partir d'un finding, je retrouve directement son application, son serveur, sa CVE et les informations de remédiation. »

### 4. Montrer les vulnérabilités les plus présentes

```sql
SELECT
    v.cve_code,
    v.title,
    COUNT(*) AS nb_findings
FROM finding AS f
JOIN vulnerability AS v
    ON v.vulnerability_id = f.vulnerability_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
GROUP BY v.vulnerability_id, v.cve_code, v.title
ORDER BY nb_findings DESC, v.cve_code
LIMIT 10;
```

**Ce que je montre :** les CVE qui affectent le plus de findings dans le run sélectionné.

**Phrase orale :** « Cette vue me permet d'identifier immédiatement les vulnérabilités les plus représentées dans le chargement. »

### 5. Montrer le KRI

```sql
WITH servers_by_hostname AS (
    SELECT
        BTRIM(s.hostname) AS hostname,
        BOOL_OR(
            s.sensitive IS TRUE
            AND s.authenticated_scan IS TRUE
        ) AS eligible,
        BOOL_OR(
            LOWER(f.severity_level) IN ('critical', 'very high')
            AND f.overdue IS TRUE
            AND f.false_positive IS NOT TRUE
        ) AS qualifying
    FROM finding AS f
    JOIN server AS s
        ON s.server_id = f.server_id
    WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
      AND s.hostname IS NOT NULL
      AND BTRIM(s.hostname) <> ''
    GROUP BY BTRIM(s.hostname)
),
counts AS (
    SELECT
        COUNT(*) FILTER (WHERE eligible AND qualifying) AS numerator,
        COUNT(*) FILTER (WHERE eligible) AS denominator
    FROM servers_by_hostname
)
SELECT
    numerator,
    denominator,
    ROUND(100.0 * numerator / NULLIF(denominator, 0), 4) AS kri_percentage
FROM counts;
```

**Ce que je montre :** le numerator, le denominator et le pourcentage calculés au grain hostname distinct.

**Phrase orale :** « Le KRI mesure la part des serveurs sensibles et scannés de manière authentifiée qui portent au moins un finding critique hors SLA et non false-positive. »

### 6. Conclure

```sql
SELECT
    pr.pipeline_run_id,
    pr.started_at,
    pr.run_status,
    pr.source_filename,
    pr.input_rows,
    pr.output_findings,
    COUNT(f.finding_id) AS persisted_findings
FROM pipeline_run AS pr
LEFT JOIN finding AS f
    ON f.pipeline_run_id = pr.pipeline_run_id
WHERE pr.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
GROUP BY
    pr.pipeline_run_id,
    pr.started_at,
    pr.run_status,
    pr.source_filename,
    pr.input_rows,
    pr.output_findings;
```

**Ce que je montre :** le statut final du run et le rapprochement entre `output_findings` et le nombre réellement persisté.

**Phrase orale :** « Je garde une traçabilité complète du chargement et je peux rapprocher le résultat annoncé par le pipeline avec les lignes réellement enregistrées. »

## 14. Bonnes pratiques

- Pour mes contrôles et mes démonstrations, je filtre toujours les analyses métier par un `pipeline_run_id` précis.
- Je ne supprime pas les anciens runs sans validation, car ils constituent l'historique des chargements.
- Je ne modifie pas directement les données PostgreSQL pour « corriger » un résultat ; je recherche d'abord la différence dans la source, le Parser ou le chargement.
- Lorsque je compare le Parser et PostgreSQL, j'utilise le même artefact et le même run.
- J'évite les `UPDATE` et les `DELETE` manuels. Une correction de données ou une politique de purge reste **TO_VALIDATE** avant exécution.
- Pour une démonstration, j'utilise uniquement des `SELECT`.
- Je fais attention aux `NULL` : ils peuvent représenter une relation non résolue, une donnée source absente ou un calcul non applicable.
- Je vérifie `run_status`, `input_rows`, `output_findings` et le nombre de lignes persistées avant de considérer un chargement comme contrôlé.
- Je ne confonds pas un identifiant technique (`finding_id`, `server_id`) avec une clé métier.

## 15. Cheat sheet finale

Avant d'exécuter les requêtes filtrées, je remplace l'UUID d'exemple par celui du run à analyser.

### Dernier run

```sql
SELECT pipeline_run_id, started_at, run_status, source_filename, input_rows, output_findings
FROM pipeline_run
ORDER BY started_at DESC
LIMIT 1;
```

### Nombre de findings du run

```sql
SELECT COUNT(*) AS nb_findings
FROM finding
WHERE pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid;
```

### Finding complet

```sql
SELECT
    f.finding_id, a.auid, s.hostname, v.cve_code,
    f.severity_level, f.overdue, f.remediation_id,
    f.proposed_action, f.strategy_type, f.strategy_description
FROM finding AS f
LEFT JOIN application AS a ON a.application_id = f.application_id
LEFT JOIN server AS s ON s.server_id = f.server_id
LEFT JOIN vulnerability AS v ON v.vulnerability_id = f.vulnerability_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
ORDER BY f.finding_id
LIMIT 20;
```

### Vulnérabilités les plus présentes

```sql
SELECT v.cve_code, COUNT(*) AS nb_findings
FROM finding AS f
JOIN vulnerability AS v ON v.vulnerability_id = f.vulnerability_id
WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
GROUP BY v.cve_code
ORDER BY nb_findings DESC
LIMIT 10;
```

### KRI

```sql
WITH servers_by_hostname AS (
    SELECT
        BTRIM(s.hostname) AS hostname,
        BOOL_OR(s.sensitive IS TRUE AND s.authenticated_scan IS TRUE) AS eligible,
        BOOL_OR(
            LOWER(f.severity_level) IN ('critical', 'very high')
            AND f.overdue IS TRUE
            AND f.false_positive IS NOT TRUE
        ) AS qualifying
    FROM finding AS f
    JOIN server AS s ON s.server_id = f.server_id
    WHERE f.pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
      AND s.hostname IS NOT NULL
      AND BTRIM(s.hostname) <> ''
    GROUP BY BTRIM(s.hostname)
),
counts AS (
    SELECT
        COUNT(*) FILTER (WHERE eligible AND qualifying) AS numerator,
        COUNT(*) FILTER (WHERE eligible) AS denominator
    FROM servers_by_hostname
)
SELECT
    numerator,
    denominator,
    ROUND(100.0 * numerator / NULLIF(denominator, 0), 4) AS kri_percentage
FROM counts;
```

### Doublons potentiels dans le run

```sql
SELECT pipeline_run_id, source_unique_id, COUNT(*) AS occurrences
FROM finding
WHERE pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid
  AND source_unique_id IS NOT NULL
GROUP BY pipeline_run_id, source_unique_id
HAVING COUNT(*) > 1
ORDER BY occurrences DESC;
```

### Relations manquantes

```sql
SELECT
    COUNT(*) FILTER (WHERE application_id IS NULL) AS without_application,
    COUNT(*) FILTER (WHERE server_id IS NULL) AS without_server,
    COUNT(*) FILTER (WHERE vulnerability_id IS NULL) AS without_vulnerability
FROM finding
WHERE pipeline_run_id = '00000000-0000-0000-0000-000000000000'::uuid;
```

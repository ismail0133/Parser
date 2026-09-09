Oui. Pour ta démo, il te faut un scénario simple :

**1. Je montre que la base est propre**

**2. Je lance le loader PostgreSQL**

**3. Je vérifie les tables dans pgAdmin**

**4. Je montre la traçabilité : pipeline_run, anomalies, artifacts**

---

# 1. Commandes terminal avant la démo

Dans VS Code / PowerShell, à la racine du projet :

```powershell
pytest
```

Puis :

```powershell
git diff --check
```

Puis :

```powershell
python -m compileall .
```

Objectif à dire à l’oral :

**Avant de charger les données, je vérifie que la suite de tests passe, que le code ne contient pas d’erreur de format et que les fichiers Python compilent correctement.**

---

# 2. Commandes PostgreSQL à exécuter avant chargement

Dans pgAdmin, vérifie que les migrations sont bien passées.

## Vérifier les tables importantes

```sql
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
```

Tu dois voir au minimum :

```text
application
server
application_server_relation
vulnerability
finding
pipeline_run
agent
agent_run
anomaly
artifact
```

---

## Vérifier l’index unique Server

```sql
SELECT
    indexname,
    indexdef
FROM pg_indexes
WHERE tablename = 'server';
```

Tu dois avoir un index unique sur `hostname`.

---

## Vérifier Artifact

```sql
SELECT
    column_name,
    data_type,
    is_nullable
FROM information_schema.columns
WHERE table_name = 'artifact'
ORDER BY ordinal_position;
```

Tu dois voir :

```text
pipeline_run_id
agent_run_id
row_count
sha256
```

---

# 3. Nettoyer la base pour une démo propre

Si c’est une base de test, fais :

```sql
TRUNCATE TABLE
    artifact,
    anomaly,
    finding,
    application_server_relation,
    server,
    vulnerability,
    application,
    agent_run,
    agent,
    pipeline_run
RESTART IDENTITY CASCADE;
```

À dire à l’oral :

**Je repars d’une base vide pour montrer un chargement complet et reproductible.**

---

# 4. Commande de chargement avec `obj_findings_enriched`

Comme tu veux charger la version enrichie, utilise :

```powershell
python scripts/load_obj_findings_to_postgres.py --applications output/obj_applications.jsonl --findings output/obj_findings_enriched.jsonl --servers output/obj_servers.jsonl --application-server-relations output/application_server_relations.jsonl --parser-result output/PARSER-Result-20260908-213424.json --parser-anomalies output/parser_anomalies.json
```

À dire à l’oral :

**Je charge les applications, les findings enrichis, les serveurs, les relations application-serveur, le résultat du Parser et les anomalies. Le but est d’avoir une persistance complète et traçable dans PostgreSQL.**

Si le loader bloque parce que le `ParserResult` pointe vers `obj_findings.jsonl`, utilise temporairement cette commande :

```powershell
python scripts/load_obj_findings_to_postgres.py --applications output/obj_applications.jsonl --findings output/obj_findings.jsonl --servers output/obj_servers.jsonl --application-server-relations output/application_server_relations.jsonl --parser-result output/PARSER-Result-20260908-213424.json --parser-anomalies output/parser_anomalies.json
```

Mais pour ta démo finale, le mieux est bien de charger `obj_findings_enriched.jsonl`.

---

# 5. Tests pgAdmin après chargement

Récupère d’abord le dernier `pipeline_run_id` :

```sql
SELECT
    pipeline_run_id,
    run_status,
    source_filename,
    input_rows,
    output_findings,
    error_count,
    warning_count,
    started_at,
    ended_at
FROM pipeline_run
ORDER BY started_at DESC
LIMIT 1;
```

Copie le `pipeline_run_id`.

Dans tes requêtes suivantes, remplace :

```text
TON_PIPELINE_RUN_ID
```

par l’id affiché.

---

# 6. Vérifier les Findings chargés

```sql
SELECT COUNT(*) AS total_findings
FROM finding
WHERE pipeline_run_id = 'TON_PIPELINE_RUN_ID';
```

Objectif :

```text
total_findings = output_findings
```

À dire :

**Je vérifie que le nombre de findings chargés correspond au nombre déclaré par le ParserResult.**

---

# 7. Vérifier les applications enrichies

```sql
SELECT
    COUNT(*) AS total_applications,
    COUNT(*) FILTER (WHERE application_name IS NULL) AS applications_sans_nom,
    COUNT(*) FILTER (WHERE application_name IS NOT NULL) AS applications_avec_nom
FROM application;
```

Puis :

```sql
SELECT
    application_id,
    auid,
    application_name,
    vital,
    continuity_level,
    application_manager,
    domain_manager,
    appsec,
    business_line
FROM application
ORDER BY application_id
LIMIT 20;
```

À dire :

**La table application est enrichie depuis APM. Le code AUID est conservé, et les informations métier comme le nom, le niveau de continuité ou les responsables applicatifs sont persistées.**

---

# 8. Vérifier les serveurs enrichis

```sql
SELECT
    COUNT(*) AS total_servers,
    COUNT(*) FILTER (WHERE operating_system IS NULL) AS servers_sans_os,
    COUNT(*) FILTER (WHERE operating_system IS NOT NULL) AS servers_avec_os
FROM server;
```

Puis :

```sql
SELECT
    server_id,
    hostname,
    operating_system,
    os_name,
    os_version,
    environment,
    environment_detail,
    sensitive,
    authenticated_scan
FROM server
ORDER BY server_id
LIMIT 20;
```

À dire :

**La table server est maintenant alimentée avec les données APM Server. L’OS complet n’est plus perdu, et les données issues des findings restent utilisées pour les champs métier comme l’environnement détaillé et la sensibilité.**

---

# 9. Vérifier les relations Application–Server

```sql
SELECT COUNT(*) AS total_relations
FROM application_server_relation;
```

Puis :

```sql
SELECT
    a.auid,
    a.application_name,
    s.hostname,
    s.operating_system
FROM application_server_relation r
JOIN application a
    ON a.application_id = r.application_id
JOIN server s
    ON s.server_id = r.server_id
ORDER BY a.auid, s.hostname
LIMIT 30;
```

À dire :

**Cette table permet de conserver la topologie APM : une application peut être liée à plusieurs serveurs, et un serveur peut être partagé par plusieurs applications.**

---

# 10. Vérifier les vulnérabilités

```sql
SELECT
    COUNT(*) AS total_vulnerabilities
FROM vulnerability;
```

Puis :

```sql
SELECT
    vulnerability_id,
    cve_code,
    title,
    severity_level,
    description,
    cvss_score
FROM vulnerability
ORDER BY vulnerability_id
LIMIT 20;
```

À dire :

**La table vulnerability centralise les CVE détectées et permet d’éviter de répéter les informations de vulnérabilité dans chaque finding.**

Tu peux ajouter :

**La partie Vulnerability reste un axe d’amélioration futur, notamment pour renforcer la normalisation des CVE et l’upsert conditionnel.**

---

# 11. Vérifier les anomalies Parser

```sql
SELECT
    anomaly_level,
    code,
    COUNT(*) AS total
FROM anomaly
GROUP BY anomaly_level, code
ORDER BY anomaly_level, total DESC;
```

Puis :

```sql
SELECT
    anomaly_id,
    pipeline_run_id,
    agent_run_id,
    finding_id,
    anomaly_level,
    code,
    message,
    details
FROM anomaly
WHERE pipeline_run_id = 'TON_PIPELINE_RUN_ID'
ORDER BY anomaly_id
LIMIT 20;
```

À dire :

**Les anomalies Parser sont maintenant persistées dans PostgreSQL. Elles sont reliées au même pipeline_run_id, ce qui permet d’auditer précisément un chargement.**

---

# 12. Vérifier les artifacts

```sql
SELECT
    artifact_type,
    filename,
    storage_path,
    row_count,
    sha256,
    pipeline_run_id,
    agent_run_id,
    created_at
FROM artifact
WHERE pipeline_run_id = 'TON_PIPELINE_RUN_ID'
ORDER BY artifact_type;
```

À dire :

**Chaque fichier utilisé dans le chargement est enregistré comme artifact avec son chemin, son hash SHA-256, son nombre de lignes quand il est calculable, et son pipeline_run_id. Cela permet de garantir la traçabilité du chargement.**

---

# 13. Requête finale de cohérence globale

C’est la meilleure requête pour ta démo :

```sql
SELECT
    pr.pipeline_run_id,
    pr.run_status,
    pr.input_rows,
    pr.output_findings,
    pr.error_count,
    pr.warning_count,
    COUNT(DISTINCT f.finding_id) AS findings_in_db,
    COUNT(DISTINCT an.anomaly_id) AS anomalies_in_db,
    COUNT(DISTINCT ar.artifact_id) AS artifacts_in_db
FROM pipeline_run pr
LEFT JOIN finding f
    ON f.pipeline_run_id = pr.pipeline_run_id
LEFT JOIN anomaly an
    ON an.pipeline_run_id = pr.pipeline_run_id
LEFT JOIN artifact ar
    ON ar.pipeline_run_id = pr.pipeline_run_id
WHERE pr.pipeline_run_id = 'TON_PIPELINE_RUN_ID'
GROUP BY
    pr.pipeline_run_id,
    pr.run_status,
    pr.input_rows,
    pr.output_findings,
    pr.error_count,
    pr.warning_count;
```

À dire :

**Cette requête donne une vision complète du run : son statut, le nombre de findings attendus, les findings réellement chargés, les anomalies et les artifacts associés. C’est la preuve que le pipeline PostgreSQL est traçable de bout en bout.**

---

# 14. Script oral court pour la démo

Tu peux dire :

**Ici, je montre la persistance PostgreSQL du pipeline. L’objectif n’est pas seulement de charger les données, mais de garantir une traçabilité complète du traitement.**

**Le loader prend en entrée les applications APM, les findings enrichis, les serveurs, les relations application-serveur, le résultat du Parser et les anomalies. Chaque chargement crée un pipeline_run_id unique.**

**Ensuite, les applications sont enrichies avec la source officielle APM, les serveurs sont chargés avec leurs informations système, et les relations Application–Server sont persistées.**

**Le statut du run vient désormais du ParserResult, donc PostgreSQL ne force plus artificiellement un SUCCESS. Les anomalies et les artifacts sont aussi rattachés au même pipeline_run_id, ce qui permet d’auditer précisément le chargement.**

**La dernière requête montre la cohérence globale : le nombre de findings chargés, les anomalies enregistrées et les fichiers associés au run.**

---

À la fin, tu peux dire :

**Cette étape valide que la couche PostgreSQL est prête pour l’industrialisation, car elle centralise les données métier, les données techniques et la traçabilité du pipeline dans un modèle relationnel contrôlé.**

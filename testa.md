Tu es encore sur la **même erreur** :

```text
ON CONFLICT (hostname)
```

mais PostgreSQL n’a toujours pas l’index/contrainte unique sur `server.hostname`.

Donc la migration `003_server_dimension.sql` **n’a pas été appliquée correctement** sur ta base.

Fais exactement ça dans **pgAdmin**, pas dans VS Code.

### 1. Vérifie d’abord si l’index unique existe

```sql
SELECT
    indexname,
    indexdef
FROM pg_indexes
WHERE tablename = 'server';
```

Si tu ne vois pas un index unique sur `hostname`, c’est pour ça que le loader plante.

### 2. Nettoie les 4 anciens serveurs invalides si non référencés

Lance :

```sql
SELECT
    s.server_id,
    s.hostname,
    COUNT(f.finding_id) AS linked_findings
FROM server AS s
LEFT JOIN finding AS f
    ON f.server_id = s.server_id
WHERE s.hostname IS NULL
   OR BTRIM(s.hostname) = ''
GROUP BY s.server_id, s.hostname;
```

Si `linked_findings = 0`, supprime-les :

```sql
DELETE FROM server
WHERE (hostname IS NULL OR BTRIM(hostname) = '')
  AND server_id NOT IN (
      SELECT DISTINCT server_id
      FROM finding
      WHERE server_id IS NOT NULL
  );
```

### 3. Vérifie les doublons hostname

```sql
SELECT
    BTRIM(hostname) AS normalized_hostname,
    ARRAY_AGG(server_id ORDER BY server_id) AS server_ids,
    COUNT(*) AS server_count
FROM server
WHERE hostname IS NOT NULL
  AND BTRIM(hostname) <> ''
GROUP BY BTRIM(hostname)
HAVING COUNT(*) > 1;
```

Si ça ne retourne rien, c’est bon.

### 4. Crée l’index unique manuellement

Comme le code fait `ON CONFLICT (hostname)`, il faut ça :

```sql
CREATE UNIQUE INDEX IF NOT EXISTS ux_server_hostname
ON server (hostname);
```

Puis vérifie :

```sql
SELECT
    indexname,
    indexdef
FROM pg_indexes
WHERE tablename = 'server';
```

### 5. Relance ta commande Python

```powershell
python scripts/load_obj_findings_to_postgres.py --applications output/obj_applications.jsonl --findings output/obj_findings.jsonl --servers output/obj_servers.jsonl --application-server-relations output/application_server_relations.jsonl --parser-result output/PARSER-Result-20260908-213424.json --parser-anomalies output/parser_anomalies.json
```

Le point clé : **tant que l’index unique sur `server(hostname)` n’existe pas dans PostgreSQL, ton `ON CONFLICT (hostname)` plantera toujours.**




Oui, là on voit le problème clairement.

Tu as seulement :

```text
server_pkey = UNIQUE sur server_id
idx_server_hostname = index simple sur hostname
```

Mais il manque un **UNIQUE** sur `hostname`.

Ton code fait sûrement :

```sql
ON CONFLICT (hostname)
```

Donc PostgreSQL exige une contrainte unique ou un index unique sur `hostname`.

## Fais ça dans pgAdmin

### 1. Vérifie d’abord les hostnames invalides

```sql
SELECT
    server_id,
    hostname
FROM server
WHERE hostname IS NULL
   OR BTRIM(hostname) = '';
```

S’il y a des lignes et qu’elles ne sont pas liées à des findings, supprime-les :

```sql
DELETE FROM server
WHERE (hostname IS NULL OR BTRIM(hostname) = '')
  AND server_id NOT IN (
      SELECT DISTINCT server_id
      FROM finding
      WHERE server_id IS NOT NULL
  );
```

---

### 2. Vérifie les doublons exacts

```sql
SELECT
    hostname,
    COUNT(*) AS total,
    ARRAY_AGG(server_id ORDER BY server_id) AS server_ids
FROM server
WHERE hostname IS NOT NULL
  AND BTRIM(hostname) <> ''
GROUP BY hostname
HAVING COUNT(*) > 1;
```

Si ça ne retourne rien, tu peux passer à l’étape suivante.

---

### 3. Crée la contrainte unique

```sql
ALTER TABLE server
ADD CONSTRAINT uq_server_hostname UNIQUE (hostname);
```

Si ça marche, vérifie :

```sql
SELECT
    indexname,
    indexdef
FROM pg_indexes
WHERE tablename = 'server';
```

Tu dois voir quelque chose comme :

```text
uq_server_hostname UNIQUE
```

---

### 4. Relance le loader

```powershell
python scripts/load_obj_findings_to_postgres.py --applications output/obj_applications.jsonl --findings output/obj_findings.jsonl --servers output/obj_servers.jsonl --application-server-relations output/application_server_relations.jsonl --parser-result output/PARSER-Result-20260908-213424.json --parser-anomalies output/parser_anomalies.json
```

Ton `idx_server_hostname` actuel n’est pas suffisant : c’est un index normal. Il faut vraiment `UNIQUE`.
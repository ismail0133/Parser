# RAW Finding Parser

## Objectif

Le parser transforme un fichier CSV RAW Finding en objets `obj_finding` structurés et validés avec Pydantic.

Le traitement reste local, déterministe et traçable. Il ne dépend d'aucun service externe et ne couvre ni l'Analyst, ni l'Orchestrator, ni PostgreSQL, ni les agents de remédiation.

Le CSV confidentiel est exclu du dépôt Git.

## Architecture du traitement

```text
RAW Finding CSV
        ↓
Loader et validation stricte des 34 colonnes
        ↓
Nettoyage technique des valeurs
        ↓
Normalisation et mapping
        ↓
Calculs documentés
        ↓
Enrichissement Application facultatif
        ↓
Validation et collecte des anomalies
        ↓
obj_finding et artefacts d'analyse
```

Les responsabilités sont réparties dans les modules suivants :

```text
src/
├── loaders/finding_loader.py
├── cleaning/finding_cleaner.py
├── mapping/finding_mapper.py
├── calculations/finding_calculations.py
├── enrichment/application_enricher.py
├── validation/finding_validator.py
├── models/finding.py
├── reporting/finding_analysis.py
└── parser.py
```

`MAPPING_RAW_TO_OBJ_FINDING.md` constitue la source de vérité pour le schéma RAW, les propriétés cibles et les règles confirmées.

## Installation

Depuis PowerShell, à la racine du projet :

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Si PowerShell bloque l'activation de l'environnement virtuel :

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Exécution sur 10 lignes

```powershell
python main.py --input "data/finding_list_fixed.csv" --limit 10
```

Cette commande permet de contrôler le schéma, les transformations et les artefacts avant une exécution complète.

## Exécution complète

```powershell
python main.py --input "data/finding_list_fixed.csv"
```

Les résultats sont écrits dans le dossier `output/`.

## Tests

Les tests utilisent uniquement des données synthétiques et ne dépendent pas du CSV confidentiel.

```powershell
python -m pytest -q
```

## Commandes de vérification sous Windows

### 4. Vérifier les 8 tâches KRI

Exécuter uniquement les tests du calcul global :

```powershell
python -m pytest tests/test_global_kri.py -v
```

Ces tests vérifient :

1. serveur sensible, scan authentifié et vulnérabilité Critical hors SLA ;
2. `authenticated_scan=False` ;
3. `authenticated_scan=None` ;
4. finding non overdue ;
5. finding faux positif ;
6. hostname distinct malgré plusieurs findings ;
7. aucun serveur éligible : `NOT_COMPUTABLE` avec `percentage=None` ;
8. catégories KRI pour les valeurs 0, 5, 20, 40 et 60.

### 5. Vérifier l'agrégation et les mismatches

```powershell
python -m pytest tests/test_kri_mismatch_analysis.py -v
```

### 6. Exécuter toute la suite de tests

```powershell
python -m pytest -q
```

Résultat attendu avec le commit `ff4440b` :

```text
55 passed
```

Si `test_loader_reads_34_columns_and_limit` échoue avec :

```text
AssertionError: assert 'PROPOSED_ACTION' == 'Proposed Owner'
```

vérifier dans `tests/test_loader_cleaning.py` que les index Python, qui commencent à zéro, sont bien les suivants :

```python
assert EXPECTED_COLUMNS[29] == "PROPOSED_ACTION"
assert EXPECTED_COLUMNS[30] == "Proposed Owner"
```

Ne pas modifier `EXPECTED_COLUMNS` dans `src/loaders/finding_loader.py` pour corriger cet échec : `PROPOSED_ACTION` est la 30e colonne du CSV et `Proposed Owner` la 31e.

### 7. Vérifier les fichiers ajoutés et modifiés

Afficher le résumé du commit :

```powershell
git show --stat --oneline ff4440b
```

Afficher exactement les lignes modifiées :

```powershell
git show ff4440b
```

Afficher seulement les noms et statuts des fichiers :

```powershell
git show --name-status --format="" ff4440b
```

### 8. Exécuter le Parser

Placer le CSV à cet emplacement :

```text
Parser\data\finding_list_fixed.csv
```

Exécuter le Parser sur 10 lignes :

```powershell
python main.py --input "data/finding_list_fixed.csv" --limit 10
```

Traiter ensuite tout le fichier :

```powershell
python main.py --input "data/finding_list_fixed.csv"
```

Afficher les artefacts générés :

```powershell
Get-ChildItem .\output
```

Afficher le dernier résultat du Parser :

```powershell
Get-Content (Get-ChildItem .\output\PARSER-Result-*.json |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1).FullName
```

## État actuel de validation

### Validation complète

La dernière exécution complète connue sur le fichier de validation actuel a produit les résultats suivants :

| Metric | Value |
|---|---:|
| Input rows | 29 999 |
| Output findings | 29 999 |
| Parsed success | 29 949 |
| Errors | 0 |
| Warnings | 50 |
| Duration | environ 26,5 s |

Ces valeurs correspondent à cette exécution de validation. Elles ne constituent pas des valeurs universelles pour tout fichier d'entrée.

Ces 50 warnings historiques provenaient d'une comparaison finding-level. Le grain métier est désormais confirmé au niveau serveur. Le nouveau contrôle regroupe les lignes par hostname et produit, selon le cas, `KRI_SERVER_MISMATCH`, `KRI_SOURCE_SERVER_INCONSISTENT` ou `KRI_SOURCE_SERVER_UNINTERPRETABLE`. Les quantités après migration doivent être mesurées sur un nouveau run réel.

### Validation d'un échantillon

Une validation RAW → `obj_finding` a été effectuée sur un échantillon représentatif de 20 findings afin de contrôler les transformations, les mappings, les calculs et les valeurs générées.

| Metric | Value |
|---|---:|
| Sample size | 20 |
| Fully valid | 19 |
| Warnings | 1 |
| Errors | 0 |
| TO_VALIDATE | 20 |

Les anciens résultats `TO_VALIDATE` précèdent les décisions métier désormais validées. Voir `TO_VALIDATE_PARSER.md` pour la séparation actuelle entre décisions validées, évolutions V2 et dépendances externes.

## Artefacts générés

Un timestamp unique `YYYYMMDD-HHMMSS` est partagé par les trois artefacts officiels d'une même exécution :

- `PARSER-Findings-<timestamp>.json` ;
- `PARSER-Finding_Analysis-<timestamp>.json` ;
- `PARSER-Finding_Analysis-<timestamp>.md`.

Les artefacts techniques suivants sont également conservés :

- `obj_findings.jsonl` ;
- `parser_anomalies.json` ;
- `parser_report.json`.

La validation d'échantillon produit :

- `PARSER-Sample_Validation.json` ;
- `PARSER-Sample_Validation.md`.

## Examiner les anomalies

Afficher la répartition des erreurs par `error_type` :

```powershell
python -c "import json,collections; d=json.load(open('output/parser_anomalies.json',encoding='utf-8')); print('=== ERRORS ==='); print(*collections.Counter(x['error_type'] for x in d if x['severity']=='ERROR').most_common(),sep='\n')"
```

Afficher la répartition des warnings par `error_type` :

```powershell
python -c "import json,collections; d=json.load(open('output/parser_anomalies.json',encoding='utf-8')); print('=== WARNINGS ==='); print(*collections.Counter(x['error_type'] for x in d if x['severity']=='WARNING').most_common(),sep='\n')"
```

Afficher le détail des erreurs :

```powershell
python -c "import json; d=json.load(open('output/parser_anomalies.json',encoding='utf-8')); print(*[x for x in d if x['severity']=='ERROR'],sep='\n')"
```

Afficher le détail des warnings :

```powershell
python -c "import json; d=json.load(open('output/parser_anomalies.json',encoding='utf-8')); print(*[x for x in d if x['severity']=='WARNING'],sep='\n')"
```

L'ancien contrôle `LAST_DETECTION_MONTH_MISMATCH` n'est plus actif. Une date `LAST_FOUND_DATE` techniquement valide est conservée même si son mois diffère du mois de reporting.

## Validation RAW → obj_finding

Le script `validate_sample_findings.py` sélectionne un échantillon représentatif et compare les lignes RAW aux objets générés sans modifier les données.

```powershell
python validate_sample_findings.py `
  --raw "data/finding_list_fixed.csv" `
  --findings "output/obj_findings.jsonl" `
  --output-dir "output" `
  --sample-size 20
```

Les statuts de contrôle sont :

- `OK` : transformation conforme à une règle confirmée ;
- `WARNING` : transformation exploitable nécessitant une attention ;
- `ERROR` : incohérence entre le RAW, la règle confirmée et l'objet produit ;
- `TO_VALIDATE` : règle métier ou propriété cible insuffisamment documentée.

Le script exige le même nombre de lignes RAW et d'objets JSONL afin de garantir la correspondance ordinale.

## KRI RAS 9

Le parser ne copie jamais directement la colonne source `KRI RAS 9` comme résultat calculé.

La validation source et le calcul sont réalisés au grain serveur, jamais par comparaison booléenne finding par finding.

Le KRI global est calculé au grain `hostname` distinct selon la formule documentée :

100 ×
(nombre de serveurs sensibles distincts, scannés en authentifié,
ayant au moins une vulnérabilité Critical/Very High hors SLA)
/
(nombre total de serveurs sensibles distincts scannés en authentifié)

Les faux positifs sont exclus.

L'interprétation documentée est :
- Perfect : 0 %
- Excellent : > 0 % et <= 10 %
- Satisfactory : > 10 % et <= 30 %
- Unsatisfactory : > 30 % et <= 50 %
- Critical : > 50 % et <= 100 %

L'agrégation globale est disponible dans `stats.kri_ras9.aggregate`. Les catégories historiques sont conservées. L'objectif métier est exposé séparément par `business_target_met = percentage < 30` : exactement 30 % n'atteint pas l'objectif.

Analyser les mismatches sur les artefacts d'un run complet :

```powershell
python analyze_kri_mismatches.py `
  --raw "data/finding_list_fixed.csv" `
  --findings "output/obj_findings.jsonl" `
  --anomalies "output/parser_anomalies.json" `
  --output-dir "output"
```

Cette commande génère :

- `PARSER-KRI_Mismatch_Analysis.json` ;
- `PARSER-KRI_Mismatch_Analysis.md`.

## ParserResult et retry

Chaque run génère `PARSER-Result-<timestamp>.json`. Ce contrat contient le statut global, les compteurs, les artefacts, le retry, l'enrichissement Application et les points ouverts.

`MAX_PARSE_ATTEMPTS` est fixé à 3. Un retry n'est possible que lorsqu'une anomalie est classée `ERROR_REMEDIABLE` et qu'une correction déterministe documentée est réellement appliquée entre deux tentatives. Les `WARNING`, `INFO` et `TO_VALIDATE` ne déclenchent aucun retry.

Les corrections déterministes actuelles sont déjà réalisées pendant le premier passage du pipeline. Aucun `ERROR` post-parse actuel ne possède de correction documentée supplémentaire ; le run normal expose donc `retry_count = 0` au lieu de répéter inutilement le même parsing.

Sans source APM/Application, l'état est :

```text
application_enrichment_status = SKIPPED_NO_SOURCE
```

Ce statut n'est pas un échec global.

## VALIDATED BUSINESS DECISIONS

- `unique_id = CVE`, sans contrainte d'unicité et sans fallback si le CVE est absent ;
- `remediation_id = REM_KEY_ID`, sinon `None` avec contrôle non bloquant ;
- `Proposed Owner` est conservé dans `ownership` ;
- `remediation_strategy.strategy_type` relève de l'Analyst et reste `None` sans source ;
- `KRI RAS 9` est au grain `SERVER / DISTINCT_HOSTNAME` avec objectif strict `< 30%`.

## DEFERRED / V2

- Routage automatique `Proposed Owner` : Infrastructure → APS, Développement → ADM.

## EXTERNAL DEPENDENCIES

- CIB APM : `WAITING_FOR_SOURCE` ;
- API LLM : `NOT_CONFIGURED` ;
- PostgreSQL : `NOT_CONFIGURED`, persistance `LOCAL_ONLY`.

Les points techniques encore ouverts sont détaillés dans `TO_VALIDATE_PARSER.md`.

## Limites actuelles

- Plusieurs findings peuvent partager le même `unique_id` car il correspond au CVE.
- Un `remediation_id` absent reste `None` et déclenche `MISSING_REMEDIATION_ID`.
- Le routage APS/ADM de `Proposed Owner` est différé en V2.
- `remediation_strategy.strategy_type` relève de l'Analyst.
- L'enrichissement Application est facultatif et dépend d'une source externe explicitement fournie au parser.
- La validation des formats reste limitée aux règles actuellement documentées et testées.

## Parser V1 Status

| Metric | Value |
|---|---|
| Status dans cet environnement | `NOT READY` |
| Date de vérification | 2026-08-12 |
| Tests | 77 passed |
| Application enrichment | `SKIPPED_NO_SOURCE` |
| KRI | Calcul et contrôle source au grain serveur ; objectif métier strict `< 30%` |
| Run final 29 999 lignes | Non exécuté ici : CSV confidentiel absent de cet environnement |
| Known TO_VALIDATE | Voir section précédente |
| Next step après validation V1 | PostgreSQL persistence |

Le statut pourra devenir `PARSER V1 = READY` après exécution du run complet sur le poste contenant `data/finding_list_fixed.csv`, génération de `ParserResult` et analyse documentée des warnings restants.


## Parser Agent V0

Le Parser Agent V0 orchestre le Parser V1 avec un workflow LangGraph déterministe :

- le Parser V1 reste le moteur unique pour le chargement, le nettoyage, le mapping, les calculs et la validation ;
- le Parser Agent valide la présence du fichier, lance le Parser une seule fois, lit `ParserResult` et décide de continuer ou de s'arrêter ;
- les warnings KRI serveur déclenchent l'analyse existante, sans retry supplémentaire ni modification de la valeur RAW ;
- le LLM est `NOT_CONFIGURED` et n'intervient dans aucun calcul ;
- PostgreSQL est `NOT_CONFIGURED` et la persistance reste `LOCAL_ONLY` ;
- la source CIB APM est `WAITING_FOR_SOURCE`, avec enrichissement `SKIPPED_NO_SOURCE` ;
- les points `TO_VALIDATE` sont transmis au futur Orchestrator sans être résolus automatiquement.

Installer les dépendances puis lancer l'Agent depuis PowerShell :

```powershell
python -m pip install -r requirements.txt
python parser_agent_main.py --input "data/finding_list_fixed.csv"
```

Choisir un autre répertoire de sortie si nécessaire :

```powershell
python parser_agent_main.py `
  --input "data/finding_list_fixed.csv" `
  --output-dir "output"
```

Le Parser Agent produit notamment :

- `PARSER-Agent_Result-<timestamp>.json` pour le futur Orchestrator ;
- `PARSER-Agent_Report-<timestamp>.md` pour une lecture humaine ;
- les artefacts habituels du Parser V1 ;
- les rapports `PARSER-KRI_Mismatch_Analysis.*` lorsqu'un warning KRI serveur est présent.

Test-Path "data\finding_list_fixed.csv"
Le résultat attendu est :
True
Lance ensuite le Parser Agent :
python parser_agent_main.py --input "data/finding_list_fixed.csv"
Avec un répertoire de sortie explicite :
python parser_agent_main.py `
  --input "data/finding_list_fixed.csv" `
  --output-dir "output"
5. Vérifier les artefacts
Get-ChildItem .\output
Afficher le dernier résultat Agent :
Get-Content (Get-ChildItem .\output\PARSER-Agent_Result-*.json |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1).FullName
Afficher le dernier rapport Markdown :
Get-Content (Get-ChildItem .\output\PARSER-Agent_Report-*.md |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1).FullName

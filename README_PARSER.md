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

Les 50 warnings observés correspondent à `KRI_MISMATCH`. Ils doivent être analysés et conservés comme éléments traçables. Un mismatch indique une différence entre la valeur KRI provenant de la source et la condition KRI calculée par le parser. Il ne doit pas être corrigé automatiquement tant que la règle métier officielle ne détermine pas quelle valeur fait foi.

### Validation d'un échantillon

Une validation RAW → `obj_finding` a été effectuée sur un échantillon représentatif de 20 findings afin de contrôler les transformations, les mappings, les calculs et les valeurs générées.

| Metric | Value |
|---|---:|
| Sample size | 20 |
| Fully valid | 19 |
| Warnings | 1 |
| Errors | 0 |
| TO_VALIDATE | 20 |

`TO_VALIDATE: 20` ne signifie pas que les 20 objets sont incorrects. Le script applique à chaque cas des contrôles dont la règle reste volontairement ouverte, notamment :

- la propriété cible et la règle métier de `Proposed Owner` ;
- la déduction de `remediation_strategy.strategy_type` ;
- la formule d'agrégation globale du KRI RAS 9.

Un objet peut donc être conforme sur tous les champs calculables tout en contenant un ou plusieurs contrôles `TO_VALIDATE`.

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

La condition booléenne au niveau d'un finding est implémentée à partir des éléments confirmés :

- serveur sensible ;
- scan authentifié par défaut, sauf indication explicite contraire ;
- sévérité `Critical` ou `Very High` ;
- finding hors SLA ;
- faux positif exclu.

Le résultat peut être `COMPUTED` ou `NOT_COMPUTABLE` lorsque des données nécessaires manquent.

Lorsque la valeur source est exploitable, elle est comparée au résultat calculé. Une différence produit un warning `KRI_MISMATCH`. Le parser conserve cette différence sans remplacer automatiquement la source ou le calcul.

La formule d'agrégation globale du KRI RAS 9 n'est pas confirmée et reste dans `TO_VALIDATE`.

## TO_VALIDATE restant

- formule officielle de `unique_id` ;
- formule de fallback de `remediation_id` lorsque `REM_KEY_ID` est absent ;
- propriété cible et règle métier de la colonne source `Proposed Owner` ;
- règles de déduction de `remediation_strategy.strategy_type` ;
- formule d'agrégation globale du KRI RAS 9 ;
- regex hostname exacte ;
- politique CVE finale ;
- formats exhaustifs des dates ;
- type final et séparateur de `solution_links` ;
- règle de préséance de l'enrichissement Application.

Ces éléments ne sont ni inventés ni complétés automatiquement.

## Limites actuelles

- Le parser ne génère aucun `unique_id` tant que sa formule officielle n'est pas disponible.
- Un `remediation_id` absent reste non calculé faute de formule de fallback confirmée.
- `Proposed Owner` est reconnu dans le schéma RAW, mais sa cible métier reste ouverte.
- `remediation_strategy.strategy_type` reste `None` sans règle documentée.
- Le calcul KRI disponible est une condition booléenne par finding, pas une agrégation globale.
- L'enrichissement Application est facultatif et dépend d'une source externe explicitement fournie au parser.
- La validation des formats reste limitée aux règles actuellement documentées et testées.

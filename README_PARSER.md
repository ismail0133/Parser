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

La condition au niveau d'un finding est calculée à partir de :
- serveur sensible ;
- scan authentifié par défaut, sauf indication explicite contraire ;
- sévérité Critical ou Very High ;
- finding hors SLA ;
- faux positif exclu.

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

L'agrégation globale est disponible dans `stats.kri_ras9.aggregate`. La comparaison de la colonne source avec la condition individuelle reste traçable par `KRI_MISMATCH` tant que le grain exact de la valeur source n'est pas confirmé.

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

## TO_VALIDATE restant

- formule officielle de `unique_id` ;
- formule de fallback de `remediation_id` lorsque `REM_KEY_ID` est absent ;
- propriété cible et règle métier de la colonne source `Proposed Owner` ;
- règles de déduction de `remediation_strategy.strategy_type` ;
- grain exact de la valeur source `KRI RAS 9` utilisée pour la comparaison ;
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

## Parser V1 Status

| Metric | Value |
|---|---|
| Status dans cet environnement | `NOT READY` |
| Date de vérification | 2026-08-12 |
| Tests | 43 passed |
| Application enrichment | `SKIPPED_NO_SOURCE` |
| KRI | Condition finding et agrégation globale implémentées ; analyse des 50 mismatches à exécuter sur les artefacts réels |
| Run final 29 999 lignes | Non exécuté ici : CSV confidentiel absent de cet environnement |
| Known TO_VALIDATE | Voir section précédente |
| Next step après validation V1 | PostgreSQL persistence |

Le statut pourra devenir `PARSER V1 = READY` après exécution du run complet sur le poste contenant `data/finding_list_fixed.csv`, génération de `ParserResult` et analyse documentée des warnings restants.


python analyze_kri_mismatches.py `
  --raw "data/finding_list_fixed.csv" `
  --findings "output/obj_findings.jsonl" `
  --anomalies "output/parser_anomalies.json" `
  --output-dir "output"


1. unique_id du FindingQuelle est la règle officielle permettant de construire le unique_id d’un obj_finding ?Est-ce un identifiant déjà disponible dans une source ou doit-il être généré ?S’il doit être généré, quels champs doivent être utilisés ?Et surtout, est-ce que cet identifiant doit rester identique pour le même finding entre plusieurs exécutions du Parser ?

2. remediation_id lorsque REM_KEY_ID est absentActuellement, lorsque REM_KEY_ID est renseigné, je l’utilise comme remediation_id.Dans le cas où REM_KEY_ID est vide ou absent, quel comportement doit être appliqué ?Doit-on laisser remediation_id = null ou existe-t-il une règle de fallback officielle basée sur une autre donnée ?

3. Mapping de Proposed OwnerLa colonne Proposed Owner existe bien dans le fichier RAW Finding.Je voudrais savoir à quelle propriété exacte de obj_finding elle doit correspondre.Est-ce le propriétaire de la remédiation, le propriétaire du finding, une équipe cible ou une autre information métier ?Je souhaite connaître le mapping exact afin de ne pas affecter cette colonne arbitrairement.

4. remediation_strategy.strategy_typeEst-ce au Parser de renseigner remediation_strategy.strategy_type, ou est-ce une information qui doit être déterminée plus tard par l’Analyst ?Si c’est au Parser de le renseigner, quelles sont les valeurs possibles et quelle règle permet de déterminer le bon strategy_type ?

5. Grain de la colonne RAW KRI RAS 9La formule globale du KRI RAS 9 est déjà connue.Ma question concerne uniquement la valeur KRI RAS 9 présente sur chaque ligne du fichier RAW Finding.

Que représente exactement cette valeur :

une information au niveau du finding ?

une information au niveau du serveur ?

une information au niveau de l’application ?

ou une valeur déjà agrégée ?

J’ai actuellement 50 KRI_MISMATCH, tous identifiés comme GRAIN_MISMATCH. J’ai donc besoin de connaître le niveau exact auquel la valeur RAW doit être comparée avec le KRI recalculé.

6. Accès CIB APM.CSV Pour finaliser l’enrichissement Application prévu dans le Parser, j’aurais également besoin :

 du fichier Excel CIB APM exporté au format CSV.

Cela me permettra de construire/utiliser les obj_applications et d’effectuer l’enrichissement des obj_findings conformément à la spécification.

7. Accès à une API d’IA générative pour les agentsPour commencer l’implémentation des agents IA et leur orchestration avec LangChain/LangGraph, j’aurais également besoin de savoir quelle API d’IA générative / quel modèle LLM est autorisé et disponible dans l’environnement BNP.

J’aurais notamment besoin de connaître :

le fournisseur ou service LLM autorisé ;

l’endpoint/API à utiliser ;

le mode d’authentification ;

le ou les modèles disponibles ;

les éventuelles limitations de tokens, quotas ou rate limits ;

les règles de sécurité concernant les données envoyées au modèle ;

si les agents doivent utiliser un modèle commun ou si plusieurs modèles sont prévus selon les agents.

Cet accès sera nécessaire pour implémenter la couche agentique, notamment le Parser Agent puis les autres agents prévus dans l’architecture multi-agents.


python analyze_kri_mismatches.py `
  --raw "data/finding_list_fixed.csv" `
  --findings "output/obj_findings.jsonl" `
  --anomalies "output/parser_anomalies.json" `
  --output-dir "output"

# RAW Finding Parser

Parser local et traçable du CSV RAW Finding vers `obj_finding` JSONL. Il n'accède à aucun service externe et ne contient aucun autre agent.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Test sur 10 lignes

```powershell
python main.py --input "data/finding_list_fixed.csv" --limit 10
```

Avec l'interpréteur de l'environnement virtuel Windows :

```powershell
.\.venv\Scripts\python.exe main.py --input "data/finding_list_fixed.csv" --limit 10
```

## Exécution complète

```powershell
python main.py --input "data/finding_list_fixed.csv"
```

Les fichiers sont écrits dans `output/`. Le CSV confidentiel n'est ni inclus ni requis par les tests.

## Tests synthétiques

```powershell
python -m pytest -q
```

## Artefacts d'une exécution

Un timestamp unique `YYYYMMDD-HHMMSS` est partagé par les trois artefacts officiels :

- `PARSER-Findings-<timestamp>.json`
- `PARSER-Finding_Analysis-<timestamp>.json`
- `PARSER-Finding_Analysis-<timestamp>.md`

Les artefacts techniques `obj_findings.jsonl`, `parser_anomalies.json` et `parser_report.json` sont conservés.

## TO_VALIDATE restant

- formule de `unique_id` (aucune propriété générée) ;
- formule de fallback de `remediation_id` ;
- éventuelle correspondance `Colonne1` → `PROPOSED OWNER` / `ownership` ;
- règles de `remediation_strategy.strategy_type` ;
- formule d'agrégation du KRI RAS 9 (la condition booléenne par finding est calculée avec scan authentifié par défaut) ;
- regex hostname exacte, politique CVE finale et formats exhaustifs de dates ;
- type final/séparateur de `solution_links` et préséance de l'enrichissement Application.

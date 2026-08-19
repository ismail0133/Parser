# Obj Application V1

Le Parser Application construit un référentiel canonique depuis le même CSV RAW
que le Parser Finding, sans modifier ce dernier :

```text
RAW Finding CSV -> contrôles par AUID -> obj_applications.jsonl
```

## Mapping confirmé par le schéma RAW

| RAW | obj_application |
|---|---|
| `AUID` | `auid` |
| `CODE_APP` | `code_app` |
| `Legacy APP ID` | `trigram` |
| `Application Name` | `application_name` |
| `AppSec Profile` | `appsec` |
| `Business Lines` | `business_line` |
| `Production Domain Manager` | `production_domain_manager` |
| `Production Manager` | `production_manager` |

`CODE_APP` reste distinct du trigram et ne remplace jamais un AUID absent.
Le format AUID réutilise la validation existante `AP[0-9]+`.

## Canonisation et conflits

Les vides techniques sont normalisés à `None`. Pour chaque AUID et chaque
propriété, une valeur non vide unique est conservée. Plusieurs valeurs distinctes
produisent `APPLICATION_CONFLICT` et la propriété canonique reste `None` : aucune
première/dernière valeur, mode ou valeur majoritaire n'est sélectionné.

Une ligne sans AUID produit `MISSING_AUID` et reste exclue. Un AUID non vide ne
respectant pas la politique de format existante produit `INVALID_AUID`, mais est
conservé dans le référentiel afin de ne pas perdre une Application réellement
présente dans le RAW. `CODE_APP` n'est jamais utilisé comme fallback.

## Exécution complète

```powershell
python scripts/build_obj_applications.py `
  --input "data/finding_list_fixed.csv" `
  --findings "output/obj_findings.jsonl" `
  --output-dir "output"
```

Le script n'applique aucune limite et affiche `df.shape` et
`df.columns.tolist()`. Il produit :

- `output/obj_applications.jsonl` ;
- `output/application_anomalies.json` ;
- `output/application_analysis.json`.

Le rapprochement avec `obj_findings` est facultatif via `--findings` et ne
modifie jamais les Findings.

## Champs non couverts par le CSV V1

Les statuts, priorités Application, valeurs numériques AppSec/vital/CIAT,
`vital`, `cis`, `strategic`, continuité, sous-business line et autres managers ne
sont ni déduits ni ajoutés au modèle V1. Ils restent à traiter avec une source
autoritaire future, notamment CIB APM.

# Obj Application

## Source et périmètre

La source est le CSV APM. Seules les applications référencées par
`obj_findings.jsonl` sont traitées. La clé de rapprochement est `AUID`, après
`strip()` et conversion en majuscules; seuls les AUID au format `^AP[0-9]+$`
sont utilisés.

## Mapping

| CSV APM | obj_application |
|---|---|
| `AUID` | `auid` |
| `Legacy APP ID` | `trigram` |
| `DAP Name` | `name` |

Ces trois colonnes sont obligatoires. Aucun fallback vers une autre colonne
n'est appliqué.

## Lignes multiples

Plusieurs lignes ayant le même AUID et les mêmes données applicatives produisent
un seul `obj_application`. Si `Legacy APP ID` ou `DAP Name` contient plusieurs
valeurs distinctes pour un même AUID, aucune valeur arbitraire n'est choisie et
aucune application n'est générée pour cet AUID. Le rapport indique l'AUID, le
champ et le nombre de valeurs distinctes sans exposer les valeurs.

La règle documentaire de suffixage `-1`, `-2` reste **TO_VALIDATE** et n'est pas
appliquée aux répétitions de lignes APM.

## Exécution

```powershell
python scripts/build_obj_applications.py `
  --input "data/REAL_APM_FILE.csv" `
  --findings "output/obj_findings.jsonl" `
  --output-dir "output"
```

Fichiers produits :

- `output/obj_applications.jsonl`
- `output/application_anomalies.json`
- `output/application_analysis.json`

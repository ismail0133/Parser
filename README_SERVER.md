# Obj Server

## Source et périmètre

`obj_servers.jsonl` est construit depuis les lignes du CSV APM dont l'`AUID`,
normalisé et validé, est présent dans `obj_findings.jsonl`.

## Mapping confirmé

| CSV APM | obj_server |
|---|---|
| `Host` | `hostname` |
| `OS Build` | `operating_system` |
| `Environment` | `environment` |

Aucun fallback n'est appliqué. Aucune source APM n'est confirmée pour
`sensitive` ou `authenticated_scan`; ces propriétés conservent les valeurs par
défaut du modèle Server existant. `Asset ID` n'a aucun contrat correspondant
dans le modèle ou la base actuels et reste **TO_VALIDATE**.

Les serveurs sont consolidés par la valeur `Host` après trim, sans déclarer
`hostname` unique globalement. Une incohérence non vide sur `OS Build` ou
`Environment` empêche la génération du serveur concerné et est reportée sans
exposer les valeurs. La relation N:N observée est exportée séparément.

## Exécution

```powershell
python scripts/build_obj_servers.py `
  --input "data/CIB_APM_Dashboard.csv" `
  --findings "output/obj_findings.jsonl" `
  --output-dir "output"
```

Fichiers produits :

- `output/obj_servers.jsonl`
- `output/application_server_relations.jsonl`
- `output/server_anomalies.json`
- `output/server_analysis.json`


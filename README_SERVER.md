# Obj Server

## Source et périmètre

`obj_servers.jsonl` est construit depuis les lignes du CSV APM dont l'`AUID`,
normalisé et validé, est présent dans `obj_findings.jsonl`.

## Mapping confirmé

| CSV APM | obj_server |
|---|---|
| `Host` | `hostname` |
| `OS Build` | `operating_system` |
| `OS Build` | `os_name`, `os_version` (dérivation contrôlée) |
| `Environment` | `environment` |

Le contrat APM contient uniquement `hostname`, `operating_system`, `os_name`,
`os_version` et `environment`. `environment_detail`, `sensitive` et
`authenticated_scan` n'en font pas partie; le modèle historique utilisé dans
Finding reste inchangé.

La dérivation OS sépare la valeur avant son premier token commençant par un
chiffre. Elle préserve toujours `operating_system`; si la séparation n'est pas
fiable, `os_name` et `os_version` restent `null`. Aucun fallback n'est appliqué.
`Asset ID` n'a aucun contrat correspondant dans le modèle ou la base actuels et
reste **TO_VALIDATE**.

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

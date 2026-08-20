```bash
# 1. Lancer le Parser
python main.py \
  --input "/chemin/vers/fichier_confidentiel.csv" \
  --output-dir "/chemin/vers/parser-output"
```

```bash
# 2. Retrouver les artefacts générés
find "/chemin/vers/parser-output" -type f \
  \( -name "parser_anomalies.json" -o -name "PARSER-Result-*.json" \) \
  -print
```

```bash
# 3. Afficher uniquement un résumé anonymisé des anomalies ERROR
# Aucun numéro de ligne, identifiant, valeur source ou autre donnée métier n’est affiché.
python - "/chemin/vers/parser-output/parser_anomalies.json" <<'PY'
import json
import sys
from collections import Counter

with open(sys.argv[1], encoding="utf-8") as f:
    anomalies = json.load(f)

errors = [a for a in anomalies if a.get("severity") == "ERROR"]
counts = Counter(a.get("error_type", "UNKNOWN_ERROR") for a in errors)

for error_type, count in sorted(counts.items()):
    print(f"{error_type} : {count} occurrences")
PY
```

```bash
# 4. Afficher error_type, occurrences, messages et champs, sans valeurs métier ni lignes
python - "/chemin/vers/parser-output/parser_anomalies.json" <<'PY'
import json
import sys
from collections import defaultdict

with open(sys.argv[1], encoding="utf-8") as f:
    anomalies = json.load(f)

summary = defaultdict(lambda: {
    "count": 0,
    "messages": set(),
    "fields": set(),
})

for anomaly in anomalies:
    if anomaly.get("severity") != "ERROR":
        continue

    error_type = anomaly.get("error_type", "UNKNOWN_ERROR")
    summary[error_type]["count"] += 1

    if anomaly.get("message"):
        summary[error_type]["messages"].add(str(anomaly["message"]))

    if anomaly.get("field"):
        summary[error_type]["fields"].add(str(anomaly["field"]))

for error_type in sorted(summary):
    item = summary[error_type]
    print(f"{error_type} : {item['count']} occurrences")
    print("  champ(s) :", ", ".join(sorted(item["fields"])) or "non renseigné")
    print("  message(s) :", " | ".join(sorted(item["messages"])) or "non renseigné")
PY
```

```bash
# 5. Afficher les compteurs et le statut depuis le dernier PARSER-Result
RESULT_FILE="$(find "/chemin/vers/parser-output" -type f \
  -name "PARSER-Result-*.json" -print | sort | tail -n 1)"

python - "$RESULT_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    result = json.load(f)

print("error_count :", result.get("errors"))
print("warning_count :", result.get("warnings"))
print("Parser status :", result.get("status"))
PY
```

Résumé minimal à transmettre :

```bash
python - \
  "/chemin/vers/parser-output/parser_anomalies.json" \
  "$RESULT_FILE" <<'PY'
import json
import sys
from collections import Counter

with open(sys.argv[1], encoding="utf-8") as f:
    anomalies = json.load(f)

with open(sys.argv[2], encoding="utf-8") as f:
    result = json.load(f)

counts = Counter(
    a.get("error_type", "UNKNOWN_ERROR")
    for a in anomalies
    if a.get("severity") == "ERROR"
)

for error_type, count in sorted(counts.items()):
    print(f"{error_type} : {count} occurrences")

print("error_count :", result.get("errors"))
print("warning_count :", result.get("warnings"))
print("Parser status :", result.get("status"))
PY
```
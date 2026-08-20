$errors = Get-Content .\output\parser_anomalies.json -Raw |
    ConvertFrom-Json |
    Where-Object severity -eq "ERROR"

$errors |
    Group-Object error_type |
    Sort-Object Name |
    ForEach-Object {
        "$($_.Name) : $($_.Count) occurrences"
    }



    $errors |
    Group-Object error_type |
    Sort-Object Name |
    ForEach-Object {
        $fields = ($_.Group.field | Where-Object { $_ } | Sort-Object -Unique) -join ", "
        $messages = ($_.Group.message | Where-Object { $_ } | Sort-Object -Unique) -join " | "

        "$($_.Name) : $($_.Count) occurrences"
        "  Champ(s) : $fields"
        "  Message(s) : $messages"
    }


    python -c "import json,collections; data=json.load(open(r'output\parser_anomalies.json',encoding='utf-8')); errors=[x for x in data if x.get('severity')=='ERROR']; counts=collections.Counter(x.get('error_type','UNKNOWN_ERROR') for x in errors); print(*[f'{k} : {v} occurrences' for k,v in sorted(counts.items())],sep='\n')"



    python -c "import json,collections; d=json.load(open(r'output\parser_anomalies.json',encoding='utf-8')); e=[x for x in d if x.get('severity')=='ERROR']; g=collections.defaultdict(lambda:{'n':0,'f':set(),'m':set()}); [(g[x.get('error_type','UNKNOWN')]['f'].add(str(x.get('field',''))),g[x.get('error_type','UNKNOWN')]['m'].add(str(x.get('message',''))),g[x.get('error_type','UNKNOWN')].update(n=g[x.get('error_type','UNKNOWN')]['n']+1)) for x in e]; print(*[f'{k}: {v[\"n\"]} occurrences\nChamp(s): {\", \".join(sorted(v[\"f\"]))}\nMessage(s): {\" | \".join(sorted(v[\"m\"]))}' for k,v in sorted(g.items())],sep='\n\n')"
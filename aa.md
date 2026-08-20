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



    python -c 'import json,collections; d=json.load(open(r"output\parser_anomalies.json",encoding="utf-8")); c=collections.Counter((x.get("error_type","UNKNOWN"),x.get("field",""),x.get("message","")) for x in d if x.get("severity")=="ERROR"); print(*["%s : %s occurrences | Champ : %s | Message : %s" % (k[0],n,k[1],k[2]) for k,n in sorted(c.items())],sep="\n")'
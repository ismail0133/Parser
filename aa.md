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
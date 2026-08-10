# Mapping corrigé — RAW FINDING → `obj_finding`

Ce mapping applique strictement les règles communiquées depuis le document « Definition - CSV Finding file ». Les statuts utilisés sont `CONFIRMED`, `CALCULATED`, `FALLBACK`, `NOT_USED` et `TO_VALIDATE`.

| # | source_column | target_obj_finding_property | category | transformation | status | comment |
|---:|---|---|---|---|---|---|
| 1 | `Month` | `as_of_date` | NORMALIZED | Convertir en date. Compléter les parties absentes avec la date courante : année, mois ou jour selon le format reçu. | CONFIRMED | Nom source confirmé par le CSV réel. Ajouter une anomalie `INFO` dès qu'une partie est déduite. Exemples documentaires : `May` → `2026-05-13`, `5-2` → `2026-05-02` pour une date courante au 13/06/2026. |
| 2 | `REM_KEY_ID` | `remediation_id` | COPY / CALCULATED | Copier la valeur nettoyée lorsqu'elle est présente. Si elle est absente, la calculer uniquement avec la formule officielle. | CONFIRMED / TO_VALIDATE | La cible et la copie sont confirmées. La formule de fallback dépend du document « Object - Finding object specification » encore absent. `Init only = Yes`. |
| 3 | `STATUS_REM` | aucune | NOT USED | Ne pas mapper. | NOT_USED | Explicitement non utilisé. |
| 4 | `HOSTNAME` | `hostname` | NORMALIZED | Nettoyer et valider selon la regex/documentation hostname. | CONFIRMED | La propriété cible est confirmée. La regex exacte devra être extraite de la documentation avant validation stricte. |
| 5 | `OPERATING_SYSTEM` | `server.os_name`, `server.os_version` | NORMALIZED | Séparer sur `_` ; texte → `os_name`, valeur numérique → `os_version`. | CONFIRMED | Exemple : `RHEL_9.6` → `RHEL`, `9.6`. |
| 6 | `AFFECTED_PLATFORMS` | `server.os_name`, `server.os_version` | FALLBACK | Compléter uniquement les propriétés OS non déterminées depuis `OPERATING_SYSTEM`. | FALLBACK | Ne doit jamais écraser une valeur obtenue depuis `OPERATING_SYSTEM`. |
| 7 | `AUID` | `application.auid` | NORMALIZED | Nettoyer et valider avec `AP[0-9]+`. | CONFIRMED | Source prioritaire de l'AUID applicatif. |
| 8 | `ENVIRONMENT` | `server.environment_detail`, `server.environment` | NORMALIZED / CALCULATED | Appliquer exclusivement la table documentaire d'environnement. | CONFIRMED | Valeur non répertoriée → `None` et anomalie ; aucune valeur par défaut. |
| 9 | `CODE_APP` | `application.auid` | FALLBACK | Utiliser seulement si `AUID` ne permet pas d'obtenir un `application.auid` valide. | FALLBACK | Ne jamais remplacer un AUID valide. La valeur de fallback doit aussi respecter le format AUID attendu. |
| 10 | `CVE` | `cve` | NORMALIZED | Nettoyer et valider selon le format CVE documenté. | CONFIRMED | Une valeur invalide génère une anomalie sans interrompre le fichier. |
| 11 | `title` | `cve_detail.title` | COPY | Copier après nettoyage technique. | CONFIRMED | Nullable selon le modèle final. |
| 12 | `PRIORITY` | `priority` | NORMALIZED | `PR1 → 1`, `PR2 → 2`, `PR3 → 3`, `PR4 → 4`. | CONFIRMED | Toute autre valeur → `None` et anomalie. Ne pas enrichir depuis Application. |
| 13 | `AFFECTED_PRODUCTS_REVIEWED` | `affected_component` | COPY | Copier après nettoyage technique. | CONFIRMED | Mapping direct confirmé. |
| 14 | `PRODUCT` | `affected_product` | COPY | Copier après nettoyage technique. | CONFIRMED | Mapping direct confirmé. |
| 15 | `XTRACT_PATH` | `target` | COPY | Copier le chemin après nettoyage technique uniquement. | CONFIRMED | Tous les préfixes sont acceptés. Une valeur absente donne `target = None`. Aucune ownership n'est déduite du chemin. |
| 16 | `ABSOLUTE_FIRST_FOUND_DATE` | `first_detection` | NORMALIZED | Convertir en date ; source prioritaire. | CONFIRMED | Si vide ou invalide, tenter le fallback `FIRST_FOUND_DATE`. |
| 17 | `FIRST_FOUND_DATE` | `first_detection` | FALLBACK | Utiliser uniquement lorsque `ABSOLUTE_FIRST_FOUND_DATE` est vide, absent ou inexploitable. | FALLBACK | Si aucune source ne permet de définir `first_detection`, anomalie `ERROR`. |
| 18 | `LAST_FOUND_DATE` | `last_detection` | NORMALIZED | Convertir en date et contrôler la cohérence du mois avec `as_of_date`. | CONFIRMED | Une incohérence produit une anomalie. |
| 19 | `AGE` | `age` | CALCULATED | Vérifier la cohérence avec `as_of_date - first_detection`. Si absent/incohérent, recalculer avec `current_date - first_detection`, en jours entiers. | CALCULATED | Un recalcul produit une anomalie `INFO`. La valeur CSV n'est pas acceptée aveuglément. |
| 20 | `SLA` | `sla` | CALCULATED | Conserver une valeur exploitable ; si absente, appliquer uniquement les règles documentées de déduction. | CALCULATED | P4 → 90 j ; application vitale + production + Very High → 90 j ; application vitale + production + High → 180 j ; Very High → 180 j ; High → 365 j ; sinon `None`. Déduction → `INFO`. |
| 21 | `SOLUTION_LINKS` | `cve_details.solution_links` | COPY | Copier après nettoyage technique. | CONFIRMED | Le type collection/chaîne devra respecter le modèle final, sans inventer de séparateur. |
| 22 | `Legacy APP ID` | `application.trigram` | COPY | Copier après nettoyage technique. | CONFIRMED | Mapping direct confirmé. |
| 23 | `Application Name` | `application.name` | COPY / ENRICHED | Utiliser la valeur source disponible ; l'enrichissement Application peut compléter selon son contrat. | CONFIRMED | Si une source Application autoritaire est chargée, sa règle de préséance devra être explicitée. |
| 24 | `AppSec Profile` | `application.appsec` | NORMALIZED / ENRICHED | Mapper le profil applicatif ; enrichir depuis Application lorsqu'une source autoritaire est disponible. | CONFIRMED | Nécessaire notamment pour `server.sensitive` et le SLA. Les valeurs hors référentiel génèrent une anomalie. |
| 25 | `Business Lines` | aucune | NOT USED | Ne pas mapper. | NOT_USED | Explicitement non utilisé. |
| 26 | `IT Sub Cluster` | `business_line` | COPY / ENRICHED | Copier la valeur disponible ; enrichir depuis Application si la source existe. | CONFIRMED | Mapping cible confirmé ; absence d'une source Application n'autorise aucune invention. |
| 27 | `Production Domain Manager` | aucune | NOT USED | Ne pas mapper. | NOT_USED | Explicitement non utilisé. |
| 28 | `Production Manager` | aucune | NOT USED | Ne pas mapper. | NOT_USED | Explicitement non utilisé. |
| 29 | `SEVERITY_LEVEL` | `severity_level` | NORMALIZED | Copier/nettoyer puis valider selon le référentiel de sévérité. | CONFIRMED | Sert au calcul du SLA et du KRI. Valeur inconnue → anomalie. |
| 30 | `PROPOSED_ACTION` | `proposed_action` | COPY / NORMALIZED | Copier après nettoyage et appliquer uniquement le référentiel documentaire disponible. | CONFIRMED | Mapping cible confirmé. |
| 31 | `Proposed Owner` | propriété cible à confirmer | TO_VALIDATE | Reconnaître la colonne dans le schéma source, mais ne pas la mapper actuellement. | TO_VALIDATE | Le nom source est confirmé par le CSV réel. La propriété cible et la règle métier ne sont pas confirmées ; aucune valeur n'est inventée. |
| 32 | `KRI RAS 9` | aucune copie directe ; résultat KRI calculé | CALCULATED / CONTROL | Utiliser la colonne uniquement pour confirmer le résultat calculé. | CALCULATED | Calcul documentaire : serveur sensible, scan authentifié, vulnérabilité Critical/Very High hors SLA, faux positifs exclus. Les sources exactes du scan authentifié et certains détails du calcul doivent rester `TO_VALIDATE` tant qu'ils ne sont pas disponibles. |
| 33 | `Action Plan` | `remediation_strategy.description`, `remediation_strategy.strategy_type`, `false_positive`, `false_positive_to_confirm` | COPY / CALCULATED | Description = valeur non vide. Calculer les indicateurs false positive sans distinction de casse. Déduire le type de stratégie uniquement selon la règle officielle. | CONFIRMED / CALCULATED / TO_VALIDATE | `false_positive = true` si égal à `False positive`. `false_positive_to_confirm = true` si contient `False positive to be confirmed`, sauf valeur explicitement fausse. La règle de `strategy_type` reste à fournir. |
| 34 | `ETA` | `eta` | NORMALIZED | Une valeur absente reste `None`. Convertir uniquement une valeur non vide selon les formats documentés. Forcer à `None` lorsque `false_positive = true`. | CONFIRMED | Seule une valeur présente mais invalide produit `INVALID_DATE`. Aucune date ne doit être inventée. |

## Calculs transverses confirmés

### Table d'environnement

| valeur source | `server.environment_detail` | `server.environment` |
|---|---|---|
| `PRODUCTION` | `PRODUCTION` | `PRODUCTION` |
| `PRE-PRODUCTION` | `PRE-PRODUCTION` | `PRODUCTION` |
| `BACKUP` | `BACKUP` | `PRODUCTION` |
| `INTEGRATION / PRE-RECETTE` | `INTEGRATION` | `NON-PRODUCTION` |
| `RECETTE` | `RECETTE` | `NON-PRODUCTION` |
| `DEVELOPPEMENT` | `DEVELOPPEMENT` | `NON-PRODUCTION` |
| `QUALIFICATION` | `QUALIFICATION` | `NON-PRODUCTION` |

### `server.sensitive`

```text
server.sensitive = (
    application.appsec ∈ {P4, P3}
    OR application.vital ∈ {GROUPE, BUSINESS}
    OR application.cis = true
) AND server.environment_detail ∈ {PRODUCTION, BACKUP}
```

Sinon, `server.sensitive = false`.

### Faux positifs

- `false_positive = true` si `Action Plan` est exactement `False positive`, sans distinction de casse ; sinon `false`.
- `false_positive_to_confirm = true` si `Action Plan` contient `False positive to be confirmed`, sans distinction de casse, sauf indication explicitement fausse.
- Lorsque `false_positive = true`, `eta = None` et les autres propriétés nullable concernées sont mises à `None` uniquement selon la règle documentaire applicable.

### SLA

Ordre des règles documentées :

1. `application.appsec = P4` → 90 jours.
2. Application vitale/active + environnement `PRODUCTION` + `Very High` → 90 jours.
3. Application vitale/active + environnement `PRODUCTION` + `High` → 180 jours.
4. `Very High` → 180 jours.
5. `High` → 365 jours.
6. Sinon → `None`.

Une déduction produit une anomalie `INFO`.

### `overdue`

```text
overdue = age > sla
```

Le résultat reste `None` si `age` ou `sla` est `None`.

## Statuts réellement encore à valider

```python
FIELDS_TO_VALIDATE = [
    "unique_id_formula",
    "remediation_id_fallback_formula",
    "proposed_owner_target_property_and_business_rule",
    "remediation_strategy.strategy_type_rules",
    "hostname_exact_regex",
    "cve_exact_validation_policy",
    "accepted_input_date_formats",
    "eta_accepted_formats",
    "solution_links_final_type_or_separator",
    "application_enrichment_precedence",
    "application.vital_source",
    "application.cis_source",
    "authenticated_scan_source",
    "kri_ras9_complete_formula_and_output_property",
]
```

`unique_id` ne doit recevoir aucun UUID aléatoire. `remediation_id` ne doit pas être calculé en l'absence de sa formule officielle. `Proposed Owner` reste ignorée tant que sa propriété cible et sa règle métier ne sont pas confirmées.

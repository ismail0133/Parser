# Parser — Business decision status

## VALIDATED

- `unique_id = CVE`. Plusieurs findings peuvent partager le même CVE ; aucune unicité n'est imposée.
- `remediation_id = REM_KEY_ID`. Si la source est absente : `None` et warning non bloquant `MISSING_REMEDIATION_ID`, sans fallback.
- `Proposed Owner` est conservé dans `ownership` lorsqu'il est présent.
- `remediation_strategy.strategy_type` relève de l'Analyst. Le Parser laisse la propriété à `None` sans source explicite.
- Le grain de `KRI RAS 9` est `SERVER / DISTINCT_HOSTNAME`.
- Le dénominateur KRI contient les serveurs sensibles avec scan authentifié.
- Le numérateur contient les serveurs éligibles avec au moins un finding Critical/Very High hors SLA et non explicitement faux positif.
- L'objectif métier est strict : `percentage < 30`. À `30.00%`, l'objectif n'est pas atteint.

## DEFERRED / V2

- Routage automatique `Proposed Owner` :
  - Infrastructure → APS
  - Développement → ADM
- Le Parser V1 conserve uniquement la valeur RAW et ne classe pas automatiquement APS/ADM.

## EXTERNAL DEPENDENCIES

- CIB APM : `WAITING_FOR_SOURCE` (API ou CSV).
- API IA générative : `NOT_CONFIGURED`.
- PostgreSQL : `NOT_CONFIGURED` ; persistance actuelle `LOCAL_ONLY`.

## TO_VALIDATE restant

- regex hostname exacte ;
- politique finale de validation CVE ;
- formats exhaustifs des dates et ETA ;
- type final ou séparateur de `solution_links` ;
- préséance de l'enrichissement Application ;
- sources `application.vital`, `application.cis` et `authenticated_scan`.

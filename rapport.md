# TO_VALIDATE — Parser Findings V1

## 1. Objectif

Ce document centralise les points du Parser V1 qui ne peuvent pas être finalisés sans validation métier ou sans information complémentaire.

Un point `TO_VALIDATE` ne signifie pas que le Parser est en erreur.

Cela signifie que la règle nécessaire n'est pas suffisamment définie pour être implémentée sans faire d'hypothèse.

Principe appliqué :

```text
Si la règle est confirmée → je l'implémente.

Si la règle est absente ou ambiguë → je conserve la donnée et je marque TO_VALIDATE.

Je n'invente aucune règle métier.
```

---

# 2. Points actuellement TO_VALIDATE

## 2.1 `unique_id`

### Ce que je sais

`obj_finding` prévoit un champ :

```text
unique_id
```

Mais la formule officielle permettant de générer cet identifiant n'est pas disponible dans les éléments actuellement exploités.

Je ne génère donc pas arbitrairement un UUID, un hash ou une concaténation de champs.

### Ce que je dois savoir exactement

Je dois obtenir une réponse aux questions suivantes :

1. Est-ce que `unique_id` est obligatoire pour chaque `obj_finding` ?
2. Est-ce que cet identifiant existe déjà dans une source ?
3. S'il doit être généré, quelle est la formule officielle ?
4. Quels champs doivent entrer dans cette formule ?
5. L'identifiant doit-il rester identique entre deux exécutions du Parser pour le même finding ?
6. Quelle est la portée de son unicité :
   - fichier ?
   - application ?
   - serveur ?
   - CVE ?
   - toute la base ?
7. Si une information du finding change, le `unique_id` doit-il changer ou rester identique ?

### Question principale à poser

> **Quelle est la règle officielle de génération du `unique_id` d'un `obj_finding`, et doit-il rester stable d'un run à l'autre ?**

### Pourquoi j'en ai besoin

Cette information sera importante notamment pour :

- identifier un finding de manière stable ;
- éviter les doublons ;
- gérer les réinsertions en base ;
- permettre le suivi d'un finding dans le temps.

### Une fois la réponse obtenue

Je devrai :

```text
mettre à jour le mapping
→ implémenter la génération
→ ajouter les tests
→ documenter la règle
→ retirer unique_id de TO_VALIDATE
```

---

# 2.2 `remediation_id` — fallback

### Ce que je sais

Le mapping actuel principal est :

```text
REM_KEY_ID
    ↓
remediation_id
```

Lorsque `REM_KEY_ID` est disponible, il est utilisé.

Le problème concerne uniquement le cas où :

```text
REM_KEY_ID = vide / absent
```

Je ne dispose pas actuellement d'une règle officielle permettant de générer une valeur de remplacement.

### Ce que je dois savoir exactement

1. `remediation_id` est-il obligatoire ?
2. Que doit faire le Parser lorsque `REM_KEY_ID` est vide ?
3. Doit-on laisser :

```text
remediation_id = null
```

ou utiliser une autre colonne ?
4. Existe-t-il une formule officielle de fallback ?
5. Si oui, quels champs composent cette formule ?
6. Cette valeur doit-elle être stable d'un run à l'autre ?

### Question principale à poser

> **Si `REM_KEY_ID` est absent, quelle valeur doit-on utiliser pour `remediation_id` ? Est-ce qu'on laisse `null` ou existe-t-il une règle de fallback officielle ?**

### À ne pas faire

Ne pas inventer par exemple :

```text
hostname + CVE
```

ou :

```text
AUID + CVE + date
```

sans validation.

---

# 2.3 `Proposed Owner`

### Ce que je sais

Le fichier RAW Finding contient réellement la colonne :

```text
Proposed Owner
```

La donnée existe donc.

Ce qui n'est pas confirmé est **sa destination métier exacte dans `obj_finding`**.

### Ce que je dois savoir exactement

1. Que représente exactement `Proposed Owner` ?
2. Est-ce :
   - le propriétaire du finding ?
   - le propriétaire de la remédiation ?
   - une équipe APS ?
   - une équipe applicative ?
   - une proposition faite par un processus précédent ?
3. Dans quelle propriété de `obj_finding` cette valeur doit-elle être stockée ?
4. Doit-elle faire partie de :

```text
remediation_strategy
```

ou d'une autre structure ?
5. La valeur RAW doit-elle être conservée telle quelle ?
6. Une normalisation des noms d'équipes / owners est-elle nécessaire ?
7. Existe-t-il une autre source ayant priorité sur `Proposed Owner` ?

### Question principale à poser

> **À quelle propriété métier de `obj_finding` correspond exactement la colonne RAW `Proposed Owner`, et quelle règle doit être appliquée pour l'utiliser ?**

### Une fois la réponse obtenue

Je pourrai fixer le mapping :

```text
Proposed Owner
      ↓
propriété cible confirmée
```

et ajouter les tests correspondants.

---

# 2.4 `remediation_strategy.strategy_type`

### Ce que je sais

L'objet Finding contient ou prévoit une structure de stratégie de remédiation avec :

```text
remediation_strategy.strategy_type
```

Mais aucune règle suffisamment précise ne me permet actuellement de déterminer automatiquement la valeur de `strategy_type`.

### Ce que je dois savoir exactement

1. Quelles sont les valeurs autorisées pour `strategy_type` ?
2. Existe-t-il une liste fermée ?

Par exemple, je dois savoir si le domaine ressemble à :

```text
PATCH
UPGRADE
CONFIGURATION
WORKAROUND
...
```

ou à quelque chose de complètement différent.

Je ne dois pas créer cette liste moi-même.

3. Quelle information permet de choisir le `strategy_type` ?
4. Est-ce une donnée :
   - directement présente dans le RAW ?
   - déduite de `PROPOSED_ACTION` ?
   - déduite de `Action Plan` ?
   - produite plus tard par l'Analyst ?
5. Est-ce réellement le Parser qui doit calculer cette valeur ?
6. Ou est-ce l'Agent Analyst qui doit la déterminer plus tard ?

### Question principale à poser

> **Qui doit définir `remediation_strategy.strategy_type` et selon quelle règle ? Est-ce une valeur produite par le Parser ou par l'Analyst ?**

### Point important

Si cette information appartient réellement à l'Analyst, le Parser ne doit pas essayer de l'inventer.

Dans ce cas, il pourra simplement produire :

```text
strategy_type = null
```

et laisser l'Analyst compléter cette information.

---

# 2.5 `KRI RAS 9 source comparison grain`

### Ce que je sais

La formule globale du **KRI RAS 9** est connue :

```text
100 ×
nombre de serveurs sensibles scannés en authentifié
avec au moins une vulnérabilité Critical / Very High hors SLA
/
nombre total de serveurs sensibles scannés en authentifié
```

Les vulnérabilités explicitement déclarées faux positif sont exclues du calcul concerné.

Le Parser possède maintenant également le calcul global.

Le problème restant n'est donc PAS la formule du KRI.

Le problème concerne la colonne RAW :

```text
KRI RAS 9
```

Lors du run réel :

```text
50 KRI_MISMATCH
50 GRAIN_MISMATCH
0 correction automatique possible
```

### Ce que je ne sais pas

Je ne sais pas encore précisément ce que représente **une valeur de la colonne `KRI RAS 9` sur une ligne du CSV**.

Il faut déterminer son grain.

### Ce que je dois savoir exactement

La valeur RAW `KRI RAS 9` correspond-elle à :

```text
un finding ?
```

ou :

```text
un serveur ?
```

ou :

```text
une application ?
```

ou :

```text
un résultat agrégé ?
```

ou à un autre niveau ?

Je dois également savoir :

1. Quel est le type métier de la valeur RAW ?
   - booléen ?
   - indicateur ?
   - pourcentage ?
   - catégorie ?
2. Peut-on réellement comparer cette valeur ligne par ligne à une condition calculée sur un `obj_finding` ?
3. Ou faut-il uniquement comparer le KRI après agrégation par serveur ?
4. À quel moment cette colonne est-elle calculée dans le processus source ?
5. Sur quel périmètre est-elle calculée ?
6. Quelle période couvre-t-elle ?
7. Est-elle calculée avant ou après exclusion des faux positifs ?

### Question principale à poser

> **Que représente exactement la valeur de la colonne `KRI RAS 9` sur chaque ligne du RAW Finding : un indicateur au niveau finding, serveur, application ou une valeur agrégée ? Et à quel niveau devons-nous la comparer avec le KRI recalculé ?**

### Situation actuelle

Le Parser conserve donc :

```text
50 KRI_MISMATCH
→ WARNING
→ GRAIN_MISMATCH
→ aucune correction automatique
```

Ces warnings ne doivent pas être supprimés tant que le grain de la valeur source n'est pas confirmé.

---

# 3. Dépendance en attente — `obj_applications`

> Ce point n'est pas considéré comme une erreur du Parser ni comme une règle métier à inventer.

### Situation

Le Parser Agent prévoit un enrichissement :

```text
obj_findings
      +
obj_applications
      ↓
obj_findings enrichis
```

Mais je ne dispose pas encore de la source APM / Application nécessaire.

Le Parser indique donc actuellement :

```text
application_enrichment_status = SKIPPED_NO_SOURCE
```

### Ce qu'il me faut

Je dois récupérer :

```text
CSV / source APM Applications
```

et idéalement les spécifications :

```text
Definition - CSV APM file
Definition - Application object specification
```

### Ce que je dois savoir une fois les documents disponibles

1. Quel est le schéma exact de `obj_application` ?
2. Quelle colonne permet de rattacher un finding à une application ?
3. AUID est-il toujours la clé principale de rapprochement ?
4. Quel fallback utiliser lorsque AUID est absent ?
5. Quelles propriétés Application doivent enrichir `obj_finding` ?
6. Quelle source est prioritaire lorsqu'une valeur existe déjà dans le RAW Finding ?
7. Que faire si aucune application correspondante n'est trouvée ?
8. Comment gérer plusieurs correspondances éventuelles ?

### Question principale

> **Pouvez-vous me fournir le fichier/source APM et la spécification officielle de `obj_application` afin que je puisse finaliser l'enrichissement Application du Parser ?**

---

# 4. Résumé des questions à poser à l'équipe

| Sujet | Question principale |
|---|---|
| `unique_id` | Quelle est la formule officielle et doit-il rester stable d'un run à l'autre ? |
| `remediation_id` | Que faire lorsque `REM_KEY_ID` est absent ? |
| `Proposed Owner` | À quelle propriété métier correspond cette colonne et quelle règle de mapping appliquer ? |
| `strategy_type` | Qui produit cette valeur, Parser ou Analyst, et selon quelle règle ? |
| `KRI RAS 9` | Quel est le grain exact de la valeur présente dans le RAW ? |
| Application | Pouvez-vous fournir la source APM et la spécification `obj_application` ? |

---

# 5. Questions courtes pour une réunion

Si je dois poser les questions oralement, je peux utiliser directement :

### Finding ID

> Pour le `unique_id`, est-ce qu'on a une formule officielle permettant d'identifier durablement un finding entre plusieurs runs ?

### Remediation ID

> Si `REM_KEY_ID` est vide, est-ce qu'on laisse `remediation_id` à null ou il existe un fallback métier officiel ?

### Proposed Owner

> La colonne `Proposed Owner` doit être mappée vers quelle propriété exacte de l'objet Finding ?

### Strategy Type

> `remediation_strategy.strategy_type`, est-ce au Parser de le déterminer ou est-ce une décision de l'Analyst ? Et quelles sont les valeurs possibles ?

### KRI

> Pour les 50 `KRI_MISMATCH`, j'ai confirmé qu'ils sont tous des `GRAIN_MISMATCH`. J'ai besoin de savoir ce que représente exactement la colonne `KRI RAS 9` dans le CSV : finding, serveur ou indicateur agrégé ?

### Application

> Pour terminer l'enrichissement Application, il me manque la source APM et la définition officielle de `obj_application`. Est-ce qu'on peut me les fournir ?

---

# 6. État actuel

```text
Parser V1
Status : READY_WITH_KNOWN_WARNINGS

Input findings  : 29 999
Output findings : 29 999
Errors          : 0

KRI warnings :
50 KRI_MISMATCH
→ 50 GRAIN_MISMATCH
→ 0 automatiquement corrigeables

Application enrichment :
SKIPPED_NO_SOURCE
```

Les éléments présents dans ce document doivent rester ouverts jusqu'à obtention d'une validation métier ou de la source nécessaire.

Aucune hypothèse ne doit être transformée en règle de production sans validation.
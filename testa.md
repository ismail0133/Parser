Proposition d’évolution de la base PostgreSQL
                                                 Suivi du cycle de vie des vulnérabilités
1. Contexte
La première phase du projet a permis de construire et de valider le socle Data nécessaire au traitement industriel des vulnérabilités. À ce stade, on a mis en place la transformation des Findings RAW avec le Parser, l’application des règles métier, la génération d’objets structurés, la persistance réelle dans PostgreSQL, les relations entre Finding, Application, Server et Vulnerability, ainsi que les contrôles d’intégrité et la validation du calcul KRI entre le Parser et PostgreSQL.
La base permet donc aujourd’hui de stocker correctement les résultats d’un run et de conserver plusieurs exécutions grâce au pipeline_run_id. La prochaine évolution pertinente consiste à ne plus utiliser PostgreSQL uniquement comme une base de stockage, mais comme une base permettant de suivre le cycle de vie d’une vulnérabilité dans le temps.
2. Problématique
Un cas métier important est celui d’une vulnérabilité détectée sur un serveur, remédiée, puis observée de nouveau lors d’une campagne suivante.
Mois N
CVE-XXXX détectée sur SERVER01
↓
Remédiation
↓
La vulnérabilité disparaît

Mois N+1
↓
Même CVE détectée à nouveau sur SERVER01
Aujourd’hui, les deux campagnes peuvent être retrouvées grâce aux différents pipelines_run_id. En revanche, la base ne dit pas encore explicitement qu’une vulnérabilité avait été remédiée puis qu’elle a réapparu. L’objectif de cette évolution est précisément de construire cette information.
3. Idée proposée
On propose de distinguer deux concepts complémentaires : l’observation et le cycle de vie.
3.1 L’observation
Le finding actuel représente ce qui a été observé pendant un run donné. Il doit être conservé tel quel, car il constitue la photographie précise d’une campagne.
Run septembre
Finding #1
SERVER01
CVE-2026-XXXX
Critical
3.2 Le cycle de vie
Au-dessus des Findings, on peut ajouter une notion représentant une vulnérabilité suivie dans le temps sur un asset donné. Cette couche ne remplace pas les Findings : elle les relie entre eux pour reconstruire l’historique.
SERVER01 + CVE-2026-XXXX

Première détection : 01/06
Dernière détection : 05/09
Statut              : REOPENED
Nombre d’occurrences : 4
Nombre de réouvertures : 1
4. Gestion des statuts
À chaque nouvelle campagne, la base pourrait comparer le run courant avec le run précédent et classifier automatiquement chaque vulnérabilité suivie.
NEW : La vulnérabilité apparaît pour la première fois.
PERSISTENT : Elle était présente au précédent run et elle est toujours présente.
REMEDIATED : Elle était présente auparavant mais n’est plus observée après remédiation.
REOPENED : Elle avait été remédiée ou avait disparu, puis elle réapparaît.
Des statuts comme FALSE_POSITIVE ou ACCEPTED_RISK pourraient également être conservés si ces états sont confirmés par les règles métier.
5. Exemple de suivi historique
Campagne	Présence	Statut
Janvier	Oui	NEW
Février	Oui	PERSISTENT
Mars	Non	REMEDIATED
Avril	Non	REMEDIATED
Mai	Oui	REOPENED
Juin	Oui	PERSISTENT
Avec cette logique, la base peut indiquer directement qu’une vulnérabilité est revenue après une première remédiation.
9. Indicateurs possibles sans IA
Cette évolution apporte déjà une valeur métier importante indépendamment de l’accès aux agents IA. PostgreSQL pourrait permettre de répondre directement à des questions comme :
•	Combien de nouvelles vulnérabilités sont apparues ce mois-ci ?
•	Combien sont encore présentes depuis le mois précédent ?
•	Combien ont été remédiées ?
•	Combien sont revenues après remédiation ?
•	Quels CVE reviennent le plus souvent ?
•	Quels serveurs ou applications concentrent le plus de vulnérabilités récurrentes ?
•	Combien de temps une vulnérabilité reste ouverte ?
•	Quel est le délai moyen de remédiation ?
•	Quel est le délai moyen avant réapparition ?
•	Quel est le taux de récurrence après remédiation ?
•	Comment le KRI évolue-t-il d’une campagne à l’autre ?
10. Vues métier
Pour rendre la base plus simple à exploiter, on peut également créer des vues PostgreSQL orientées métier. L’objectif est d’éviter de reconstruire des requêtes complexes pour chaque consultation.
•	v_current_open_vulnerabilities
•	v_new_vulnerabilities
•	v_persistent_vulnerabilities
•	v_remediated_vulnerabilities
•	v_reopened_vulnerabilities
•	v_kri_history
•	v_remediation_effectiveness
11. Pourquoi cette évolution est intéressante
Cette proposition est cohérente avec l’architecture actuelle car elle ne remet pas en cause le travail déjà réalisé. Elle l’enrichit en ajoutant une dimension historique et métier au-dessus de la persistance existante.
Aujourd’hui

RAW
↓
Parser
↓
PostgreSQL
↓
Finding / Application / Server / Vulnerability
L’évolution proposée serait :
RAW
↓
Parser
↓
PostgreSQL
↓
Historique des runs
↓
Cycle de vie des vulnérabilités
↓
Remédiation
↓
KPI / KRI / récurrence
↓
Agents IA
La couche agentique pourra ainsi s’appuyer plus tard sur une donnée qui contient déjà l’historique, le contexte et les indicateurs nécessaires au raisonnement.
12. Ordre de réalisation
1.	Valider la clé métier permettant d’identifier une même vulnérabilité entre deux campagnes.
2.	Comparer deux pipeline_run.
3.	Identifier automatiquement les états NEW, PERSISTENT, REMEDIATED et REOPENED.
4.	Construire l’historique.
5.	Créer les vues métier.
6.	Ajouter les KPI de récurrence et d’efficacité de la remédiation.
7.	Préparer ensuite ces informations pour les futurs agents.
Conclusion
Le Parser et PostgreSQL constituent aujourd’hui une fondation Data. L’étape suivante serait de faire de PostgreSQL une base historique du cycle de vie des vulnérabilités.
Idée centrale : ne pas écraser les anciennes vulnérabilités, mais conserver chaque observation et utiliser l’historique des campagnes pour déterminer si une vulnérabilité est nouvelle, persistante, remédiée ou réouverte.

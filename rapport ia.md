# Rapport de réunion  
## Gestion du contexte et optimisation des agents IA

### 1. Objectif de la réunion

La réunion portait principalement sur les bonnes pratiques à appliquer lors de l’utilisation de modèles IA et d’agents, notamment autour de la **gestion du contexte**, des **tokens**, des **sessions**, des **MCP**, des **Skills**, de l’**orchestration des agents** et des techniques d’optimisation.

L’objectif était de comprendre comment mieux organiser le contexte envoyé au modèle afin d’éviter une consommation inutile de tokens et de rendre les agents plus efficaces.

---

## 2. Gestion de la fenêtre de contexte

Les modèles disposent d’une **fenêtre de contexte limitée**, pouvant aller jusqu’à un volume très important de tokens selon le modèle utilisé.

Cependant, il ne faut pas remplir cette fenêtre inutilement. Plus le contexte envoyé est important, plus :

- la consommation de tokens augmente ;
- le coût peut augmenter ;
- le modèle doit traiter davantage d’informations ;
- des informations inutiles peuvent se retrouver dans le contexte.

Il est donc important de donner au modèle uniquement les informations nécessaires pour réaliser la tâche demandée.

Pour une petite modification dans un projet, il n’est par exemple pas nécessaire de faire relire tout le projet au modèle. Il faut essayer de limiter le contexte aux fichiers, informations et règles réellement concernés.

---

## 3. Gestion des sessions

Les sessions doivent également être gérées correctement.

Lorsqu’une conversation devient très longue, une grande quantité d’informations peut être renvoyée au modèle à chaque nouvelle requête.

Pour des petites tâches ou lorsqu’un sujet change, il peut donc être préférable de travailler dans une nouvelle session avec uniquement le contexte nécessaire.

Lorsqu’une session doit être conservée, il est possible d’utiliser des mécanismes de **compaction** afin de réduire la taille de la conversation tout en gardant les informations importantes.

---

## 4. Contexte du projet

Pour éviter d’expliquer de nouveau l’ensemble du projet dans chaque nouvelle session, il est possible de conserver un fichier dédié contenant les informations essentielles du projet.

L’exemple évoqué pendant la réunion est un fichier de type **CLAUDE.md**.

Ce fichier peut servir à conserver notamment :

- la compréhension générale du projet ;
- l’architecture ;
- les technologies utilisées ;
- les règles importantes ;
- les informations nécessaires pour travailler sur le projet.

Ce fichier doit rester limité et précis afin de ne pas ajouter inutilement trop de contexte au modèle.

---

## 5. MCP

Les **MCP** permettent de connecter le modèle à différents outils ou services.

Des exemples comme GitHub, DevOps ou d’autres outils ont été évoqués.

Cependant, lorsqu’un MCP est configuré, sa description, ses outils et ses instructions peuvent également être ajoutés au contexte du modèle.

Il faut donc éviter de charger ou connecter inutilement trop de MCP lorsque ceux-ci ne sont pas nécessaires à la tâche.

L’idée présentée est comparable à un **détecteur de mouvement** : l’outil doit être utilisé lorsqu’il est nécessaire, plutôt que de rester constamment actif sans besoin.

---

## 6. Skills

Les **Skills** permettent de donner à un agent des instructions spécifiques pour un type de tâche.

Une Skill peut définir :

- une responsabilité ;
- une tâche précise ;
- les étapes à suivre ;
- les résultats attendus ;
- les validations nécessaires.

Cela permet de garder les instructions spécialisées séparées et de ne charger que celles qui sont nécessaires au moment où l’agent doit réaliser une tâche particulière.

---

## 7. Orchestration et agents spécialisés

Un autre point important de la réunion concernait l’utilisation de plusieurs **agents spécialisés**.

Au lieu d’avoir un seul agent qui réalise toutes les tâches, plusieurs agents peuvent être créés selon les besoins, par exemple pour :

- le développement UI ;
- les migrations ;
- les tests ;
- la documentation.

Un **orchestrateur** peut ensuite coordonner ces différents agents.

Son rôle est de comprendre la tâche, déterminer quel agent doit intervenir et lui transmettre les informations nécessaires.

Cela permet notamment de limiter le contexte de chaque agent à sa responsabilité.

---

## 8. Transmission du contexte entre agents

Lorsqu’un agent termine une tâche et qu’un autre doit continuer le travail, il n’est pas nécessaire de transmettre toute la conversation ou tout le contexte précédent.

Il est préférable de transmettre uniquement les informations nécessaires à l’étape suivante.

Le contexte peut donc être réduit progressivement entre les différentes étapes du workflow afin d’éviter une consommation excessive de tokens.

---

## 9. Choix du modèle

Il est également important d’utiliser le **bon modèle selon la tâche**.

Toutes les tâches ne nécessitent pas le même niveau de raisonnement ou le même modèle.

Une tâche simple peut être réalisée avec un modèle adapté à ce niveau de complexité, tandis qu’une tâche plus complexe, comme une réflexion d’architecture, peut nécessiter un modèle différent.

L’objectif est donc d’adapter le modèle au travail demandé plutôt que d’utiliser systématiquement le même modèle pour toutes les tâches.

---

## 10. Checkpoints

La réunion a également présenté le principe des **checkpoints**.

Lorsqu’un agent effectue plusieurs modifications et qu’une erreur apparaît, il peut être difficile de corriger le problème après plusieurs étapes.

Les checkpoints permettent de conserver un état intermédiaire du travail.

Si une modification produit un mauvais résultat, il devient alors possible de revenir à un état précédent plutôt que de continuer à corriger un contexte devenu incorrect.

---

## 11. Points principaux à retenir

Les principaux éléments retenus de la réunion sont :

- limiter le contexte envoyé au modèle ;
- éviter de conserver inutilement des sessions trop longues ;
- utiliser la compaction lorsque cela est nécessaire ;
- conserver les informations importantes du projet dans un fichier dédié comme `CLAUDE.md` ;
- ne pas charger inutilement tous les MCP ;
- utiliser des Skills pour spécialiser les instructions ;
- utiliser plusieurs agents spécialisés lorsque cela est pertinent ;
- utiliser un orchestrateur pour répartir les tâches ;
- transmettre uniquement le contexte nécessaire entre les agents ;
- choisir le modèle en fonction de la tâche ;
- utiliser des checkpoints pour pouvoir revenir à un état précédent en cas de problème.

## Conclusion

Le point principal de la réunion est l’importance de la **gestion du contexte** dans le fonctionnement des modèles et des agents IA.

Il ne suffit pas de donner le maximum d’informations au modèle. Il faut surtout lui transmettre les bonnes informations au bon moment, limiter les éléments inutiles et organiser correctement les sessions, les outils et les différents agents.

Cette gestion permet de mieux maîtriser la consommation de tokens et de rendre le fonctionnement des agents plus efficace.
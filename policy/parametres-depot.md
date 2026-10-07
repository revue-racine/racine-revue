# Paramètres du dépôt de confiance (à appliquer et vérifier par l'administrateur)

Toutes les commandes se lancent depuis l'appareil de l'administrateur, avec sa
propre session `gh`, **jamais depuis l'hôte des agents**. `R=<administrateur>/<depot>`.
Les points marqués *(à confirmer)* reposent sur une API récente : vérifier la
documentation GitHub au moment du bootstrap, et noter dans le journal ce qui a
été appliqué réellement.

## 1. Dépôt

| Réglage | Valeur | Commande |
|---|---|---|
| Visibilité | public | création |
| Issues | activées (canal de demande) | `gh api -X PATCH repos/$R -F has_issues=true` |
| Wiki, Projects, Discussions | désactivés | `gh api -X PATCH repos/$R -F has_wiki=false -F has_projects=false -F has_discussions=false` |
| Fusion | squash seul, branche supprimée après fusion | `gh api -X PATCH repos/$R -F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=false -F allow_auto_merge=false -F delete_branch_on_merge=true` |
| Secret scanning + push protection | activés | `gh api -X PATCH repos/$R --input -` avec `security_and_analysis` |
| Signalement privé de vulnérabilité | activé | `gh api -X PUT repos/$R/private-vulnerability-reporting` |
| Collaborateurs, clés de déploiement, webhooks, environnements, secrets, variables | **aucun** | contrôle §4 |

## 2. Actions

| Réglage | Valeur | Commande |
|---|---|---|
| Actions autorisées | sélection explicite, épinglage SHA exigé *(à confirmer : `sha_pinning_required`)* | `gh api -X PUT repos/$R/actions/permissions -F enabled=true -f allowed_actions=selected -F sha_pinning_required=true` |
| Liste | `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`, `actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6` | `gh api -X PUT repos/$R/actions/permissions/selected-actions --input -` (`github_owned_allowed=false`, `verified_allowed=false`, `patterns_allowed=[…]`) |
| Jeton par défaut | lecture seule ; Actions ne crée ni n'approuve de PR | `gh api -X PUT repos/$R/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false` |
| PR de forks | approbation exigée pour tout contributeur externe *(à confirmer)* | `gh api -X PUT repos/$R/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors` |
| Runners | hébergés par GitHub uniquement ; **aucun runner auto-hébergé enregistré** | contrôle §4 |

## 3. Règles (rulesets)

```
gh api -X POST repos/$R/rulesets --input policy/rulesets/main-protege.json
gh api -X POST repos/$R/rulesets --input policy/rulesets/etiquettes-immuables.json
```

`bypass_actors` est vide dans les deux : l'administrateur lui-même passe par une
PR dont « Contrôles statiques » est vert. Modifier une règle reste un pouvoir
d'administrateur ; c'est l'identité de confiance, et c'est pour cela qu'elle
ne doit exister sur aucun hôte d'agent.

## 4. Contrôles attendus (à coller dans le journal de bootstrap)

```
gh api repos/$R --jq '{id, owner_id: .owner.id, visibility, default_branch, has_issues, has_wiki}'
gh api repos/$R/rulesets --jq '[.[] | {id, name, enforcement}]'
gh api repos/$R/rulesets/<id> --jq '.bypass_actors'            # [] pour chaque règle
gh api repos/$R/collaborators --jq 'map(.login)'                 # [<administrateur>] seul
gh api repos/$R/keys --jq length                                 # 0
gh api repos/$R/hooks --jq length                                # 0
gh api repos/$R/environments --jq .total_count                   # 0
gh api repos/$R/actions/secrets --jq .total_count                # 0
gh api repos/$R/actions/variables --jq .total_count              # 0
gh api repos/$R/actions/runners --jq .total_count                # 0
gh api repos/$R/actions/permissions
gh api repos/$R/actions/permissions/selected-actions
gh api repos/$R/actions/permissions/workflow
```

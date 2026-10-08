# Racine de confiance — revue indépendante

Ce dépôt produit des **attestations de revue** signées par GitHub Actions
(Sigstore, sans clé privée gérée ici) : « le protocole `revue/1` a été appliqué
à exactement ce commit et à exactement cet arbre, et voici le verdict
normalisé ». Il est public pour que n'importe qui puisse vérifier une
attestation, et pour bénéficier des attestations d'artefacts de GitHub, réservées
aux dépôts publics hors offre Enterprise.

Il est administré par une identité qui n'existe sur aucun hôte d'agent. Les
agents ne peuvent que **demander** une revue ; ils ne peuvent ni modifier ce
dépôt, ni choisir le verdict, ni fournir le sujet.

## Ce qui vit ici

| Chemin | Rôle |
|---|---|
| `.github/workflows/revue.yml` | workflow de confiance : admission, sujet recalculé, relecture, signature, réponse — produit des attestations `revue/2` seulement |
| `.github/workflows/controles.yml` | contrôles statiques exigés avant toute fusion |
| `protocol/revue-v1.md` | protocole de revue v1, figé : il sert à vérifier les attestations v1 déjà émises |
| `protocol/revue-v2.md` | protocole de revue v2 (son empreinte figure dans chaque attestation v2) |
| `schemas/` | schémas fermés : demande, sujet, sortie du relecteur, prédicat, politique (v1 figés ; sujet, prédicat et politique en v2) |
| `policy/confiance-v1.json` | politique v1 (génération 1), figée |
| `policy/confiance-v2.json` | politique v2 (génération 2) : identité de la racine, demandeurs, dépôts, relecteur `openai-responses` non acceptable, fraîcheur, limites |
| `policy/ancres-v1.json` | ancres gouvernées : base de revue de chaque dépôt, modifiée par PR seulement |
| `policy/rulesets/`, `policy/parametres-depot.md` | protections du dépôt, sous forme rejouable et vérifiable |
| `outils/` | code du workflow (bibliothèque standard seule) : producteur v2 (`revue2.py`, `relecteur_openai.py`, consigne du relecteur), producteur v1 conservé (`revue.py`), vérificateurs v1 (`verifier.py`) et v2 candidat (`verifier2.py`), pont P1 (v1 seulement, inactif) |
| `tests/` | tests statiques et fonctionnels, sans réseau ni secret |
| `BOOTSTRAP.md` | procédure exceptionnelle de création, et son journal |

## Ce qui ne vit jamais ici

- aucun secret, jeton, clé privée ou credential d'un service tiers dans les
  fichiers ou l'historique. La seule clé de service tiers (relecteur `revue/2`)
  est un secret de l'environnement GitHub `relecteur-openai`, restreint à
  `main`, que seul le step de relecture reçoit ;
- aucune donnée métier, aucun contenu d'un dépôt relu (code, diff, chemins,
  messages de commit, texte de revue) — ni dans les fichiers, ni dans les logs,
  ni dans les artifacts, ni dans les attestations ;
- aucun prompt, fichier d'instructions ou hook venu d'un dépôt relu ;
- aucun nom de dépôt privé : les dépôts relus sont désignés par un alias et un
  identifiant numérique ;
- aucune configuration qui donnerait à un hôte d'agent un rôle sur ce dépôt
  (collaborateur, clé de déploiement, runner auto-hébergé, application installée
  dont il détiendrait la clé).

## Demander une revue

Ouvrir une issue dont le corps est exactement :

```json
{"format":"olistic.confiance.demande/1","request_id":"<32 hex>","depot":"<alias>","pointe":"<sha 40>","declaration_p1":{"classe":"A","auteur":"<agent>"}}
```

Seuls les demandeurs listés par identifiant numérique dans la politique sont
admis : l'identité est l'ID numérique, jamais le login. La base n'est jamais
demandée : c'est l'ancre gouvernée du dépôt. Un `request_id` ne sert qu'une fois,
et toute opération acceptante le consomme dans le registre du dépôt (protocole §6). La réponse est un commentaire automatique puis la fermeture de l'issue ;
le commentaire n'est pas une preuve, l'attestation l'est.

## Vérifier une attestation

Attestations v2 : `outils/verifier2.py` (protocole `revue-v2.md` §7), vérificateur
**candidat**, avec une configuration consommateur distincte de celle du v1. Sous la
politique génération 2, il rejette toute attestation v2 (`relecteur_non_acceptable`).

Attestations v1 : `outils/verifier.py` (protocole v1 §7), inchangé. Il épingle l'identité numérique et les noms
de ce dépôt et de son propriétaire, le workflow et son commit, la branche `main`,
l'émetteur OIDC, le déclencheur `issues`, les runners hébergés et les empreintes
exactes de la politique et du protocole ; il recalcule le sujet depuis le dépôt
local avec son ancre, contrôle la fraîcheur et le rejeu, et agrège toutes les
attestations du sujet, récupérées par `bundle_url`. C'est une vérification pure :
elle n'autorise rien. Le seul chemin vers une attestation SSH P1 est
`outils/pont_p1.py`, qui vérifie, consomme et signe dans une seule opération.

## Données rendues publiques

Tout ce dépôt est public, et le reste tant que l'administrateur ne le supprime
pas. Ce qui en sort :

| Surface | Contenu | Conservation |
|---|---|---|
| fichiers et historique git | code, schémas, politique (ids numériques des dépôts relus et des demandeurs, login des demandeurs), ancres (SHA et empreintes de commits) | jusqu'à suppression ou réécriture par l'administrateur ; les copies et forks tiers échappent à son contrôle |
| étiquettes `consommation/<request_id>/…` | registre de consommation : liaison (alias, pointe, empreintes du sujet et du prédicat, horodatage), état final, empreinte du document P1 signé — jamais le document | immuables (règle `etiquettes-immuables`) |
| issues et commentaires | `request_id`, alias, pointe, déclaration P1, auteur, dates ; réponses automatiques (codes de refus, verdict, digest, lien d'attestation) | jusqu'à suppression par l'administrateur |
| journaux d'exécution Actions | étapes, durées, codes de refus ; aucun contenu relu | selon le réglage de conservation du dépôt (90 jours par défaut, modifiable), supprimables |
| attestations (API GitHub) | énoncé in-toto complet : sujet (alias, `repository_id`, SHA, empreintes sha256), prédicat, certificat (dépôt, workflow, commit, exécution) | supprimables par l'administrateur dans l'API GitHub |
| journal de transparence Sigstore public | entrée de l'attestation : au moins le certificat (dépôt, workflow, commit, exécution) et des empreintes ; selon le type d'entrée, l'énoncé complet — à traiter comme tel | **immuable**, hors du contrôle de quiconque |

Ce qui n'apparaît jamais : nom d'un dépôt privé, chemin, nom de fichier, message
de commit, branche, auteur de commit, diff, texte ou constat de revue, secret.
Un SHA ou une empreinte sha256 ne révèle aucun contenu ; elle permet seulement de
confirmer une copie exacte que l'on détient déjà. Un `repository_id` de dépôt
privé ne se résout pas publiquement.

## État

Lot 1 (clos) : relecteur `factice` seul — toute attestation v1 porte
`INDETERMINE` et aucune n'est acceptante.

Lot 2 : protocole `revue/2`, relecteur `openai-responses` (OpenAI Responses
direct, sans outil, sans stockage, sans exécution du code candidat), politique
génération 2 où ce relecteur est **non acceptable** : toute attestation v2 est
**consultative**, quel que soit son verdict, et le commentaire de réponse le dit.
Seul le dépôt lui-même (`auto-test`) peut être relu. Aucun pont P1 pour le v2.

Limites assumées du Lot 2 :

- l'identité du modèle (`relecteur.modele`) est celle que le fournisseur déclare
  dans sa réponse ; elle n'est pas prouvée cryptographiquement, et un identifiant
  sans date peut désigner des versions successives ;
- la sortie brute du relecteur (constats compris) n'est ni publiée ni conservée :
  seule son empreinte est attestée ;
- l'encadrement du diff n'est pas une frontière de sécurité : un relecteur
  automatique peut être influencé par le contenu qu'il relit ;
- le workflow v2 ne doit pas être activé avant que l'administrateur ait créé et
  protégé l'environnement `relecteur-openai` (`policy/parametres-depot.md` §5).
  Sans clé, toute demande est refusée sans attestation (`relecteur_cle_absente`).

# Bootstrap de la racine de confiance — procédure exceptionnelle

Cette procédure ne s'exécute **qu'une fois**. Elle repose sur un état qui ne se
reproduit pas : un dépôt vide, sans règle. Dès l'étape 6, `main` n'accepte plus
que des PR vertes et `bypass_actors` est vide ; refaire un bootstrap exigerait
un nouveau dépôt, donc un nouvel identifiant numérique, que tous les
consommateurs rejettent tant qu'ils ne l'ont pas épinglé par une décision
explicite. Ce n'est donc jamais une procédure normale de mise à jour.

Tout se fait **hors de l'hôte des agents**, sur un appareil de l'administrateur.
L'hôte des agents ne détient, à aucun moment, ni mot de passe, ni jeton, ni clé
SSH, ni session `gh`, ni code de récupération de l'identité administrative.

## 0. Préalable — le bundle

Le bundle est préparé sur l'hôte des agents et n'y vaut rien d'autre qu'une
proposition. Sa valeur vient de la lecture qu'en fait l'administrateur.

1. Récupérer l'archive depuis l'appareil de l'administrateur (tirée par lui,
   jamais poussée par l'hôte) et comparer son sha256 à la valeur annoncée par un
   second canal.
2. Lire intégralement `.github/workflows/revue.yml`, `outils/revue.py`,
   `policy/confiance-v1.json`, `protocol/revue-v1.md`.
3. Lancer localement : `python3 -m unittest discover -s tests` (dépendances :
   `tests/requirements.txt`).
4. Contrôler l'absence de noms internes avec une liste tenue **hors de ce dépôt**
   (un nom par ligne : hôtes, comptes, dépôts privés, services) :
   `python3 tests/controle_noms.py <liste-privée>`. Ni la liste ni ses empreintes
   ne sont jamais publiées.

## 1. Identité administrative

- Compte GitHub dédié `<administrateur>`, adresse de messagerie **qui n'est lue
  par aucun agent ni connecteur** (une boîte relevée par un agent permettrait de
  détourner une réinitialisation).
- 2FA par clé de sécurité ou passkey ; codes de récupération hors ligne.
- Clé SSH de signature de commits générée sur l'appareil de l'administrateur,
  déclarée comme *signing key* du compte.
- Aucun connecteur, aucune application OAuth ni GitHub App liée à ce compte dont
  un agent détiendrait l'accès. Ne jamais lancer `gh auth login` avec ce compte
  sur l'hôte des agents.

## 2. Dépôt vide

Créer `<administrateur>/<depot>` **public, vide** (ni README, ni licence, ni
`.gitignore`). Relever :

```
gh api repos/<administrateur>/<depot> --jq '{id, owner_id: .owner.id}'
```

## 3. Identité de demande

Compte GitHub dédié `<operateur>` : aucun dépôt, aucun rôle sur ce dépôt.
Relever son identifiant numérique : `gh api users/<operateur> --jq .id`.
Son jeton (classique, portée `public_repo` seule, expiration courte) est la
**seule** pièce installée ensuite sur l'hôte des agents. Ne jamais l'inviter
comme collaborateur : ouvrir une issue sur un dépôt public ne demande aucun rôle.

## 4. Ancrage de la politique

Dans `policy/confiance-v1.json`, remplir `racine.proprietaire`,
`racine.proprietaire_id`, `racine.depot`, `racine.depot_id`, `demandeurs`
(`<operateur>` et son identifiant) et `depots[auto-test].repository_id`
(= `racine.depot_id`). `policy/ancres-v1.json` reste à `null` : une ancre ne
peut pas désigner le commit qui la contient ; elle est posée à l'étape 6 bis.
Contrôle :

```
python3 -I outils/revue.py politique --finale
python3 -m unittest discover -s tests
```

## 5. Publication initiale — l'unique poussée directe

```
git init -b main && git add -A
git commit -S -m "bootstrap: racine de confiance v1"
git remote add origin https://github.com/<administrateur>/<depot>.git
git push origin main
```

Relever le SHA du commit. Le workflow `controles` doit passer sur ce push.

## 6. Protections — fermeture du chemin de bootstrap

Appliquer `policy/parametres-depot.md` §1 à §3, dans cet ordre. À partir de là,
`main` refuse toute poussée directe, y compris de l'administrateur.

## 6 bis. Ancre de `auto-test` — première PR sous protection

Sur une branche, poser dans `policy/ancres-v1.json` l'ancre de `auto-test` = SHA
du commit de bootstrap, et son `objet_sha256` :

```
git cat-file commit <sha> | python3 -c 'import sys,hashlib; b=sys.stdin.buffer.read(); print(hashlib.sha256(b"commit %d\0" % len(b) + b).hexdigest())'
```

PR, « Contrôles statiques » vert, fusion squash. Toute ancre ultérieure suit le
même chemin ; jamais une donnée de demande.

## 7. Jeton de demande sur l'hôte des agents

Installer le jeton de `<operateur>` dans un emplacement dédié (configuration
`gh` séparée, permissions 0600), distinct de toute autre identité GitHub de
l'hôte. Le noter dans le gestionnaire de secrets.

## 8. Vérification d'activation

| # | Essai | Attendu |
|---|---|---|
| 1 | `<operateur>` ouvre une demande `auto-test` (nouveau `request_id`, pointe = un commit de `main` postérieur à l'ancre) | réponse « attestée, verdict `INDETERMINE` » ; base attestée = ancre |
| 2 | vérification sur l'appareil de l'administrateur (`outils/verifier.py`, configuration épinglant commit du workflow, empreintes de politique et de protocole, génération) | signature et provenance valides, décision **rejet** (relecteur factice non acceptable) |
| 2 bis | même demande ouverte dans une nouvelle issue avec le même `request_id` | refus `request_id_deja_utilise`, aucune attestation |
| 3 | un octet du prédicat modifié dans le bundle téléchargé (`--bundle`) | `gh attestation verify` échoue |
| 4 | demande par un autre compte | refus `demandeur_non_autorise`, aucune attestation |
| 5 | demande avec un champ `verdict` ou `base` | refus `demande_invalide`, aucune attestation |
| 6 | demande avec une pointe inexistante | refus `objet_introuvable`, aucune attestation |
| 7 | `<operateur>` tente : poussée d'une branche, `workflow_dispatch`, ajout de collaborateur, lecture des rulesets en écriture | 403 / 404 partout |
| 8 | PR depuis un fork modifiant `revue.yml` | seul `controles` s'exécute (après approbation), `revue` ne s'exécute pas |
| 9 | journaux publics des exécutions | aucun nom de dépôt privé, aucun contenu, aucun chemin |

## 9. Clôture

1. Poser l'étiquette `racine-v1` sur le commit de bootstrap (immuable par
   `etiquettes-immuables`).
2. Compléter le journal ci-dessous par une PR (la première fusion sous
   protection en est la preuve), en y collant les sorties de
   `policy/parametres-depot.md` §4.
3. Transmettre aux consommateurs, par un canal hors de ce dépôt : propriétaire,
   dépôt et leurs identifiants numériques, commit(s) de workflow acceptés,
   empreintes sha256 exactes de `policy/confiance-v1.json` et de
   `protocol/revue-v1.md`, génération.
4. Le pont P1 (protocole §8) n'est pas activé au Lot 1 : aucune clé SSH de
   relecteur n'est créée et aucune étiquette `consommation/…` n'existe. À son
   activation (Lot 2), vérifier d'abord que `GITHUB_TOKEN` du job peut créer une
   étiquette `consommation/…` et ne peut ni la déplacer ni la supprimer.

## Journal

| Champ | Valeur |
|---|---|
| Date (UTC) | 2026-10-08 |
| sha256 de l'archive du bundle reçue | `2d5145a27d6351dfee55824336ee52305ced4932aa8d5baa749f00752a27176e` |
| `<administrateur>` / identifiant numérique | `revue-racine` / `339338245` |
| `<depot>` / identifiant numérique | `revue-racine/racine-revue` / `1409404929` |
| `<operateur>` / identifiant numérique | `miguelfromba` / `241122414` |
| SHA du commit de bootstrap | `3bf64c3c483762601c725067b30bb0a8a868fe0d` |
| Identifiants des rulesets, `bypass_actors` | `etiquettes-immuables` = `24684532`, `bypass_actors=[]` ; `main-protege` = `24684531`, `bypass_actors=[]` |
| Activation : essais 1 à 9 | **PASS — tous les essais 1 à 9 conformes, ainsi que l'essai 2 bis.** Voir détails ci-dessous. |
| Écarts constatés et décisions | Bootstrap initial : bundle `d8429419d7b0a03a53b81fa6cadde93905ddbd90eff320d9e14766be7beb824e`, commit `3bf64c3c483762601c725067b30bb0a8a868fe0d`. Un défaut CI de contrôle de `.git/` a nécessité une exception bornée de bootstrap avant protection : seul `tests/test_bundle.py` a changé ; bundle corrigé/final `2d5145a27d6351dfee55824336ee52305ced4932aa8d5baa749f00752a27176e`, commit `048378841b1380c3b5ac979738a2bb473ae6a8e7`, ensuite étiqueté `racine-v1`. Deux écarts supplémentaires révélés par l'activation ont été corrigés par PR protégées : URL réelle de bundle `*.blob.core.windows.net` (PR #3, merge `03e6d20ff8e63c4ee8c059f185483f135df53897`) ; procédure de rejeu corrigée en « nouvelle issue avec le même `request_id` » (PR #4, merge `91c1a6469ce9f2ea29d2345d12b8eff8e67cd59f`). Aucun affaiblissement du modèle de confiance. |

### Activation — détail des essais 1 à 9 et 2 bis

- **1.** Demande valide : attestation `INDETERMINE`, run `37707994499`, sujet `9b61439e820c1f6d944335d46508dec778fdb589063c7aebc9baaa82a0f8e0e1`.
- **2.** Vérification indépendante : signature/provenance valides ; usage autorisant refusé avec `relecteur_non_acceptable`.
- **2 bis.** Rejeu du même `request_id` dans une nouvelle issue (#5) : `request_id_deja_utilise`, aucune nouvelle attestation, run `37712015114`.
- **3.** Modification d'un octet du prédicat signé : `gh attestation verify` échoue (`EXIT=1`).
- **4.** Demandeur non autorisé (#6) : `demandeur_non_autorise`, signature `skipped`, run `37712616580`.
- **5.** Demande invalide avec champ `verdict` (#7) : `demande_invalide`, signature `skipped`, run `37712868534`.
- **6.** Pointe inexistante (#8) : `objet_introuvable`, signature `skipped`, run `37713061804`.
- **7.** Opérateur O : push refusé `403`, `workflow_dispatch` refusé `403`, ajout collaborateur et écriture ruleset refusés `404`.
- **8.** PR de fork #9 modifiant `revue.yml` : seul `controles` exécuté après approbation, run `37713709313` `success`, aucun run `revue`, PR fermée non fusionnée.
- **9.** Journaux publics des exécutions : 16 journaux récupérés ; contrôle avec la liste privée de l'administrateur, 3 noms contrôlés, 0 fichier fautif, `EXIT=0`.

### Contrôles finaux de configuration du dépôt

    depot:
      id: 1409404929
      owner_id: 339338245
      visibility: public
      default_branch: main
      has_issues: true
      has_wiki: false

    rulesets:
      - id: 24684532
        name: etiquettes-immuables
        enforcement: active
        bypass_actors: []
      - id: 24684531
        name: main-protege
        enforcement: active
        bypass_actors: []

    collaborators:
      - revue-racine

    deploy_keys: 0
    hooks: 0
    environments: 0
    actions_secrets: 0
    actions_variables: 0
    actions_runners: 0

    actions_permissions:
      enabled: true
      allowed_actions: selected
      sha_pinning_required: true

    selected_actions:
      github_owned_allowed: false
      verified_allowed: false
      patterns_allowed:
        - actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        - actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6

    workflow_permissions:
      default_workflow_permissions: read
      can_approve_pull_request_reviews: false

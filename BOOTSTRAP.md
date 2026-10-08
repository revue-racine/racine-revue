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
| Date (UTC) | |
| sha256 de l'archive du bundle reçue | |
| `<administrateur>` / identifiant numérique | |
| `<depot>` / identifiant numérique | |
| `<operateur>` / identifiant numérique | |
| SHA du commit de bootstrap | |
| Identifiants des rulesets, `bypass_actors` | |
| Activation : essais 1 à 9 | |
| Écarts constatés et décisions | |

# Protocole de revue v1 (`revue/1`)

Ce fichier fait partie de ce qui est attesté : son sha256 est inscrit dans chaque
prédicat et épinglé par les consommateurs. Le modifier passe par la règle
`main-protege` et invalide toutes les attestations antérieures pour un
consommateur qui épingle la nouvelle empreinte.

## 1. Ce qu'une attestation prouve, et ce qu'elle ne prouve pas

Une attestation `urn:olistic:confiance:attestation-revue:1` prouve, pour qui la
vérifie selon §7 :

- que le workflow `.github/workflows/revue.yml` de ce dépôt, sur `refs/heads/main`,
  à un commit de workflow épinglé, exécuté par un runner hébergé par GitHub sur
  l'événement `issues`, a produit ce prédicat ;
- que le sujet a été recalculé par le workflow depuis le dépôt candidat, sa base
  étant l'**ancre gouvernée** du dépôt et non une donnée de la demande ;
- que le verdict est la normalisation (§5) de la sortie du relecteur déclaré, sous la
  politique, le protocole et les ancres dont les empreintes figurent dans le prédicat.

Elle ne prouve pas :

- que le code relu est sûr — un relecteur automatique peut se tromper ou être
  influencé par le contenu qu'il relit (injection d'instructions) ;
- qu'un consommateur a effectivement vérifié l'attestation avant d'agir ;
- une approbation de classe B — elle n'en tient jamais lieu.

## 2. Demande

Une demande est une issue ouverte sur ce dépôt par un demandeur listé dans la
politique, identifié par son **identifiant numérique** (jamais par son login).
Le titre et les étiquettes sont ignorés. Le corps est exactement un document JSON
conforme à `schemas/demande-v1.schema.json` :

```json
{"format":"olistic.confiance.demande/1","request_id":"<32 hex>","depot":"<alias>",
 "pointe":"<sha 40>","declaration_p1":{"classe":"A","auteur":"<agent>"}}
```

- `request_id` : identifiant à usage unique, tiré au hasard par le demandeur.
- `declaration_p1` : déclaration, jamais vérifiée ici ; reprise telle quelle dans
  le prédicat pour que le pont P1 (§8) la recopie, et confrontée par le P1 à son
  propre calcul de classe et à ses trailers. Une déclaration fausse ne peut donc
  produire qu'un refus.

La demande ne contient **ni base**, ni verdict, ni arbre, ni relecteur, ni
génération : tout autre champ fait refuser la demande entière. JSON avec clé en
double, flottant, `NaN`, ou corps au-delà de la limite : refus. Un refus
d'admission ne produit aucune attestation.

**Identité.** Un demandeur est son identifiant numérique GitHub, et rien
d'autre : le login n'intervient dans aucune décision. Un compte renommé reste le
même demandeur ; un autre compte qui reprend le login reste un tiers.

**Doublons.** Avant tout calcul, le workflow lit l'historique complet du dépôt
(toutes les issues, ordre de création, sans filtre serveur par auteur), borné à
`numero // 100 + 12` pages, puis filtre localement par `user.id`. Un élément
dont l'identité ne peut pas être établie, une erreur ou une borne dépassée font
refuser. Si une issue de numéro inférieur, d'un demandeur autorisé, porte le
même `request_id`, la demande est refusée (`request_id_deja_utilise`). La plus ancienne gagne, quel
que soit l'ordre d'exécution : deux issues concurrentes donnent un seul résultat.
Une issue d'un tiers ne réserve jamais un `request_id`.

## 3. Base gouvernée

`policy/ancres-v1.json` donne, pour chaque dépôt de la politique, l'**ancre** :
le dernier état accepté (commit et sha256 de son objet commit). Elle n'est
modifiée que par une PR fusionnée sur `main`. La base de revue est toujours
l'ancre ; le demandeur ne fournit que la pointe. En conséquence :

- le demandeur ne peut pas placer la base après un changement dangereux : tout
  ce qui sépare l'ancre de la pointe est dans le périmètre ;
- deux demandes sur la même pointe ont la même base, donc le même sujet, tant que
  l'ancre ne change pas ;
- une ancre nulle interdit toute revue du dépôt (`ancre_absente`) ; une ancre non
  ancêtre de la pointe est refusée (`ancre_non_ancetre`), comme une ancre dont
  l'objet récupéré n'a pas l'empreinte sha256 attendue (`ancre_divergente`).

Le consommateur recalcule le sujet avec **sa propre** ancre gouvernée (pour le P1 :
`ancre_gouvernance`) ; une attestation calculée sur une autre base n'a pas le même
digest et est rejetée.

## 4. Sujet

Le workflow résout l'alias en `repository_id` par la politique, récupère l'ancre
et la pointe dans un dépôt nu neuf (aucune configuration système, globale ni
d'environnement ; sans hooks, attributs, filtres, pilotes de diff, helpers
d'identifiants ni sous-modules ; `fsckObjects` actif ; transport `https` seul),
puis calcule, pour la base et pour la pointe :

| Champ | Définition |
|---|---|
| `commit` | identifiant git (SHA-1) |
| `objet_sha256` | sha256 de l'objet commit au format d'objet git : `commit <taille>\0<contenu>` |
| `arbre` | identifiant git de l'arbre |
| `arbre_sha256` | sha256 du manifeste trié par chemin (octets) des lignes `mode SP sha256(contenu) SP chemin NUL` |

et `perimetre_sha256` : sha256 du manifeste trié par chemin des lignes
`statut SP mode_avant SP h_avant SP mode_apres SP h_apres SP chemin NUL` de
`base..pointe` (h = sha256 du contenu, `-` si absent, sans détection de renommage).

Tout **gitlink** (sous-module, mode 160000) dans la base, la pointe ou le
périmètre fait refuser la demande (`gitlink_refuse`). Un `.gitmodules` sans
gitlink est un fichier ordinaire.

Le digest in-toto du sujet est le sha256 de son encodage canonique (JSON, clés
triées, sans espace, UTF-8). Son nom est `olistic-revue:<alias>@<pointe>#<request_id>`.

Le job de signature **recalcule le sujet indépendamment** et refuse de signer si
le prédicat reçu du job de revue porte un autre sujet, d'autres empreintes de
protocole, de politique ou d'ancres, une autre demande, ou un instant incohérent.

## 5. Relecture et verdict

Le relecteur reçoit le diff `base..pointe` comme donnée. Il n'exécute aucun code
candidat, ne charge aucune instruction du candidat (`AGENTS.md`, `CLAUDE.md`,
hooks, configuration d'outil) comme autorité et n'a pas accès au jeton de
signature. Sa sortie brute doit être conforme à `schemas/sortie-relecteur-v1.schema.json`.

Énumération exacte des verdicts : `FAVORABLE`, `DEFAVORABLE`, `INDETERMINE`.

| Sortie du relecteur | Verdict attesté | Motif |
|---|---|---|
| relecteur `factice` (Lot 1), quelle que soit sa sortie | `INDETERMINE` | `relecteur_factice` |
| vide, illisible, non conforme, clé en double, casse ou valeur différente | `INDETERMINE` | `sortie_invalide` |
| `FAVORABLE` avec un constat `bloquant` ou `majeur` | `INDETERMINE` | `favorable_incoherent` |
| `INDETERMINE` | `INDETERMINE` | `relecteur` |
| diff au-delà de la limite de la politique | `INDETERMINE` | `diff_trop_grand` |
| `FAVORABLE` ou `DEFAVORABLE` conforme | identique | `null` |

La sortie brute n'est jamais publiée ; seul son sha256 (`rapport_sha256`) entre
dans le prédicat.

## 6. Fraîcheur, révocation, rejeu

- **Génération.** La politique porte une `generation` gouvernée, inscrite dans
  chaque prédicat. Toute modification de la politique change son empreinte.
- **Coupure.** `fraicheur.coupure` : une attestation dont l'horodatage vérifié est
  antérieur est rejetée.
- **Validité.** `fraicheur.validite_s` : au-delà, rejet (`attestation_perimee`).
- **Horodatage vérifié.** Le consommateur prend le plus ancien horodatage vérifié
  (journal de transparence ou TSA) rendu par la vérification cryptographique ;
  absent, illisible ou futur au-delà de `derive_horloge_s` : rejet. L'`instant`
  du prédicat doit le précéder d'au plus `tolerance_instant_s`.
- **Révocation d'un relecteur.** Par PR : `actif` et `acceptable` à `false`,
  `generation` + 1, `coupure` à l'instant de la révocation. Le workflow refuse
  dès lors de produire une attestation pour ce relecteur ; les consommateurs
  réépinglent l'empreinte de la nouvelle politique et rejettent toutes les
  attestations antérieures (`politique_differente`).
- **Rejeu.** Une attestation est liée à un `request_id` (prédicat et nom du
  sujet). La vérification (§7) est pure et ne vaut jamais autorisation. Toute
  opération acceptante — la seule est le pont P1 (§8) — consomme le `request_id`
  dans le **registre de consommation** du dépôt de confiance : étiquettes
  immuables `refs/tags/consommation/<rid>/reserve` puis `…/fin` (SIGNE ou
  ECHEC), créées une seule fois chacune, de façon atomique, depuis le job
  protégé. Sans registre, aucune acceptation. Un `request_id` réservé ne
  redevient jamais disponible.

## 7. Vérification par un consommateur

Configuration propre au consommateur, jamais lue dans l'attestation : identité
numérique et noms de la racine, workflow, nom du workflow, ref, commits de
workflow acceptés, type de prédicat, **empreintes exactes** de la politique et du
protocole, génération. La politique utilisée doit avoir exactement l'empreinte
épinglée.

1. Lister **toutes** les attestations du digest du sujet par l'API GitHub
   (pagination complète par l'en-tête `Link`, restreinte au dépôt de confiance).
   Chaque élément doit porter une `bundle_url` https, sans identifiants, port 443,
   hôte `*.github.com` ou `*.githubusercontent.com` ; le champ `bundle` en ligne
   n'est jamais utilisé, et aucun bundle n'est accepté de l'appelant. Le bundle est
   téléchargé sans jeton, hôte revalidé après redirection, décompressé (snappy
   bloc, tailles bornées), relu (JSON sans doublon, `mediaType` Sigstore), puis
   vérifié par `gh attestation verify --bundle` avec les épinglages. Tout échec :
   rejet.
2. Pour chaque résultat : certificat (émetteur OIDC ; URI, identifiant numérique,
   propriétaire et identifiant numérique du propriétaire du dépôt source ;
   visibilité ; ref ; URI et digest du signataire et de la configuration ;
   `githubWorkflow*` ; déclencheur `issues` ; runner hébergé ; commit du workflow
   épinglé ; URI d'exécution), `_type` in-toto `https://in-toto.io/Statement/v1`,
   type de prédicat, sujet unique de digest et de nom attendus, prédicat conforme
   au schéma, sujet égal octet pour octet au sujet recalculé, empreintes de
   protocole et de politique et génération égales aux épinglages, relecteur actif,
   acceptable et de modèle autorisé, fraîcheur (§6).
3. Agrégation, indépendante de l'ordre et du nombre :
   - attestations de **ce** `request_id` : toutes doivent passer l'étape 2 ; aucune
     `DEFAVORABLE` ; au moins une `FAVORABLE` ;
   - attestations d'autres demandes du même sujet : une `DEFAVORABLE` entièrement
     valide bloque (redemander ne lave pas un refus) ; les autres sont ignorées, si
     bien que multiplier les demandes ne crée aucun déni ;
   - aucun refus ne dépend du nombre d'attestations.

Référence exécutable : `outils/verifier.py`.

## 8. Raccord avec le P1 : pont vers l'attestation SSH

Le P1 n'accepte qu'une `Review-Attestation` SSH détachée. Il n'est pas modifié.
La chaîne est :

GitHub / Sigstore (preuve amont) → **pont P1**, hors de portée de l'hôte des agents
→ `Review-Attestation` conforme au P1.

- **Composant.** `outils/pont_p1.py`, opération unique
  `verifier_consommer_et_signer(config, request_id, alias, pointe, registre)`,
  exécutée dans un job dédié de ce dépôt (Lot 2), dans un environnement GitHub
  restreint à `main`, avec `contents: write` pour le registre. Elle ne reçoit que
  des références : aucune API n'accepte une décision, un verdict, un résultat de
  vérification, un document ou des octets à signer.
- **Identité.** Une clé SSH de relecteur, famille P1 `gpt-codex-family`, générée
  par l'administrateur hors de l'hôte des agents, stockée uniquement comme secret
  de cet environnement. Sa clé publique doit être déclarée relecteur gouverné dans
  l'autorité vivante du P1 : c'est une **proposition de classe B** distincte.
- **Hors de portée.** Seuls les workflows de `main` lisent ce secret ; `main` ne
  change que par PR de l'administrateur ; les demandeurs n'ont aucun rôle ; le
  relecteur automatique tourne dans un autre job, sans ce secret.
- **Enchaînement, sans frontière appelable.** Sujet recalculé → §7 en entier
  (liste, `bundle_url`, vérification cryptographique, `evaluer`) → décision
  acceptée exigée → réservation atomique du `request_id` (liaison : sujet,
  prédicat, horodatage) → document P1 construit sur place → contrôle que la
  réservation lue est exactement celle posée → signature → `fin` = SIGNE avec
  l'empreinte du document. La signature n'est rendue qu'après SIGNE.
- **États.** DISPONIBLE → RESERVE → SIGNE | ECHEC, sans retour. Un échec après
  réservation clôt en ECHEC ; si cette clôture échoue aussi, l'état RESERVE se
  diagnostique et se clôt explicitement en ECHEC. Jamais deux signatures pour un
  `request_id`, jamais de réutilisation après SIGNE.
- **Champs repris.** `format` = `olistic.gouvernance.attestation/1` ; `role` =
  `revue` ; `depot` = configuration privée du pont ; `pointe` et `arbre` = pointe du
  sujet attesté ; `classe` et `auteur` = `declaration_p1` attestée ;
  `relecteur` = `gpt-codex-family` ; `reference_revue` =
  `olistic-revue:sha256:<digest du sujet>#<request_id>` ; `reference_approbation`
  = `null` ; `instant` = horodatage vérifié. Signature
  `ssh-keygen -Y sign -n olistic-gouvernance-revue` sur l'encodage canonique ;
  trailer = base64 de `{document, signature, principal}`.
- **Remise.** Jamais en clair dans ce dépôt public : le document contient le nom
  du dépôt relu. Le mode de remise chiffrée relève du Lot 2.

Au Lot 1, aucun workflow n'appelle le pont et aucune clé n'existe.

## 9. Versions

Tout changement de format de demande, de sujet, de prédicat ou de règle de
normalisation crée `revue/2` et un nouveau type de prédicat. Un consommateur
n'accepte que les empreintes qu'il épingle.

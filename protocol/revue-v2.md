# Protocole de revue v2 (`revue/2`)

Ce fichier fait partie de ce qui est attesté : son sha256 est inscrit dans chaque
prédicat v2 et épinglé par les consommateurs v2. Le protocole `revue/1`
(`protocol/revue-v1.md`) reste en vigueur, inchangé, pour vérifier les
attestations v1 existantes ; rien de ce qui suit ne le modifie.

## 0. Rapport avec `revue/1`

| | `revue/1` | `revue/2` |
|---|---|---|
| type de prédicat | `urn:olistic:confiance:attestation-revue:1` | `urn:olistic:confiance:attestation-revue:2` |
| politique | `policy/confiance-v1.json` (génération 1) | `policy/confiance-v2.json` (génération ≥ 2) |
| sujet | `olistic.confiance.sujet-revue/1` | `olistic.confiance.sujet-revue/2` |
| nom du sujet | `olistic-revue:<alias>@<pointe>#<rid>` | `olistic-revue2:<alias>@<pointe>#<rid>` |
| relecteur | `factice` (ou `codex`, jamais activé) | `openai-responses` |
| vérificateur | `outils/verifier.py` | `outils/verifier2.py` |
| pont P1 | `outils/pont_p1.py` (inactif) | **aucun** |

Après la fusion qui introduit `revue/2`, le workflow `.github/workflows/revue.yml`
ne produit **plus que** des attestations v2. Les attestations v1 déjà émises restent
vérifiables par le vérificateur v1 sous la politique v1, dont les octets ne
changent pas.

Le format du sujet diffère du v1 pour que les digests soient disjoints : la liste
des attestations d'un digest (§7) ne mêle jamais v1 et v2.

Inchangés et communs : la demande (`schemas/demande-v1.schema.json`, si bien
qu'un `request_id` est unique pour les deux versions), les ancres gouvernées
(`policy/ancres-v1.json`), la sortie du relecteur
(`schemas/sortie-relecteur-v1.schema.json`) et sa normalisation (§5).

## 1. Ce qu'une attestation prouve, et ce qu'elle ne prouve pas

Une attestation `urn:olistic:confiance:attestation-revue:2` prouve, pour qui la
vérifie selon §7 :

- que le workflow `.github/workflows/revue.yml` de ce dépôt, sur `refs/heads/main`,
  à un commit de workflow épinglé, exécuté par un runner hébergé par GitHub sur
  l'événement `issues`, a produit ce prédicat ;
- que le sujet a été recalculé par le workflow depuis le dépôt candidat, sa base
  étant l'ancre gouvernée du dépôt et non une donnée de la demande ;
- que le verdict est la normalisation (§5) de la sortie reçue du fournisseur pour
  le modèle déclaré, sous la politique, le protocole et les ancres dont les
  empreintes figurent dans le prédicat.

Elle ne prouve pas :

- que le code relu est sûr — un relecteur automatique peut se tromper ou être
  influencé par le contenu qu'il relit (injection d'instructions) ;
- **quel modèle a réellement été exécuté** : `relecteur.modele` est l'identifiant
  demandé au fournisseur et confirmé par lui dans sa réponse. Aucune preuve
  cryptographique ne lie la réponse à un modèle ni à des poids ; un identifiant
  sans date peut désigner des versions successives ;
- le contenu de la revue : la sortie brute n'est ni publiée ni conservée ; seul son
  sha256 (`rapport_sha256`) est attesté ;
- qu'un consommateur a effectivement vérifié l'attestation avant d'agir ;
- une approbation de classe B.

**Portée.** Tant que la politique déclare le relecteur `acceptable: false`, une
attestation v2 n'a **aucune valeur d'autorisation**, quel que soit son verdict. Le
prédicat recopie cette valeur (`relecteur.acceptable`) pour le lecteur humain ; seule
la politique épinglée fait foi pour le consommateur (§7). Une attestation produite
sous une politique où le relecteur n'est pas acceptable ne le devient jamais : une
politique ultérieure a une autre empreinte.

## 2. Demande

Identique à `revue/1` §2 (format `olistic.confiance.demande/1`, identité par
identifiant numérique, doublons de `request_id` sur tout l'historique). Le
dédoublonnage couvre les demandes antérieures quelle que soit la version de
protocole qui les a traitées.

## 3. Base gouvernée

Identique à `revue/1` §3, avec les mêmes ancres (`policy/ancres-v1.json`).

## 4. Sujet

Identique à `revue/1` §4 champ par champ, à deux différences près : `format` vaut
`olistic.confiance.sujet-revue/2`, et le nom du sujet est
`olistic-revue2:<alias>@<pointe>#<request_id>`. Le digest in-toto est le sha256 de
l'encodage canonique (JSON, clés triées, sans espace, UTF-8).

Le job de signature recalcule le sujet indépendamment et refuse de signer si le
prédicat reçu porte un autre sujet, d'autres empreintes de protocole, de politique
ou d'ancres, une autre demande, ou un instant incohérent.

## 5. Relecture et verdict

### 5.1 Relecteur `openai-responses`

- Un seul appel `POST https://api.openai.com/v1/responses`, hôte et chemin
  constants, sans redirection suivie, sans mandataire hérité de l'environnement,
  sans nouvelle tentative.
- Requête : `model` = premier modèle de la politique ; `instructions` = la
  consigne fixe `outils/consigne-relecteur-v2.txt` ; une seule entrée utilisateur
  portant le diff `base..pointe` encadré ; sortie structurée stricte
  (`text.format`, `json_schema`, `strict: true`) selon la projection §5.3 ;
  `store: false` ; aucun outil.
- Le relecteur n'exécute aucun code candidat, ne charge aucune instruction du
  candidat comme autorité et n'a accès ni au jeton de signature ni au jeton OIDC.
  L'encadrement du diff n'est pas une frontière de sécurité : son contenu reste
  non fiable.
- Clé du fournisseur : secret d'un environnement GitHub dédié, restreint à
  `main`, attaché au seul job de relecture ; jamais dans un prompt, une sortie,
  un message d'erreur ni un journal.
- Délai total borné par une minuterie murale ; réponse plafonnée en octets ;
  `Content-Encoding` autre que `identity` refusé.

### 5.2 Enveloppe fournisseur et sortie du relecteur

L'**enveloppe** est la réponse HTTP du fournisseur. Elle est valide si et seulement
si : statut HTTP 200 ; corps JSON UTF-8 sans clé en double ; `object` =
`response` ; `status` = `completed` ; `error` et `incomplete_details` nuls ou
absents ; `model` égal, octet pour octet, au modèle demandé ; `output` ne contient
que des éléments `reasoning` et `message` (rôle `assistant`), et les messages ne
contiennent que des parties `output_text` ; exactement une partie `output_text` en
tout.

**Toute enveloppe invalide fait refuser la demande : aucun prédicat, aucune
attestation.** Codes : `relecteur_cle_absente`, `relecteur_cle_invalide`,
`relecteur_minuterie`, `relecteur_configuration`,
`relecteur_connexion`, `relecteur_delai`, `relecteur_redirection`,
`relecteur_http_client`, `relecteur_quota`, `relecteur_http_serveur`,
`relecteur_encodage`, `relecteur_trop_grand`, `relecteur_enveloppe_illisible`,
`relecteur_statut`, `relecteur_modele_inattendu`, `relecteur_element_inattendu`,
`relecteur_refus_modele`, `relecteur_sortie_absente`, `relecteur_interne`.

La **sortie du relecteur** est le texte de l'unique `output_text` d'une enveloppe
valide, en octets UTF-8 exacts. Elle est normalisée exactement comme en `revue/1`
§5 :

| Sortie du relecteur | Verdict attesté | Motif |
|---|---|---|
| vide, illisible, non conforme à `sortie-relecteur-v1`, clé en double, casse ou valeur différente | `INDETERMINE` | `sortie_invalide` |
| `FAVORABLE` avec un constat `bloquant` ou `majeur` | `INDETERMINE` | `favorable_incoherent` |
| `INDETERMINE` | `INDETERMINE` | `relecteur` |
| diff au-delà de la limite de la politique (aucun appel) | `INDETERMINE` | `diff_trop_grand` |
| `FAVORABLE` ou `DEFAVORABLE` conforme | identique | `null` |

`rapport_sha256` = sha256 de la sortie du relecteur ; `null` seulement quand
aucune sortie n'a été obtenue (`diff_trop_grand`) ou qu'elle est vide.

### 5.3 Projection du schéma de sortie

Le schéma envoyé au fournisseur est **dérivé mécaniquement**, à chaque appel, de
`schemas/sortie-relecteur-v1.schema.json` : suppression de `$schema`, `$id`,
`title`, `description`, `minLength`, `maxLength` ; conservation de `type`,
`properties`, `required`, `additionalProperties`, `enum`, `items`, `minItems`,
`maxItems`, `pattern` ; tout autre mot-clé, tout objet ouvert ou dont une clé n'est
pas requise fait échouer. La projection ne fait que relâcher : le schéma local
reste l'autorité de §5.2.

## 6. Fraîcheur, révocation, rejeu

Identique à `revue/1` §6, sous la politique v2. Aucune opération acceptante
n'existe pour `revue/2` : aucun registre de consommation n'est utilisé.

## 7. Vérification par un consommateur

Identique à `revue/1` §7, avec : le type de prédicat v2, la politique v2 dont
l'empreinte exacte est épinglée, la génération de cette politique, le schéma
`schemas/attestation-revue-v2.schema.json`, le sujet et le nom de sujet v2, et
l'exigence supplémentaire `relecteur.acceptable` égal à la valeur de la
politique. Un relecteur non acceptable fait rejeter (`relecteur_non_acceptable`).

Référence exécutable : `outils/verifier2.py`, vérificateur **candidat**, distinct du
paquet consommateur v1, qu'il ne remplace pas.

## 8. Pont P1

Aucun. `revue/2` ne produit aucune `Review-Attestation`, et
`outils/pont_p1.py` n'accepte que des attestations v1.

## 9. Versions

Tout changement de format de demande, de sujet, de prédicat ou de règle de
normalisation crée `revue/3` et un nouveau type de prédicat. Un consommateur
n'accepte que les empreintes qu'il épingle.

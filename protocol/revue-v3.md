# Protocole de revue v3 — contrat dormant (`revue/3`)

Ce fichier définit le contrat dormant de `revue/3`. Son empreinte sha256 est
portée par les deux variantes de prédicat. Il ne modifie ni `revue/1`, ni
`revue/2`, ni leur vérificateur, ni le pont P1 existant.

## 0. Portée de l'incrément

`revue/3` introduit un espace de noms indépendant :

| Élément | Valeur v3 |
|---|---|
| protocole | `revue/3` |
| politique | `olistic.confiance.politique/3`, génération 3 |
| sujet | `olistic.confiance.sujet-revue/3` |
| prédicat | `urn:olistic:confiance:attestation-revue:3` |
| nom du sujet | `olistic-revue3:<alias>@<pointe>#<request_id>` |
| vérification | deux variantes fermées : synthétique locale ou Sigstore |
| autorisation | toujours fausse |

Le workflow courant reste un producteur `revue/2`. Aucun workflow ne produit,
ne signe ni ne publie une attestation v3 dans cet incrément.

## 1. Non-autorisation structurelle

La politique v3 est exclusivement `dormant`. Le schéma impose à chaque
relecteur `actif: false`, `acceptable: false` et des listes vides pour les
modèles, fournisseurs et endpoints. Le prédicat impose `autorisation: false`
et `relecteur.acceptable: false`. La variante synthétique impose des identités
de modèle, fournisseur et endpoint nulles ; la variante Sigstore les exige non
vides mais ne les ajoute jamais aux listes d'autorisation de la politique.

Une tentative d'activation est refusée par le chargeur de politique, y compris
si le prédicat synthétique porte un verdict `FAVORABLE`. Modifier seulement les
données de politique ne peut pas rendre le protocole actif : une évolution du
contrat, de ses schémas et de ses tests sera nécessaire.

Un verdict synthétique v3 est une donnée de test. Une attestation Sigstore v3
peut prouver cryptographiquement son intégrité et la provenance de son workflow,
mais elle ne constitue ni une permission, ni une approbation. La politique
dormante rend toute preuve v3 inacceptable par P1.

## 2. Interfaces communes conservées

La demande reste `olistic.confiance.demande/1`. Les ancres restent
`policy/ancres-v1.json`. Le calcul Git du sujet, l'encodage JSON canonique et
les fonctions d'empreinte sont réutilisés sans modification depuis
`outils/revue.py`.

Le format distinct du sujet rend son digest disjoint de ceux de v1 et v2. La
politique et le protocole v3 ont leurs propres empreintes. Aucun consommateur v1
ou v2 ne reconnaît le type de prédicat v3.

## 3. Sélection de la famille

La famille de l'auteur est calculée par une table fermée compatible avec P1 :

- `codex`, `gpt`, `chatgpt-codex` et `gpt-<suffixe>` appartiennent à
  `gpt-codex-family` ;
- `claude` et `claude-<suffixe>` appartiennent à `claude-family` ;
- toute autre valeur est refusée.

La politique contient des couples explicites `famille_auteur` →
`famille_relecture`. Dans cette génération, le seul couple est
`gpt-codex-family` → `claude-family`. Une famille absente de la table, une
sélection en double, un relecteur absent de la politique ou une famille de
relecture identique à celle de l'auteur sont refusés. Aucun fallback n'existe.

La présence de `claude-family` dans la politique ne valide aucun modèle,
fournisseur ou endpoint.

## 4. Sujet v3

Le sujet est recalculé comme en `revue/1`, puis son champ `format` devient
`olistic.confiance.sujet-revue/3`. Il contient l'identité numérique du dépôt,
les identités complètes des commits de base et de pointe et l'empreinte du
périmètre.

Son nom est
`olistic-revue3:<alias>@<pointe>#<request_id>` et son digest est le sha256 de
son JSON canonique UTF-8.

## 5. Deux variantes du même prédicat

Les deux variantes utilisent le même format
`olistic.confiance.attestation-revue/3`, le même type de prédicat et le même
sujet. Elles se distinguent par un bloc `verification` fermé. Aucun repli d'une
variante vers l'autre n'est permis.

### 5.1 Variante synthétique

Un prédicat synthétique lie exactement :

- le sujet v3 ;
- la demande admise et sa déclaration P1 ;
- les empreintes du présent protocole, de la politique v3 et des ancres ;
- la famille de relecture sélectionnée ;
- un verdict et l'empreinte d'un rapport synthétique ;
- un marqueur de portée non autorisante.

Le bloc `verification` porte obligatoirement :

- `nature: synthetique-hors-ligne` ;
- `cryptographie_effective: false` ;
- `signature_effective: false` ;
- `provenance_effective: false` ;
- la liste fermée des contrôles reportés.

Le schéma fermé interdit notamment tout champ `Approval-Attestation`. Le code
v3 ne produit ni document d'approbation, ni trailer d'approbation, ni signature.

La variante synthétique conserve en outre des identités de modèle, fournisseur
et endpoint nulles. Elle reste vérifiable par `verifier_synthetique`, mais le
vérificateur cryptographique et le pont P1 v3 la refusent systématiquement avec
`attestation_synthetique_refusee`, même si elle est placée dans une enveloppe
Sigstore valide.

### 5.2 Variante Sigstore

La variante Sigstore porte obligatoirement :

- `nature: cryptographique-sigstore` ;
- les trois marqueurs `cryptographie_effective`, `signature_effective` et
  `provenance_effective` à `true` ;
- une liste `controles_reportes` vide ;
- l'identité non vide du modèle, du fournisseur et de l'endpoint attestés ;
- `relecteur.acceptable: false` et `autorisation: false`.

Ces marqueurs sont des contraintes du prédicat, pas une preuve par eux-mêmes.
La preuve vient exclusivement du bundle Sigstore vérifié par
`gh attestation verify`, avec les épinglages du consommateur. Une simple
validation JSON ne peut donc jamais produire
`cryptographiquement_valide: true`.

## 6. Vérification

La politique est épinglée à `policy/confiance-v3.json`. Lorsqu'un chemin de
fichier est fourni, ses octets doivent être exactement identiques aux octets
livrés ; toute différence, y compris de présentation JSON, est refusée avec
`politique_non_epinglee`. Lorsqu'une fonction reçoit un objet JSON déjà décodé,
ses octets d'origine ne sont techniquement plus disponibles : elle compare
alors sa représentation `revue.canonique` à celle de la politique livrée.
Cette représentation est du JSON UTF-8, clés triées, sans espaces entre les
séparateurs et sans échappement ASCII forcé. Une divergence est refusée avec le
même motif avant toute sélection de famille ou vérification de prédicat.

La vérification synthétique hors ligne de `outils/verifier3.py` contrôle :

1. le schéma fermé du prédicat ;
2. l'égalité canonique du sujet attendu et du sujet embarqué ;
3. les empreintes locales de protocole, politique et ancres ;
4. la génération et l'état dormant de la politique ;
5. la sélection déterministe de la famille depuis l'auteur déclaré ;
6. la cohérence du verdict, du motif et du rapport ;
7. tous les marqueurs de vérification synthétique et de non-autorisation.

Une réussite synthétique signifie seulement `verifiee: true`,
`nature: synthetique-hors-ligne`, `autorisante: false`. Une entrée incohérente
est rejetée avec un motif fermé.

Le Lot 3A.3 ajoute une chaîne distincte `verifier_cryptographique` qui ne reçoit
aucun bundle, prédicat, verdict ou résultat de vérification de son appelant.
Elle :

1. charge une configuration du consommateur qui épingle la racine, les commits
   du workflow, les empreintes de protocole et de politique, l'identité exacte
   attendue et les empreintes révoquées ;
2. recalcule le digest du sujet fourni ;
3. liste tous les bundles de ce digest par l'API GitHub ;
4. télécharge chaque `bundle_url` par le transport borné existant ;
5. appelle `gh attestation verify` avec dépôt, workflow, ref, émetteur OIDC,
   type de prédicat et interdiction des runners auto-hébergés ;
6. contrôle champ par champ le certificat, l'énoncé in-toto, le sujet, la
   demande, les empreintes, l'identité de relecture, la fraîcheur et la
   révocation.

La configuration du consommateur constate l'identité attestée ; elle ne
l'ajoute pas aux listes d'autorisation vides de la politique.

Le résultat sépare trois propriétés :

- `cryptographiquement_valide` : la vérification Sigstore a réussi ;
- `conforme_au_contrat` : provenance, sujet, empreintes, identité, fraîcheur et
  révocation sont conformes ;
- `acceptable_p1` : toujours `false` dans ce lot.

Les deux premières peuvent être vraies dans les tests. La troisième ne peut
jamais l'être tant que la politique livrée reste dormante.

## 7. Contrôles encore reportés

Restent hors de cet incrément et explicitement non implémentés :

- appel OpenRouter réel, preuve fournisseur indépendante du workflow,
  Broadcast et contrôles administratifs de compte ;
- signature et publication Sigstore par un workflow réel ;
- toute production opérationnelle d'une `Review-Attestation` ;
- `Approval-Attestation`, qui reste une preuve humaine distincte en classe B ;
- activation de workflow, environnement, secret ou budget.

## 8. Pont P1 v3 dormant

`outils/pont_p1_v3.py` réutilise le sujet v3, le vérificateur Sigstore, le
registre atomique existant et le contrat SSH exact de P1. Sa seule opération de
signature est explicitement une simulation hors ligne non autorisante :

- principal préfixé `test-` et dépôt P1 sous `test.invalid/` ;
- registre GitHub opérationnel refusé ;
- clé SSH éphémère non gouvernée par P1 ;
- `Review-Reference` préfixée `TEST-NON-AUTORISANT:` ;
- résultat extérieur portant `acceptable_p1: false` ;
- aucune `Approval-Attestation`, aucun `Approved-by`.

Le document et sa signature sont compatibles avec le parseur P1, mais P1 les
refuse parce que l'identité de test n'est pas gouvernée. La simulation consomme
néanmoins son `request_id` dans un registre de test atomique afin d'éprouver le
rejeu, la concurrence et les échecs partiels. Ajouter un chemin opérationnel
exigera un nouveau changement contractuel, une revue indépendante et
l'approbation humaine de classe B.

## 9. Versions et évolution

Les fichiers v1/v2, les composants du Lot 3A.2 et
`.github/workflows/revue.yml` sont intangibles dans ce lot. La variante
Sigstore ne rend pas rétroactivement cryptographique ou autorisante une
attestation synthétique produite sous une empreinte antérieure ou courante.

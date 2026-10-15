# Protocole de revue v3 — socle contractuel inerte (`revue/3`)

Ce fichier définit uniquement le premier incrément dormant de `revue/3`. Son
empreinte sha256 est portée par les prédicats synthétiques. Il ne modifie ni
`revue/1`, ni `revue/2`, ni leur vérificateur, ni le pont P1 existant.

## 0. Portée de l'incrément

`revue/3` introduit un espace de noms indépendant :

| Élément | Valeur v3 |
|---|---|
| protocole | `revue/3` |
| politique | `olistic.confiance.politique/3`, génération 3 |
| sujet | `olistic.confiance.sujet-revue/3` |
| prédicat | `urn:olistic:confiance:attestation-revue:3` |
| nom du sujet | `olistic-revue3:<alias>@<pointe>#<request_id>` |
| vérification | synthétique, locale, hors ligne |
| autorisation | toujours fausse |

Le workflow courant reste un producteur `revue/2`. Aucun workflow ne produit,
ne signe ni ne publie une attestation v3 dans cet incrément.

## 1. Non-autorisation structurelle

La politique v3 est exclusivement `dormant`. Le schéma impose à chaque
relecteur `actif: false`, `acceptable: false` et des listes vides pour les
modèles, fournisseurs et endpoints. Le prédicat impose `autorisation: false`,
`relecteur.acceptable: false` et des identités de modèle, fournisseur et
endpoint nulles.

Une tentative d'activation est refusée par le chargeur de politique, y compris
si le prédicat synthétique porte un verdict `FAVORABLE`. Modifier seulement les
données de politique ne peut pas rendre le protocole actif : une évolution du
contrat, de ses schémas et de ses tests sera nécessaire.

Un verdict v3 de cet incrément est une donnée de test. Il n'est ni une revue
cryptographiquement prouvée, ni une permission, ni une approbation.

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

## 5. Prédicat synthétique

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

## 6. Vérification hors ligne

La politique est épinglée à `policy/confiance-v3.json`. Lorsqu'un chemin de
fichier est fourni, ses octets doivent être exactement identiques aux octets
livrés ; toute différence, y compris de présentation JSON, est refusée avec
`politique_non_epinglee`. Lorsqu'une fonction reçoit un objet JSON déjà décodé,
ses octets d'origine ne sont techniquement plus disponibles : elle compare
alors sa représentation `revue.canonique` à celle de la politique livrée.
Cette représentation est du JSON UTF-8, clés triées, sans espaces entre les
séparateurs et sans échappement ASCII forcé. Une divergence est refusée avec le
même motif avant toute sélection de famille ou vérification de prédicat.

`outils/verifier3.py` contrôle sur des objets synthétiques :

1. le schéma fermé du prédicat ;
2. l'égalité canonique du sujet attendu et du sujet embarqué ;
3. les empreintes locales de protocole, politique et ancres ;
4. la génération et l'état dormant de la politique ;
5. la sélection déterministe de la famille depuis l'auteur déclaré ;
6. la cohérence du verdict, du motif et du rapport ;
7. tous les marqueurs de vérification synthétique et de non-autorisation.

Une réussite signifie seulement `verifiee: true`,
`nature: synthetique-hors-ligne`, `autorisante: false`. Une entrée incohérente
est rejetée avec un motif fermé. L'interface de vérification cryptographique
échoue explicitement avec `verification_cryptographique_non_implementee` ; elle
ne délègue jamais silencieusement à la vérification synthétique.

## 7. Contrôles reportés

Sont hors de cet incrément et explicitement non implémentés :

- transport OpenRouter, identité de modèle, fournisseur et endpoint, ZDR,
  collecte, fallback, BYOK, Broadcast et plafond financier ;
- signature et publication Sigstore, récupération d'attestations et preuve de
  provenance du workflow ;
- pont P1 v3, consommation anti-rejeu et toute production de
  `Review-Attestation` ;
- `Approval-Attestation`, qui reste une preuve humaine distincte en classe B ;
- activation de workflow, environnement, secret ou budget.

## 8. Versions et évolution

Les fichiers v1/v2 et `.github/workflows/revue.yml` sont intangibles dans ce
lot. Les incréments suivants ajouteront leurs propres contrôles sans rendre
rétroactivement autorisante une attestation synthétique produite sous cette
politique et cette empreinte.

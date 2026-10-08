# Sécurité

Signaler une vulnérabilité par le signalement privé de GitHub (onglet Security),
jamais par une issue : les issues de ce dépôt sont publiques et servent de canal
de demande automatisé.

Ce dépôt est une racine de confiance. Toute faiblesse qui permettrait d'obtenir
une attestation signée par `.github/workflows/revue.yml@refs/heads/main` pour un
sujet ou un verdict qui n'est pas le résultat du protocole `revue/1` est dans le
périmètre — en particulier : faire signer un prédicat non recalculé, faire
exécuter une autre version du workflow, obtenir un jeton OIDC de ce dépôt hors
du job `attestation`, faire paraître dans une attestation une donnée privée, faire admettre une
demande sous l'identité d'un demandeur par son seul login, consommer deux fois
un même `request_id`, obtenir une `Review-Attestation` sans attestation vérifiée
et consommée, ou faire accepter un bundle qui ne vient pas de `bundle_url`.

Pour `revue/2` également : faire apparaître la clé du relecteur hors de l'en-tête
d'autorisation (prompt, journal, sortie, attestation, autre job), faire émettre une
attestation à partir d'une enveloppe fournisseur invalide, faire exécuter par le
relecteur un outil ou du code venu du candidat, ou faire accepter par un
vérificateur une attestation d'un relecteur non acceptable.

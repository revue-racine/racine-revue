#!/usr/bin/env python3
"""Pont P2 → P1 : production de la `Review-Attestation` SSH attendue par le P1.

Le P1 (figé) n'accepte qu'une attestation SSH détachée, portée par le trailer
`Review-Attestation` de la fusion : base64 de `{document, signature, principal}`,
`document` ayant exactement les clés `CLES_ATTESTATION_P1`, signé par
`ssh-keygen -Y sign` dans l'espace `olistic-gouvernance-revue` sur l'encodage
canonique du document, par un relecteur gouverné de la famille attendue.

Une seule opération publique : `verifier_consommer_et_signer`. Elle ne reçoit
que des références (request_id, alias, pointe) et sa configuration ; elle
récupère elle-même les attestations (API GitHub, `bundle_url`), les vérifie
(Sigstore, provenance, politique, protocole, génération, coupure, fraîcheur,
sujet recalculé, verdict), réserve le request_id dans le registre atomique,
construit le document P1 et le signe, dans cet ordre et sans frontière
publique entre ces étapes. Aucune API n'accepte une décision, un verdict, un
résultat de vérification, un document ou des octets à signer.

Elle ne fait foi que dans le job protégé du dépôt de confiance (protocole §8),
où la clé, le jeton du registre et le code lui-même sont hors de portée de
l'hôte des agents. Lot 1 : aucun workflow ne l'appelle, aucune clé réelle.
"""
import base64
import datetime
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import registre as registre_mod  # noqa: E402
import revue  # noqa: E402
import verifier  # noqa: E402

FORMAT_P1 = "olistic.gouvernance.attestation/1"
ESPACE_REVUE_P1 = "olistic-gouvernance-revue"
CLES_ATTESTATION_P1 = frozenset({"format", "role", "depot", "pointe", "arbre", "classe", "auteur", "relecteur",
                                 "reference_revue", "reference_approbation", "instant"})
# Famille P2 → valeur P1 de `Reviewed-by` et famille du relecteur gouverné (§26.5).
FAMILLES_P1 = {"codex": "gpt-codex-family"}


@dataclass(frozen=True)
class ConfigPont:
    confiance: str      # configuration épinglée du consommateur (JSON)
    politique: str      # politique dont l'empreinte est épinglée
    ancres: str         # ancres gouvernées
    cle: str            # clé SSH du relecteur-p2 (secret d'environnement)
    principal: str
    depot_p1: str       # valeur `depot` du P1 (variable privée d'environnement)
    url_candidat: str
    protocoles: tuple = ("https",)
    jeton: str = ""     # jeton du job pour l'API de liste (facultatif, dépôt public)


def _horloge():
    return datetime.datetime.now(datetime.timezone.utc)


def verifier_consommer_et_signer(config, request_id, alias, pointe, registre):
    """Vérifie, consomme le request_id et signe. Rend les trailers de fusion à
    poser, `Review-Attestation` compris. Tout échec lève `revue.Refus` ; un
    échec après réservation clôt le request_id en ECHEC, jamais en DISPONIBLE."""
    if not isinstance(registre, registre_mod.RegistreConsommation):
        raise revue.Refus("registre_absent")
    if not isinstance(config, ConfigPont) or not config.depot_p1:
        raise revue.Refus("configuration_pont_invalide")
    demande = {"format": "olistic.confiance.demande/1", "request_id": request_id, "depot": alias, "pointe": pointe,
               "declaration_p1": {"classe": "A", "auteur": "inconnu"}}  # désignation seule : déclaration lue dans l'attestation
    revue.exiger(demande, "demande", "demande_invalide")
    conf, pol = verifier.charger_confiance(config.confiance, config.politique)
    ancres = revue.charger_ancres(pol, config.ancres)
    etat, _ = registre.etat(request_id)
    if etat != registre_mod.DISPONIBLE:
        raise revue.Refus("request_id_deja_consomme", etat)

    with tempfile.TemporaryDirectory(prefix="pont-p1-") as tmp:
        sujet, _ = revue.calculer_sujet(demande, pol, ancres, config.url_candidat, Path(tmp) / "git", config.protocoles)
        resultats = verifier.recuperer_resultats(conf, sujet, tmp, jeton=config.jeton or None)
    decision = verifier.evaluer(resultats, sujet, request_id, conf, pol, _horloge())
    if not decision.acceptee or decision["verdicts"].count("FAVORABLE") != 1 or "DEFAVORABLE" in decision["verdicts"]:
        raise revue.Refus("non_acceptee", decision.get("motif", ""))
    predicat = decision["predicat"]
    famille = FAMILLES_P1.get(predicat["relecteur"]["famille"])
    if famille is None:
        raise revue.Refus("famille_sans_equivalent_p1")
    sujet_sha256 = revue.sha256_hex(revue.canonique(sujet))
    liaison = {"request_id": request_id, "depot": alias, "pointe": pointe, "sujet_sha256": sujet_sha256,
               "predicat_sha256": revue.sha256_hex(revue.canonique(predicat)),
               "instant_verifie": decision["instant_verifie"]}

    registre.reserver(request_id, liaison)  # point de non-retour : atomique, unique
    try:
        decl = predicat["demande"]["declaration_p1"]
        document = {
            "format": FORMAT_P1,
            "role": "revue",
            "depot": config.depot_p1,
            "pointe": sujet["pointe"]["commit"],
            "arbre": sujet["pointe"]["arbre"],
            "classe": decl["classe"],
            "auteur": decl["auteur"],
            "relecteur": famille,
            "reference_revue": f"olistic-revue:sha256:{sujet_sha256}#{request_id}",
            "reference_approbation": None,
            "instant": decision["instant_verifie"],
        }
        if set(document) != CLES_ATTESTATION_P1 or revue.canonique(predicat["sujet"]) != revue.canonique(sujet) \
                or predicat["demande"]["request_id"] != request_id or document["pointe"] != pointe:
            raise revue.Refus("substitution_detectee")
        octets = revue.canonique(document)
        registre.controler_reservation(request_id, liaison)
        with tempfile.TemporaryDirectory(prefix="pont-p1-sig-") as tmp:
            chemin = Path(tmp) / "document"
            chemin.write_bytes(octets)
            r = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "sign", "-q", "-f", str(config.cle), "-n", ESPACE_REVUE_P1,
                                str(chemin)], capture_output=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            if r.returncode != 0:
                raise revue.Refus("signature_impossible")
            signature = (Path(tmp) / "document.sig").read_text("utf-8")
        registre.marquer_signe(request_id, liaison, revue.sha256_hex(octets))
    except revue.Refus as e:
        _clore_en_echec(registre, request_id, liaison, e.motif)
        raise
    except Exception as e:  # noqa: BLE001
        _clore_en_echec(registre, request_id, liaison, "erreur_interne")
        raise revue.Refus("erreur_interne", type(e).__name__)
    porteur = {"document": document, "signature": signature, "principal": config.principal}
    return {
        "Agent": document["auteur"],
        "Reviewed-by": document["relecteur"],
        "Reviewed-commit": document["pointe"],
        "Review-Reference": document["reference_revue"],
        "Review-Attestation": base64.b64encode(json.dumps(porteur, ensure_ascii=False).encode("utf-8")).decode("ascii"),
    }


def _clore_en_echec(registre, request_id, liaison, motif):
    """Meilleur effort : si la clôture échoue aussi, l'état reste RESERVE,
    diagnosticable et clos ensuite par `RegistreConsommation.clore_en_echec`."""
    try:
        registre.marquer_echec(request_id, liaison, motif)
    except revue.Refus:
        pass

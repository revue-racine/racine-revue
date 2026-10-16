#!/usr/bin/env python3
"""Pont P1 v3 dormant : simulation SSH explicitement non autorisante.

Il n'existe volontairement aucune opération de production. L'unique opération
publique exige des marqueurs de test, refuse le transport de registre GitHub,
vérifie elle-même la preuve Sigstore depuis ses références, consomme le
`request_id` dans le registre atomique, puis signe un document P1 avec une clé
de test non gouvernée.
"""
import base64
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import registre as registre_mod  # noqa: E402
import revue  # noqa: E402
import revue3  # noqa: E402
import verifier3  # noqa: E402

FORMAT_P1 = "olistic.gouvernance.attestation/1"
ESPACE_REVUE_P1 = "olistic-gouvernance-revue"
CLES_ATTESTATION_P1 = frozenset({
    "format", "role", "depot", "pointe", "arbre", "classe", "auteur",
    "relecteur", "reference_revue", "reference_approbation", "instant",
})
PREFIXE_REFERENCE_TEST = "TEST-NON-AUTORISANT:"


@dataclass(frozen=True)
class ConfigPontV3Test:
    confiance: str
    politique: str
    ancres: str
    cle_test: str
    principal_test: str
    depot_p1_test: str
    url_candidat: str
    protocoles: tuple = ("file",)
    jeton: str = ""


@dataclass(frozen=True)
class ResultatPontV3Test:
    cryptographiquement_valide: bool
    conforme_au_contrat: bool
    acceptable_p1: bool
    nature: str
    trailers: dict
    document: dict


def _horloge():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def _config_test_valide(config):
    return (
        isinstance(config, ConfigPontV3Test)
        and config.principal_test.startswith("test-")
        and config.depot_p1_test.startswith("test.invalid/")
        and config.protocoles == ("file",)
        and not config.jeton
    )


def verifier_consommer_et_signer_test_non_autorisant(
        config, request_id, alias, pointe, registre):
    """Produit uniquement une simulation de `Review-Attestation`.

    Aucun résultat, prédicat, verdict, document ou octet à signer n'est accepté
    depuis l'appelant. Un échec après réservation clôt le `request_id` en
    `ECHEC` et ne le remet jamais à disposition.
    """
    if not _config_test_valide(config):
        raise revue.Refus("configuration_test_invalide")
    if not isinstance(registre, registre_mod.RegistreConsommation):
        raise revue.Refus("registre_absent")
    if isinstance(getattr(registre, "_t", None), registre_mod.TransportRefsGitHub):
        raise revue.Refus("registre_operationnel_interdit")

    politique = revue3.charger_politique(config.politique)
    ancres = revue.charger_ancres(politique, config.ancres)
    demande = {
        "format": "olistic.confiance.demande/1",
        "request_id": request_id,
        "depot": alias,
        "pointe": pointe,
        "declaration_p1": {"classe": "A", "auteur": "codex"},
    }
    revue.exiger(demande, "demande", "demande_invalide")
    etat, _ = registre.etat(request_id)
    if etat != registre_mod.DISPONIBLE:
        raise revue.Refus("request_id_deja_consomme", etat)

    with tempfile.TemporaryDirectory(prefix="pont-p1-v3-verif-") as tmp:
        sujet, _ = revue3.calculer_sujet(
            demande, politique, ancres, config.url_candidat,
            Path(tmp) / "git", config.protocoles,
        )
        decision = verifier3.verifier_cryptographique(
            config.confiance,
            config.politique,
            sujet,
            request_id,
            Path(tmp) / "sigstore",
            maintenant=_horloge(),
            jeton=None,
        )
    if not decision.cryptographiquement_valide:
        raise revue.Refus(decision.motif)
    if not decision.conforme_au_contrat:
        raise revue.Refus(decision.motif)
    if decision.verdict != "FAVORABLE" \
            or decision.motif != "politique_dormante":
        raise revue.Refus("decision_v3_incoherente", decision.motif)
    if decision.acceptable_p1 is not False:
        raise revue.Refus("activation_interdite")
    predicat = decision.predicat
    verdict_predicat = predicat.get("verdict") if type(predicat) is dict else None
    if type(verdict_predicat) is not str or verdict_predicat != "FAVORABLE":
        raise revue.Refus("decision_v3_incoherente", "predicat")
    verification = predicat.get("verification")
    if type(verification) is not dict \
            or verification.get("nature") != verifier3.NATURE_CRYPTOGRAPHIQUE:
        raise revue.Refus("attestation_synthetique_refusee")

    sujet_sha256 = revue.sha256_hex(revue.canonique(sujet))
    liaison = {
        "request_id": request_id,
        "depot": alias,
        "pointe": pointe,
        "sujet_sha256": sujet_sha256,
        "preuve_sha256": decision.preuve_sha256,
        "instant_verifie": decision.instant_verifie,
    }
    registre.reserver(request_id, liaison)
    try:
        declaration = predicat["demande"]["declaration_p1"]
        reference = (
            f"{PREFIXE_REFERENCE_TEST}olistic-revue3:"
            f"sha256:{sujet_sha256}#{request_id}"
        )
        document = {
            "format": FORMAT_P1,
            "role": "revue",
            "depot": config.depot_p1_test,
            "pointe": sujet["pointe"]["commit"],
            "arbre": sujet["pointe"]["arbre"],
            "classe": declaration["classe"],
            "auteur": declaration["auteur"],
            "relecteur": predicat["relecteur"]["famille"],
            "reference_revue": reference,
            "reference_approbation": None,
            "instant": decision.instant_verifie,
        }
        if set(document) != CLES_ATTESTATION_P1 \
                or revue.canonique(predicat["sujet"]) != revue.canonique(sujet) \
                or predicat["demande"]["request_id"] != request_id \
                or document["pointe"] != pointe:
            raise revue.Refus("substitution_detectee")
        octets = revue.canonique(document)
        registre.controler_reservation(request_id, liaison)
        with tempfile.TemporaryDirectory(prefix="pont-p1-v3-ssh-test-") as tmp:
            chemin = Path(tmp) / "document"
            chemin.write_bytes(octets)
            resultat = subprocess.run(
                [
                    "/usr/bin/ssh-keygen", "-Y", "sign", "-q",
                    "-f", config.cle_test, "-n", ESPACE_REVUE_P1, str(chemin),
                ],
                capture_output=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            if resultat.returncode != 0:
                raise revue.Refus("signature_test_impossible")
            signature = (Path(tmp) / "document.sig").read_text("utf-8")
        registre.marquer_signe(request_id, liaison, revue.sha256_hex(octets))
    except revue.Refus as e:
        _clore_en_echec(registre, request_id, liaison, e.motif)
        raise
    except Exception as e:  # noqa: BLE001
        _clore_en_echec(registre, request_id, liaison, "erreur_interne")
        raise revue.Refus("erreur_interne", type(e).__name__) from None

    porteur = {
        "document": document,
        "signature": signature,
        "principal": config.principal_test,
    }
    trailers = {
        "Agent": document["auteur"],
        "Reviewed-by": document["relecteur"],
        "Reviewed-commit": document["pointe"],
        "Review-Reference": document["reference_revue"],
        "Review-Attestation": base64.b64encode(
            json.dumps(porteur, ensure_ascii=False).encode("utf-8")
        ).decode("ascii"),
    }
    return ResultatPontV3Test(
        cryptographiquement_valide=True,
        conforme_au_contrat=True,
        acceptable_p1=False,
        nature="simulation-hors-ligne-non-autorisante",
        trailers=trailers,
        document=document,
    )


def _clore_en_echec(registre, request_id, liaison, motif):
    try:
        registre.marquer_echec(request_id, liaison, motif)
    except revue.Refus:
        pass

#!/usr/bin/env python3
"""Vérificateurs hors ligne des deux variantes d'attestation ``revue/3``.

La variante synthétique conserve exactement le comportement du Lot 3A.1. La
variante Sigstore n'accepte jamais un résultat fourni par son appelant : elle
liste les bundles du sujet, les télécharge, puis réutilise
``gh attestation verify`` et les contrôles de provenance du vérificateur v1.

Une preuve Sigstore peut être cryptographiquement valide et conforme au contrat
sans être acceptable par P1. Sous la politique v3 livrée, ``acceptable_p1`` est
structurellement et systématiquement faux.
"""
import argparse
import datetime
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import revue  # noqa: E402
import revue3  # noqa: E402
import schema_strict  # noqa: E402
import verifier  # noqa: E402

NATURE_CRYPTOGRAPHIQUE = "cryptographique-sigstore"
VERIFICATION_SYNTHETIQUE = {
    "nature": revue3.NATURE_SYNTHETIQUE,
    "cryptographie_effective": False,
    "signature_effective": False,
    "provenance_effective": False,
    "controles_reportes": list(revue3.CONTROLES_REPORTES),
}
VERIFICATION_CRYPTOGRAPHIQUE = {
    "nature": NATURE_CRYPTOGRAPHIQUE,
    "cryptographie_effective": True,
    "signature_effective": True,
    "provenance_effective": True,
    "controles_reportes": [],
}
CLES_IDENTITE = {"famille", "modele", "fournisseur", "endpoint"}
CLES_CONFIANCE_CRYPTO = verifier.CLES_CONFIANCE | {"identite_relecteur", "revocations"}


@dataclass(frozen=True)
class DecisionSynthetique:
    verifiee: bool
    autorisante: bool
    nature: str
    motif: str
    verdict: str | None
    sujet_digest: str | None


@dataclass(frozen=True)
class DecisionCryptographique:
    cryptographiquement_valide: bool
    conforme_au_contrat: bool
    acceptable_p1: bool
    nature: str
    motif: str
    verdict: str | None = None
    sujet_digest: str | None = None
    preuve_sha256: str | None = None
    instant_verifie: str | None = None
    predicat: dict | None = None


def _rejet_synthetique(motif):
    return DecisionSynthetique(
        verifiee=False,
        autorisante=False,
        nature=revue3.NATURE_SYNTHETIQUE,
        motif=motif,
        verdict=None,
        sujet_digest=None,
    )


def _decision_crypto(crypto, contrat, motif, **champs):
    return DecisionCryptographique(
        cryptographiquement_valide=crypto,
        conforme_au_contrat=contrat,
        acceptable_p1=False,
        nature=NATURE_CRYPTOGRAPHIQUE,
        motif=motif,
        **champs,
    )


def controler_synthetique(predicat, sujet, politique):
    """Contrôle 3A.1 inchangé, avec discrimination explicite de variante."""
    revue3.controler_politique(politique)
    revue3.controler_invariants(predicat, politique)
    if predicat.get("verification") != VERIFICATION_SYNTHETIQUE:
        raise revue.Refus("attestation_invalide", "variante synthétique incohérente")
    identite = predicat.get("relecteur") or {}
    if any(identite.get(cle) is not None for cle in ("modele", "fournisseur", "endpoint")):
        raise revue.Refus("attestation_invalide", "identité interdite dans la variante synthétique")
    octets_sujet = revue.canonique(sujet)
    if revue.canonique(predicat["sujet"]) != octets_sujet:
        raise revue.Refus("sujet_divergent")
    empreintes = revue3.empreintes_locales()
    presentes = (
        predicat["protocole"]["sha256"],
        predicat["politique"]["sha256"],
        predicat["ancres_sha256"],
    )
    attendues = (empreintes["protocole"], empreintes["politique"], empreintes["ancres"])
    if presentes != attendues:
        raise revue.Refus("empreintes_divergentes")
    if predicat["protocole"]["version"] != revue3.VERSION_PROTOCOLE:
        raise revue.Refus("protocole_divergent")
    return predicat, revue.sha256_hex(octets_sujet)


def verifier_synthetique(predicat, sujet, politique=None):
    """Vérifie le contrat local ; la décision reste toujours non autorisante."""
    try:
        if politique is None:
            politique = revue3.charger_politique()
        revue3.controler_politique(politique)
        predicat, digest = controler_synthetique(predicat, sujet, politique)
    except (revue.Refus, KeyError, TypeError) as e:
        motif = e.motif if isinstance(e, revue.Refus) else "attestation_illisible"
        return _rejet_synthetique(motif)
    return DecisionSynthetique(
        verifiee=True,
        autorisante=False,
        nature=revue3.NATURE_SYNTHETIQUE,
        motif="politique_dormante",
        verdict=predicat["verdict"],
        sujet_digest=digest,
    )


def _chaine_identite(valeur, maximum):
    return (
        isinstance(valeur, str)
        and 0 < len(valeur) <= maximum
        and all(caractere.isprintable() for caractere in valeur)
    )


def charger_confiance_cryptographique(chemin_confiance, chemin_politique=None):
    """Charge les épinglages du consommateur, distincts d'une autorisation.

    L'identité attendue sert à vérifier ce que le workflow a attesté. Elle ne
    peuple pas les listes vides de la politique et ne rend donc aucun modèle,
    fournisseur ou endpoint acceptable.
    """
    try:
        conf = revue.charger_json_strict(Path(chemin_confiance).read_bytes())
    except (OSError, ValueError) as e:
        raise revue.Refus("confiance_v3_invalide", type(e).__name__) from None
    if not isinstance(conf, dict) or set(conf) != CLES_CONFIANCE_CRYPTO:
        raise revue.Refus("confiance_v3_invalide", "clés")
    identite = conf.get("identite_relecteur")
    if not isinstance(identite, dict) or set(identite) != CLES_IDENTITE:
        raise revue.Refus("confiance_v3_invalide", "identite_relecteur")
    if identite.get("famille") not in ("gpt-codex-family", "claude-family") \
            or not _chaine_identite(identite.get("modele"), 160) \
            or not _chaine_identite(identite.get("fournisseur"), 80) \
            or not _chaine_identite(identite.get("endpoint"), 160):
        raise revue.Refus("confiance_v3_invalide", "identite_relecteur")
    commits = conf.get("commits_racine")
    if not isinstance(commits, list) or not commits or len(commits) != len(set(commits)) \
            or any(re.fullmatch(r"[0-9a-f]{40}", c or "") is None for c in commits):
        raise revue.Refus("confiance_v3_invalide", "commits_racine")
    revocations = conf.get("revocations")
    if not isinstance(revocations, list) or len(revocations) != len(set(revocations)) \
            or any(re.fullmatch(r"[0-9a-f]{64}", x or "") is None for x in revocations):
        raise revue.Refus("confiance_v3_invalide", "revocations")

    politique = revue3.charger_politique(chemin_politique)
    empreintes = revue3.empreintes_locales()
    if conf.get("politique_sha256") != empreintes["politique"]:
        raise revue.Refus("politique_non_epinglee")
    if conf.get("protocole_sha256") != empreintes["protocole"]:
        raise revue.Refus("protocole_non_epingle")
    if conf.get("generation") != 3 or conf.get("type_predicat") != revue3.TYPE_PREDICAT:
        raise revue.Refus("confiance_v3_invalide", "version")
    racine = politique["racine"]
    for cle in ("proprietaire", "proprietaire_id", "depot", "depot_id", "workflow", "nom_workflow", "ref"):
        if conf.get(cle) != racine[cle]:
            raise revue.Refus("confiance_v3_invalide", f"racine.{cle}")
    familles = {r["famille"] for r in politique["relecteurs"]}
    if identite["famille"] not in familles:
        raise revue.Refus("confiance_v3_invalide", "famille_relecteur")
    return conf, politique


def _empreinte_enonce(enonce):
    return revue.sha256_hex(revue.canonique(enonce))


def _controler_resultat_cryptographique(resultat, sujet, request_id, conf, politique, maintenant):
    try:
        vr = resultat["verificationResult"]
        certificat = vr["signature"]["certificate"]
        enonce = vr["statement"]
    except (KeyError, TypeError):
        raise verifier.Invalide("resultat_illisible")

    motif = verifier.controler_certificat(certificat, conf)
    if motif:
        raise verifier.Invalide(motif)
    if enonce.get("_type") != verifier.TYPE_INTOTO:
        raise verifier.Invalide("type_intoto")
    if enonce.get("predicateType") != revue3.TYPE_PREDICAT:
        raise verifier.Invalide("type_predicat")
    predicat = enonce.get("predicate")
    if schema_strict.erreurs(predicat, revue3.schema("attestation-revue")):
        raise verifier.Invalide("predicat_invalide")
    if predicat["verification"]["nature"] == revue3.NATURE_SYNTHETIQUE:
        raise verifier.Invalide("attestation_synthetique_refusee")
    if predicat["verification"] != VERIFICATION_CRYPTOGRAPHIQUE:
        raise verifier.Invalide("predicat_invalide")

    octets_sujet = revue.canonique(sujet)
    sujets = enonce.get("subject")
    if not isinstance(sujets, list) or len(sujets) != 1 \
            or sujets[0].get("digest") != {"sha256": revue.sha256_hex(octets_sujet)}:
        raise verifier.Invalide("digest_sujet")
    if sujets[0].get("name") != revue3.nom_sujet(sujet, request_id):
        raise verifier.Invalide("nom_sujet")
    if revue.canonique(predicat["sujet"]) != octets_sujet:
        raise verifier.Invalide("sujet_divergent")
    if predicat["demande"]["request_id"] != request_id:
        raise verifier.Invalide("request_id_divergent")
    if predicat["protocole"] != {"version": revue3.VERSION_PROTOCOLE, "sha256": conf["protocole_sha256"]}:
        raise verifier.Invalide("protocole_different")
    attendu_politique = {
        "version": politique["version"],
        "generation": politique["generation"],
        "etat": politique["etat"],
        "sha256": conf["politique_sha256"],
    }
    if predicat["politique"] != attendu_politique or predicat["ancres_sha256"] != revue3.empreintes_locales()["ancres"]:
        raise verifier.Invalide("politique_differente")
    if (predicat["verdict"] == "INDETERMINE") != (predicat["motif"] is not None):
        raise verifier.Invalide("predicat_invalide")

    identite = conf["identite_relecteur"]
    try:
        famille = revue3.selectionner_famille(
            predicat["demande"]["declaration_p1"]["auteur"], politique
        )
    except revue.Refus as e:
        raise verifier.Invalide(e.motif) from None
    if predicat["relecteur"]["famille"] != famille or identite["famille"] != famille:
        raise verifier.Invalide("famille_relecture_divergente")
    for cle in ("modele", "fournisseur", "endpoint"):
        if predicat["relecteur"][cle] != identite[cle]:
            raise verifier.Invalide(f"{cle}_non_admis")
    if predicat["relecteur"]["acceptable"] is not False or predicat["autorisation"] is not False:
        raise verifier.Invalide("attestation_autorisante_interdite")

    instant_verifie = verifier.instant_verifie(vr, politique, maintenant)
    instant_predicat = revue.instant_utc(predicat["instant"])
    ecart = (instant_verifie - instant_predicat).total_seconds() if instant_predicat else None
    fraicheur = politique["fraicheur"]
    if ecart is None or not (-fraicheur["derive_horloge_s"] <= ecart <= fraicheur["tolerance_instant_s"]):
        raise verifier.Invalide("instant_incoherent")
    preuve_sha256 = _empreinte_enonce(enonce)
    if preuve_sha256 in conf["revocations"]:
        raise verifier.Invalide("attestation_revoquee")
    return predicat, instant_verifie, preuve_sha256


def _evaluer_resultats_verifies(resultats, sujet, request_id, conf, politique, maintenant):
    """Évalue exclusivement des résultats déjà rendus par ``gh verify``."""
    if not resultats:
        return _decision_crypto(False, False, "aucune_attestation_pour_la_demande")
    propres = []
    propres_invalides = []
    autres_defavorables = []
    for resultat in resultats:
        try:
            rid = resultat["verificationResult"]["statement"]["predicate"]["demande"]["request_id"]
        except (KeyError, TypeError):
            rid = None
        try:
            predicat, instant, empreinte = _controler_resultat_cryptographique(
                resultat, sujet, request_id if rid == request_id else rid, conf, politique, maintenant
            )
        except verifier.Invalide as e:
            if rid == request_id:
                propres_invalides.append(e.motif)
            continue
        if rid == request_id:
            propres.append((predicat, instant, empreinte))
        elif predicat["verdict"] == "DEFAVORABLE":
            autres_defavorables.append((predicat, instant, empreinte))
    if propres_invalides:
        return _decision_crypto(True, False, min(propres_invalides))
    if not propres:
        return _decision_crypto(True, False, "aucune_attestation_pour_la_demande")

    verdicts = sorted({p[0]["verdict"] for p in propres})
    def cle_decision(element):
        return element[1], element[0]["demande"]["issue"], element[2]
    defavorables_propres = [p for p in propres if p[0]["verdict"] == "DEFAVORABLE"]
    if defavorables_propres:
        choisi = min(defavorables_propres, key=cle_decision)
        return _decision_crypto(
            True, True, "verdict_defavorable",
            verdict="DEFAVORABLE",
            sujet_digest=revue.sha256_hex(revue.canonique(sujet)),
            preuve_sha256=choisi[2],
            instant_verifie=revue.format_instant(choisi[1]),
            predicat=choisi[0],
        )
    if autres_defavorables:
        choisi = min(autres_defavorables, key=cle_decision)
        return _decision_crypto(
            True, True, "defavorable_sur_le_meme_sujet",
            verdict="DEFAVORABLE",
            sujet_digest=revue.sha256_hex(revue.canonique(sujet)),
            preuve_sha256=choisi[2],
            instant_verifie=revue.format_instant(choisi[1]),
            predicat=choisi[0],
        )
    if "FAVORABLE" not in verdicts:
        choisi = min(propres, key=cle_decision)
        return _decision_crypto(
            True, True, "aucun_verdict_favorable",
            verdict=choisi[0]["verdict"],
            sujet_digest=revue.sha256_hex(revue.canonique(sujet)),
            preuve_sha256=choisi[2],
            instant_verifie=revue.format_instant(choisi[1]),
            predicat=choisi[0],
        )
    favorables = [p for p in propres if p[0]["verdict"] == "FAVORABLE"]
    choisi = min(favorables, key=cle_decision)
    return _decision_crypto(
        True, True, "politique_dormante",
        verdict="FAVORABLE",
        sujet_digest=revue.sha256_hex(revue.canonique(sujet)),
        preuve_sha256=choisi[2],
        instant_verifie=revue.format_instant(choisi[1]),
        predicat=choisi[0],
    )


def verifier_cryptographique(config, politique, sujet, request_id, travail, maintenant=None, jeton=None):
    """Chaîne Sigstore complète depuis les références du consommateur.

    Aucun bundle, résultat de vérification, prédicat ou verdict n'est accepté en
    paramètre. Les tests remplacent uniquement la frontière ``gh`` et le
    transport HTTP par des doublures hors ligne.
    """
    maintenant = maintenant or datetime.datetime.now(datetime.timezone.utc)
    try:
        conf, pol = charger_confiance_cryptographique(config, politique)
        chemin_travail = Path(travail)
        chemin_travail.mkdir(parents=True, exist_ok=True)
        resultats = verifier.recuperer_resultats(conf, sujet, chemin_travail, jeton=jeton)
    except (revue.Refus, OSError, ValueError) as e:
        motif = e.motif if isinstance(e, revue.Refus) else "verification_cryptographique"
        return _decision_crypto(False, False, motif)
    return _evaluer_resultats_verifies(resultats, sujet, request_id, conf, pol, maintenant)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--predicat", required=True)
    parser.add_argument("--sujet", required=True)
    parser.add_argument("--politique", default=str(revue3.RACINE / revue3.FICHIER_POLITIQUE))
    args = parser.parse_args(argv)
    try:
        predicat = revue.charger_json_strict(Path(args.predicat).read_bytes())
        sujet = revue.charger_json_strict(Path(args.sujet).read_bytes())
        politique = revue3.charger_politique(args.politique)
        decision = verifier_synthetique(predicat, sujet, politique)
    except (ValueError, revue.Refus) as e:
        motif = e.motif if isinstance(e, revue.Refus) else "json_invalide"
        decision = _rejet_synthetique(motif)
    print(json.dumps(asdict(decision), ensure_ascii=False, sort_keys=True))
    return 0 if decision.verifiee else 1


if __name__ == "__main__":
    sys.exit(main())

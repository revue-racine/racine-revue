#!/usr/bin/env python3
"""Socle contractuel inerte de revue/3.

Ce module ne contient ni transport fournisseur, ni signature, ni publication,
ni pont P1. Il construit des objets synthétiques hors ligne et refuse toute
activation, y compris pour un verdict favorable.
"""
import argparse
import datetime
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import revue  # noqa: E402
import schema_strict  # noqa: E402

Refus = revue.Refus
RACINE = revue.RACINE
FORMAT_SUJET = "olistic.confiance.sujet-revue/3"
FORMAT_PREDICAT = "olistic.confiance.attestation-revue/3"
TYPE_PREDICAT = "urn:olistic:confiance:attestation-revue:3"
VERSION_PROTOCOLE = "revue/3"
FICHIER_PROTOCOLE = "protocol/revue-v3.md"
FICHIER_POLITIQUE = "policy/confiance-v3.json"
FICHIER_ANCRES = revue.FICHIER_ANCRES
NATURE_SYNTHETIQUE = "synthetique-hors-ligne"
CONTROLES_REPORTES = (
    "signature-cryptographique",
    "provenance-sigstore",
    "identite-modele-fournisseur",
    "pont-p1",
)


def schema(nom):
    """Schémas v3 pour politique, sujet et attestation ; v1 pour les
    interfaces communes qui restent inchangées."""
    version = 3 if nom in ("politique", "sujet-revue", "attestation-revue") else 1
    return json.loads((RACINE / "schemas" / f"{nom}-v{version}.schema.json").read_text("utf-8"))


def exiger(valeur, nom_schema, motif):
    erreurs = schema_strict.erreurs(valeur, schema(nom_schema))
    if erreurs:
        raise Refus(motif, "; ".join(erreurs[:5]))


def empreintes_locales():
    return {
        cle: revue.sha256_hex((RACINE / fichier).read_bytes())
        for cle, fichier in (
            ("protocole", FICHIER_PROTOCOLE),
            ("politique", FICHIER_POLITIQUE),
            ("ancres", FICHIER_ANCRES),
        )
    }


def famille_auteur(auteur):
    """Classe un identifiant d'auteur par la table fermée du P1."""
    if not isinstance(auteur, str):
        raise Refus("auteur_inconnu")
    if re.fullmatch(r"(?:codex|gpt|gpt-.+|chatgpt-codex)", auteur):
        return "gpt-codex-family"
    if re.fullmatch(r"(?:claude|claude-.+)", auteur):
        return "claude-family"
    raise Refus("auteur_inconnu")


def _controler_structure_politique(politique):
    """Valide le schéma et les invariants internes avant l'épinglage."""
    exiger(politique, "politique", "politique_invalide")

    alias = [d["alias"] for d in politique["depots"]]
    relecteurs = [r["famille"] for r in politique["relecteurs"]]
    familles_auteur = [s["famille_auteur"] for s in politique["selection"]]
    if len(alias) != len(set(alias)) or len(relecteurs) != len(set(relecteurs)) \
            or len(familles_auteur) != len(set(familles_auteur)):
        raise Refus("politique_invalide", "alias ou famille en double")
    if revue.instant_utc(politique["fraicheur"]["coupure"]) is None:
        raise Refus("politique_invalide", "coupure illisible")
    racine = politique["racine"]
    auto = [d for d in politique["depots"] if d["alias"] == "auto-test"]
    if auto and auto[0]["repository_id"] != racine["depot_id"]:
        raise Refus("politique_invalide", "auto-test doit désigner la racine")
    connus = set(relecteurs)
    for selection in politique["selection"]:
        if selection["famille_auteur"] == selection["famille_relecture"]:
            raise Refus("famille_non_independante")
        if selection["famille_relecture"] not in connus:
            raise Refus("famille_relecture_inconnue")
    return politique


def octets_politique_canonique():
    """Octets exacts de la seule politique autorisée par cet incrément."""
    return (RACINE / FICHIER_POLITIQUE).read_bytes()


def _objet_politique_canonique():
    try:
        politique = revue.charger_json_strict(octets_politique_canonique())
    except ValueError as e:
        raise Refus("politique_invalide", str(e))
    return _controler_structure_politique(politique)


def controler_politique(politique):
    """Épingle un objet décodé à la représentation canonique livrée.

    Les octets d'origine ne sont plus disponibles à cette interface : la
    comparaison utilise donc ``revue.canonique`` des deux objets JSON.
    """
    _controler_structure_politique(politique)
    canonique = _objet_politique_canonique()
    if revue.canonique(politique) != revue.canonique(canonique):
        raise Refus("politique_non_epinglee")
    return politique


def charger_politique(chemin=None):
    chemin = Path(chemin) if chemin else RACINE / FICHIER_POLITIQUE
    octets = chemin.read_bytes()
    try:
        politique = revue.charger_json_strict(octets)
    except ValueError as e:
        raise Refus("politique_invalide", str(e))
    _controler_structure_politique(politique)
    if octets != octets_politique_canonique():
        raise Refus("politique_non_epinglee")
    return politique


def verifier_activation(politique, verdict=None):
    """Porte volontairement impossible dans le contrat 3A.1."""
    if politique.get("etat") != "dormant":
        raise Refus("politique_invalide")
    if verdict is not None and verdict not in ("FAVORABLE", "DEFAVORABLE", "INDETERMINE"):
        raise Refus("verdict_invalide")
    raise Refus("politique_dormante")


def selectionner_famille(auteur, politique):
    controler_politique(politique)
    source = famille_auteur(auteur)
    choix = [s["famille_relecture"] for s in politique["selection"] if s["famille_auteur"] == source]
    if len(choix) != 1:
        raise Refus("famille_relecture_indisponible")
    cible = choix[0]
    if cible == source:
        raise Refus("famille_non_independante")
    relecteurs = [r for r in politique["relecteurs"] if r["famille"] == cible]
    if len(relecteurs) != 1:
        raise Refus("famille_relecture_inconnue")
    relecteur = relecteurs[0]
    if relecteur["actif"] or relecteur["acceptable"] or relecteur["modeles"] \
            or relecteur["fournisseurs"] or relecteur["endpoints"]:
        raise Refus("politique_non_dormante")
    return cible


def calculer_sujet(demande, politique, ancres, url, travail, protocoles=("https",)):
    controler_politique(politique)
    sujet, git = revue.calculer_sujet(demande, politique, ancres, url, travail, protocoles)
    sujet = dict(sujet, format=FORMAT_SUJET)
    exiger(sujet, "sujet-revue", "sujet_invalide")
    return sujet, git


def nom_sujet(sujet, request_id):
    return f"olistic-revue3:{sujet['depot']['alias']}@{sujet['pointe']['commit']}#{request_id}"


def _demande_predicat(admis):
    return {
        "issue": admis["issue"],
        "demandeur_id": admis["demandeur_id"],
        "request_id": admis["demande"]["request_id"],
        "declaration_p1": admis["demande"]["declaration_p1"],
    }


def construire_predicat_synthetique(sujet, admis, politique, verdict, motif, rapport_sha256, instant=None):
    exiger(sujet, "sujet-revue", "sujet_invalide")
    controler_politique(politique)
    famille = selectionner_famille(admis["demande"]["declaration_p1"]["auteur"], politique)
    empreintes = empreintes_locales()
    predicat = {
        "format": FORMAT_PREDICAT,
        "sujet": sujet,
        "demande": _demande_predicat(admis),
        "protocole": {"version": VERSION_PROTOCOLE, "sha256": empreintes["protocole"]},
        "politique": {
            "version": politique["version"],
            "generation": politique["generation"],
            "etat": politique["etat"],
            "sha256": empreintes["politique"],
        },
        "ancres_sha256": empreintes["ancres"],
        "relecteur": {
            "famille": famille,
            "modele": None,
            "fournisseur": None,
            "endpoint": None,
            "acceptable": False,
        },
        "verification": {
            "nature": NATURE_SYNTHETIQUE,
            "cryptographie_effective": False,
            "signature_effective": False,
            "provenance_effective": False,
            "controles_reportes": list(CONTROLES_REPORTES),
        },
        "verdict": verdict,
        "motif": motif,
        "rapport_sha256": rapport_sha256,
        "instant": instant or revue.format_instant(datetime.datetime.now(datetime.timezone.utc)),
        "autorisation": False,
    }
    controler_invariants(predicat, politique)
    return predicat


def controler_invariants(predicat, politique):
    controler_politique(politique)
    exiger(predicat, "attestation-revue", "attestation_invalide")
    indetermine = predicat["verdict"] == "INDETERMINE"
    if indetermine != (predicat["motif"] is not None):
        raise Refus("attestation_invalide", "motif incohérent")
    if tuple(predicat["verification"]["controles_reportes"]) != CONTROLES_REPORTES:
        raise Refus("attestation_invalide", "contrôles reportés incomplets ou réordonnés")
    if predicat["politique"]["generation"] != politique["generation"] \
            or predicat["politique"]["etat"] != politique["etat"]:
        raise Refus("attestation_invalide", "politique divergente")
    attendu = selectionner_famille(predicat["demande"]["declaration_p1"]["auteur"], politique)
    if predicat["relecteur"]["famille"] != attendu:
        raise Refus("famille_relecture_divergente")
    if predicat["autorisation"] is not False or predicat["relecteur"]["acceptable"] is not False:
        raise Refus("attestation_autorisante_interdite")
    if revue.instant_utc(predicat["instant"]) is None:
        raise Refus("attestation_invalide", "instant illisible")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sous = parser.add_subparsers(dest="commande", required=True)
    politique = sous.add_parser("politique")
    politique.add_argument("--activation", action="store_true")
    politique.add_argument("--fichier")
    args = parser.parse_args(argv)
    if args.commande == "politique":
        try:
            pol = charger_politique(args.fichier)
            if args.activation:
                verifier_activation(pol)
        except Refus as e:
            print(json.dumps({"statut": "refus", "motif": e.motif},
                             ensure_ascii=False, sort_keys=True))
            return 1
        print("politique v3 conforme, dormante et non autorisante")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())

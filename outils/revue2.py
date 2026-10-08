#!/usr/bin/env python3
"""Revue de confiance v2 (`revue/2`, protocol/revue-v2.md).

Bibliothèque standard seulement. Réutilise sans les modifier les fonctions du
v1 (`outils/revue.py`) : admission, récupération git, empreintes, normalisation
de la sortie du relecteur. Ce qui change : politique v2, sujet v2 (format
distinct, donc digest disjoint du v1), relecteur `openai-responses`, prédicat
v2, réponse publique qui signale la portée consultative.

Sous-commandes appelées par `.github/workflows/revue.yml` :
  admission       identique au v1, sous la politique v2
  revue           sujet v2, relecture `openai-responses`, prédicat v2
  preparer        recalcul indépendant du sujet v2, contrôle du prédicat, fichiers à signer
  reponse         commentaire de réponse, portée consultative explicite
  politique       contrôle la politique v2 (`--finale` : refuse une politique non ancrée)

Les attestations v1 restent vérifiables par `outils/verifier.py`, inchangé.
"""
import argparse
import datetime
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # nécessaire sous `python3 -I`
import relecteur_openai  # noqa: E402
import revue  # noqa: E402
import schema_strict  # noqa: E402

Refus = revue.Refus
RACINE = revue.RACINE
FORMAT_SUJET = "olistic.confiance.sujet-revue/2"
FORMAT_PREDICAT = "olistic.confiance.attestation-revue/2"
TYPE_PREDICAT = "urn:olistic:confiance:attestation-revue:2"
VERSION_PROTOCOLE = "revue/2"
FICHIER_PROTOCOLE = "protocol/revue-v2.md"
FICHIER_POLITIQUE = "policy/confiance-v2.json"
FICHIER_ANCRES = revue.FICHIER_ANCRES  # ancres gouvernées communes, format v1 inchangé
FAMILLE = "openai-responses"
VARIABLE_CLE = "CLE_RELECTEUR"
MOTIFS_AVEC_RAPPORT = (None, "relecteur", "favorable_incoherent")


def schema(nom):
    """Schémas v2 pour politique, sujet et prédicat ; v1 pour ce qui ne change pas
    (demande, ancres, sortie du relecteur)."""
    version = 2 if nom in ("politique", "sujet-revue", "attestation-revue") else 1
    return json.loads((RACINE / "schemas" / f"{nom}-v{version}.schema.json").read_text("utf-8"))


def exiger(valeur, nom_schema, motif):
    errs = schema_strict.erreurs(valeur, schema(nom_schema))
    if errs:
        raise Refus(motif, "; ".join(errs[:5]))


# --------------------------------------------------------------- politique

def charger_politique(chemin=None, finale=False):
    chemin = Path(chemin) if chemin else RACINE / FICHIER_POLITIQUE
    try:
        pol = revue.charger_json_strict(chemin.read_bytes())
    except ValueError as e:
        raise Refus("politique_invalide", str(e))
    exiger(pol, "politique", "politique_invalide")
    alias = [d["alias"] for d in pol["depots"]]
    familles = [r["famille"] for r in pol["relecteurs"]]
    if len(set(alias)) != len(alias) or len(set(familles)) != len(familles):
        raise Refus("politique_invalide", "alias ou famille en double")
    if revue.instant_utc(pol["fraicheur"]["coupure"]) is None:
        raise Refus("politique_invalide", "coupure illisible")
    for r in pol["relecteurs"]:
        if r["acceptable"] and not r["actif"]:
            raise Refus("politique_invalide", "relecteur acceptable mais inactif")
    if finale:
        r = pol["racine"]
        manquants = [k for k in ("proprietaire", "proprietaire_id", "depot", "depot_id") if r[k] is None]
        if manquants:
            raise Refus("politique_non_ancree", ", ".join(manquants))
        if not pol["demandeurs"]:
            raise Refus("politique_non_ancree", "aucun demandeur")
        if any(d["repository_id"] is None for d in pol["depots"]):
            raise Refus("politique_non_ancree", "dépôt sans repository_id")
        auto = [d for d in pol["depots"] if d["alias"] == "auto-test"]
        if auto and auto[0]["repository_id"] != r["depot_id"]:
            raise Refus("politique_invalide", "auto-test doit désigner le dépôt de confiance")
    return pol


def charger_ancres(pol, chemin=None):
    return revue.charger_ancres(pol, chemin)


def relecteur_actif(pol):
    actifs = [r for r in pol["relecteurs"] if r["actif"]]
    if len(actifs) != 1:
        raise Refus("politique_invalide", "exactement un relecteur actif")
    return actifs[0]


# ------------------------------------------------------------------- sujet

def calculer_sujet(demande, pol, ancres, url, travail, protocoles=("https",)):
    """Même récupération et mêmes empreintes que le v1 ; seul le format
    change, si bien qu'un sujet v2 n'a jamais le digest d'un sujet v1."""
    sujet, git = revue.calculer_sujet(demande, pol, ancres, url, travail, protocoles)
    sujet = dict(sujet, format=FORMAT_SUJET)
    exiger(sujet, "sujet-revue", "sujet_invalide")
    return sujet, git


def nom_sujet(sujet, request_id):
    return f"olistic-revue2:{sujet['depot']['alias']}@{sujet['pointe']['commit']}#{request_id}"


# --------------------------------------------------------------- relecture

def relire(cle, rel, diff, connexion=None):
    """Sortie brute du relecteur, ou Refus (enveloppe fournisseur invalide)."""
    if rel["famille"] != FAMILLE:
        raise Refus("relecteur_configuration")
    return relecteur_openai.relire(cle, rel["modeles"][0], diff, revue.schema("sortie-relecteur"), connexion)


def normaliser_verdict(sortie):
    """Normalisation v1 de la sortie du relecteur, reprise telle quelle (§5)."""
    return revue.normaliser_verdict(FAMILLE, sortie)


# ---------------------------------------------------------------- prédicat

def empreintes_locales():
    return {cle: revue.sha256_hex((RACINE / f).read_bytes())
            for cle, f in (("protocole", FICHIER_PROTOCOLE), ("politique", FICHIER_POLITIQUE),
                           ("ancres", FICHIER_ANCRES))}


def construire_predicat(sujet, admis, pol, rel, verdict, motif, rapport, instant=None):
    e = empreintes_locales()
    predicat = {
        "format": FORMAT_PREDICAT,
        "sujet": sujet,
        "demande": {"issue": admis["issue"], "demandeur_id": admis["demandeur_id"],
                    "request_id": admis["demande"]["request_id"],
                    "declaration_p1": admis["demande"]["declaration_p1"]},
        "protocole": {"version": VERSION_PROTOCOLE, "sha256": e["protocole"]},
        "politique": {"version": pol["version"], "generation": pol["generation"], "sha256": e["politique"]},
        "ancres_sha256": e["ancres"],
        "relecteur": {"famille": rel["famille"], "modele": rel["modeles"][0], "acceptable": rel["acceptable"]},
        "verdict": verdict,
        "motif": motif,
        "rapport_sha256": rapport,
        "instant": instant or revue.format_instant(datetime.datetime.now(datetime.timezone.utc)),
    }
    controler_invariants(predicat, pol)
    return predicat


def controler_invariants(predicat, pol):
    exiger(predicat, "attestation-revue", "predicat_invalide")
    if (predicat["verdict"] == "INDETERMINE") != (predicat["motif"] is not None):
        raise Refus("predicat_invalide", "motif exigé si et seulement si INDETERMINE")
    if predicat["motif"] in MOTIFS_AVEC_RAPPORT and predicat["rapport_sha256"] is None:
        raise Refus("predicat_invalide", "rapport exigé")
    if predicat["motif"] == "diff_trop_grand" and predicat["rapport_sha256"] is not None:
        raise Refus("predicat_invalide", "aucun rapport sans relecture")
    if predicat["politique"]["generation"] != pol["generation"]:
        raise Refus("predicat_invalide", "génération")
    r = next((x for x in pol["relecteurs"] if x["famille"] == predicat["relecteur"]["famille"]), None)
    if r is None or not r["actif"]:
        raise Refus("predicat_invalide", "relecteur inactif")
    if predicat["relecteur"]["modele"] not in r["modeles"]:
        raise Refus("predicat_invalide", "modèle non autorisé")
    if predicat["relecteur"]["acceptable"] is not r["acceptable"]:
        raise Refus("predicat_invalide", "acceptable diverge de la politique")


def preparer_signature(predicat_brut, admis, sujet_recalcule, pol):
    try:
        predicat = revue.charger_json_strict(predicat_brut)
    except ValueError as e:
        raise Refus("predicat_invalide", str(e))
    controler_invariants(predicat, pol)
    if revue.canonique(predicat["sujet"]) != revue.canonique(sujet_recalcule):
        raise Refus("sujet_divergent")
    e = empreintes_locales()
    if (predicat["protocole"]["sha256"], predicat["politique"]["sha256"], predicat["ancres_sha256"]) != \
            (e["protocole"], e["politique"], e["ancres"]):
        raise Refus("empreintes_divergentes")
    attendu = {"issue": admis["issue"], "demandeur_id": admis["demandeur_id"],
               "request_id": admis["demande"]["request_id"], "declaration_p1": admis["demande"]["declaration_p1"]}
    if predicat["demande"] != attendu:
        raise Refus("demande_divergente")
    t = revue.instant_utc(predicat["instant"])
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    if t is None or not (0 <= (maintenant - t).total_seconds() <= pol["fraicheur"]["tolerance_instant_s"]):
        raise Refus("instant_incoherent")
    octets_sujet = revue.canonique(sujet_recalcule)
    return {
        "sujet_octets": octets_sujet,
        "sujet_digest": revue.sha256_hex(octets_sujet),
        "sujet_nom": nom_sujet(sujet_recalcule, admis["demande"]["request_id"]),
        "predicat_octets": revue.canonique(predicat),
        "verdict": predicat["verdict"],
    }


# ---------------------------------------------------------------- réponse

def portee_publique():
    """Ligne de portée pour le commentaire public, lue dans la politique du même
    commit. Illisible : traitée comme non autorisante."""
    try:
        rel = relecteur_actif(charger_politique())
    except Refus:
        return "- portée : inconnue — à traiter comme consultative, sans valeur d'autorisation"
    if not rel["acceptable"]:
        return (f"- portée : CONSULTATIVE — relecteur `{rel['famille']}` non acceptable sous cette politique ; "
                "cette attestation n'autorise ni n'approuve rien, quel que soit son verdict")
    return f"- portée : relecteur `{rel['famille']}` acceptable ; seule une vérification §7 complète décide"


def texte_reponse(e):
    lignes = ["Réponse automatique du protocole revue/2. Ce commentaire n'est pas une preuve : "
              "seule l'attestation signée fait foi."]
    if e.get("ADMIS_OUI") != "oui":
        lignes.append(f"- statut : refusée à l'admission ({e.get('MOTIF_ADMISSION') or 'inconnu'})")
    elif e.get("STATUT_REVUE") != "pret":
        lignes.append(f"- statut : refusée avant attestation ({e.get('MOTIF_REVUE') or 'inconnu'})")
    elif e.get("RESULTAT_ATTESTATION") != "success":
        lignes.append("- statut : échec de l'attestation (aucune preuve émise)")
    else:
        lignes.append(f"- statut : attestée, verdict `{e.get('VERDICT')}`")
        lignes.append(portee_publique())
        lignes.append(f"- sujet : `{e.get('SUJET_DIGEST')}`")
        lignes.append(f"- attestation : {e.get('URL_ATTESTATION')}")
    return "\n".join(lignes) + "\n"


# --------------------------------------------------------------------- CLI

def _admis_depuis_env():
    return revue.charger_json_strict(os.environ["ADMIS"].encode())


def lister_issues_api(env, numero):
    return revue.lister_issues_api(env, numero)


def url_du_depot(depot, env):
    return revue.url_du_depot(depot, env)


def main(argv=None):
    p = argparse.ArgumentParser()
    sous = p.add_subparsers(dest="cmd", required=True)
    a = sous.add_parser("admission")
    a.add_argument("--evenement", required=True)
    a.add_argument("--sortie", required=True)
    for nom in ("revue", "preparer"):
        s = sous.add_parser(nom)
        s.add_argument("--travail", required=True)
        s.add_argument("--sortie", required=True)
    sous.choices["preparer"].add_argument("--dossier", required=True)
    r = sous.add_parser("reponse")
    r.add_argument("--fichier", required=True)
    q = sous.add_parser("politique")
    q.add_argument("--finale", action="store_true")
    args = p.parse_args(argv)

    if args.cmd == "politique":
        pol = charger_politique(finale=args.finale)
        charger_ancres(pol)
        relecteur_actif(pol)
        print("politique v2 conforme" + (" et ancrée" if args.finale else ""))
        return 0

    if args.cmd == "admission":
        try:
            pol = charger_politique(finale=True)
            evenement = revue.charger_json_strict(Path(args.evenement).read_bytes())
            premier = revue.admettre(evenement, pol)  # refus précoces, avant tout appel d'API
            admis = revue.admettre(evenement, pol, lister_issues_api(os.environ, premier["issue"]))
        except Refus as e:
            revue.ecrire_sorties(args.sortie, {"admis": "non", "motif": e.motif})
            print(f"refus : {e.motif}")
            return 0
        revue.ecrire_sorties(args.sortie, {"admis": "oui", "motif": "", "demande": revue.canonique(admis).decode()})
        return 0

    if args.cmd == "revue":
        cle = os.environ.pop(VARIABLE_CLE, "")  # retirée de l'environnement avant tout sous-processus
        try:
            if not cle:
                raise Refus("relecteur_cle_absente")
            pol = charger_politique(finale=True)
            ancres = charger_ancres(pol)
            admis = _admis_depuis_env()
            depot = next(d for d in pol["depots"] if d["alias"] == admis["demande"]["depot"])
            sujet, git = calculer_sujet(admis["demande"], pol, ancres, url_du_depot(depot, os.environ), args.travail)
            rel = relecteur_actif(pol)
            diff = revue.extraire_diff(git, sujet)
            if len(diff) > pol["limites"]["diff_octets"]:
                verdict, motif, rapport = "INDETERMINE", "diff_trop_grand", None
            else:
                verdict, motif, rapport = normaliser_verdict(relire(cle, rel, diff))
            predicat = construire_predicat(sujet, admis, pol, rel, verdict, motif, rapport)
        except Refus as e:
            revue.ecrire_sorties(args.sortie, {"statut": "refus", "motif": e.motif})
            print(f"refus : {e.motif}")
            return 0
        finally:
            cle = None
        revue.ecrire_sorties(args.sortie, {"statut": "pret", "motif": "",
                                           "predicat": revue.canonique(predicat).decode()})
        return 0

    if args.cmd == "preparer":
        pol = charger_politique(finale=True)
        ancres = charger_ancres(pol)
        admis = _admis_depuis_env()
        depot = next(d for d in pol["depots"] if d["alias"] == admis["demande"]["depot"])
        sujet, _ = calculer_sujet(admis["demande"], pol, ancres, url_du_depot(depot, os.environ), args.travail)
        prep = preparer_signature(os.environ["PREDICAT"].encode(), admis, sujet, pol)
        dossier = Path(args.dossier)
        dossier.mkdir(parents=True, exist_ok=True)
        (dossier / "sujet.json").write_bytes(prep["sujet_octets"])
        (dossier / "predicat.json").write_bytes(prep["predicat_octets"])
        revue.ecrire_sorties(args.sortie, {
            "sujet_digest": "sha256:" + prep["sujet_digest"],
            "sujet_nom": prep["sujet_nom"],
            "verdict": prep["verdict"],
        })
        return 0

    if args.cmd == "reponse":
        Path(args.fichier).write_text(texte_reponse(os.environ), encoding="utf-8")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())

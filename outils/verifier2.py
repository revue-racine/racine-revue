#!/usr/bin/env python3
"""Vérificateur de référence CANDIDAT d'une attestation de revue v2.

Distinct du vérificateur v1 (`outils/verifier.py`, inchangé, qui reste celui du
paquet consommateur v1). Réutilise sans les modifier ses fonctions de
transport, de bundle et de provenance ; change ce qui est propre au v2 :
politique v2, sujet v2, prédicat v2, relecteur `openai-responses`.

VÉRIFICATION PURE : la décision n'est jamais une autorisation et ne consomme
rien. Aucun pont n'existe pour le v2. Sous la politique génération 2,
`openai-responses` n'est pas acceptable : toute attestation v2 est rejetée
(`relecteur_non_acceptable`), quel que soit son verdict — mais seulement après
tous les autres contrôles (provenance, prédicat, modèle, fraîcheur), pour qu'un
canari révèle toute autre anomalie par son propre motif.
"""
import argparse
import datetime
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import revue  # noqa: E402
import revue2  # noqa: E402
import schema_strict  # noqa: E402
import verifier  # noqa: E402

Invalide = verifier.Invalide
Decision = verifier.Decision
_rejet = verifier._rejet
CLES_CONFIANCE = verifier.CLES_CONFIANCE
TYPE_INTOTO = verifier.TYPE_INTOTO


def charger_confiance(chemin_confiance, chemin_politique):
    conf = revue.charger_json_strict(Path(chemin_confiance).read_bytes())
    if not isinstance(conf, dict) or set(conf) != CLES_CONFIANCE:
        raise revue.Refus("confiance_invalide", "clés")
    if not conf["commits_racine"] or not all(isinstance(c, str) and len(c) == 40 for c in conf["commits_racine"]):
        raise revue.Refus("confiance_invalide", "commits_racine")
    if conf["type_predicat"] != revue2.TYPE_PREDICAT:
        raise revue.Refus("confiance_invalide", "type_predicat")
    octets = Path(chemin_politique).read_bytes()
    if revue.sha256_hex(octets) != conf["politique_sha256"]:
        raise revue.Refus("politique_non_epinglee")
    pol = revue2.charger_politique(chemin_politique, finale=True)
    if pol["generation"] != conf["generation"]:
        raise revue.Refus("generation_divergente")
    r = pol["racine"]
    for cle in ("proprietaire", "proprietaire_id", "depot", "depot_id", "workflow", "nom_workflow", "ref"):
        if r[cle] != conf[cle]:
            raise revue.Refus("confiance_invalide", f"racine.{cle}")
    if pol["type_predicat"] != conf["type_predicat"]:
        raise revue.Refus("confiance_invalide", "type_predicat")
    return conf, pol


def controler(resultat, sujet, conf, pol, maintenant):
    try:
        vr = resultat["verificationResult"]
        cert = vr["signature"]["certificate"]
        enonce = vr["statement"]
    except (KeyError, TypeError):
        raise Invalide("resultat_illisible")
    motif = verifier.controler_certificat(cert, conf)
    if motif:
        raise Invalide(motif)
    if enonce.get("_type") != TYPE_INTOTO:
        raise Invalide("type_intoto")
    if enonce.get("predicateType") != conf["type_predicat"]:
        raise Invalide("type_predicat")
    predicat = enonce.get("predicate")
    if schema_strict.erreurs(predicat, revue2.schema("attestation-revue")):
        raise Invalide("predicat_invalide")
    octets = revue.canonique(sujet)
    sujets = enonce.get("subject")
    if not isinstance(sujets, list) or len(sujets) != 1 or \
            sujets[0].get("digest") != {"sha256": revue.sha256_hex(octets)}:
        raise Invalide("digest_sujet")
    if sujets[0].get("name") != revue2.nom_sujet(sujet, predicat["demande"]["request_id"]):
        raise Invalide("nom_sujet")
    if revue.canonique(predicat["sujet"]) != octets:
        raise Invalide("sujet_divergent")
    if predicat["protocole"]["sha256"] != conf["protocole_sha256"]:
        raise Invalide("protocole_different")
    if predicat["politique"]["sha256"] != conf["politique_sha256"] or predicat["politique"]["generation"] != conf["generation"]:
        raise Invalide("politique_differente")
    if (predicat["verdict"] == "INDETERMINE") != (predicat["motif"] is not None):
        raise Invalide("predicat_invalide")
    rel = next((r for r in pol["relecteurs"] if r["famille"] == predicat["relecteur"]["famille"]), None)
    if rel is None or not rel["actif"]:
        raise Invalide("relecteur_inactif")
    if predicat["relecteur"]["modele"] not in rel["modeles"]:
        raise Invalide("modele_non_autorise")
    t = verifier.instant_verifie(vr, pol, maintenant)
    instant = revue.instant_utc(predicat["instant"])
    ecart = (t - instant).total_seconds() if instant else None
    if ecart is None or not (-pol["fraicheur"]["derive_horloge_s"] <= ecart <= pol["fraicheur"]["tolerance_instant_s"]):
        raise Invalide("instant_incoherent")
    # En DERNIER : sous acceptable:false (canari), une anomalie de provenance, de
    # modèle ou de fraîcheur est signalée par son propre motif, jamais masquée.
    if predicat["relecteur"]["acceptable"] is not rel["acceptable"]:
        raise Invalide("acceptable_divergent")
    if not rel["acceptable"]:
        raise Invalide("relecteur_non_acceptable")
    return predicat, t


def evaluer(resultats, sujet, request_id, conf, pol, maintenant):
    """Même règle d'agrégation que le v1 (protocole v2 §7)."""
    if not isinstance(resultats, list):
        return _rejet("resultats_illisibles")
    propres, instants, autres_defavorables = [], [], 0
    for r in resultats:
        try:
            rid = r["verificationResult"]["statement"]["predicate"]["demande"]["request_id"]
        except (KeyError, TypeError):
            rid = None
        if rid == request_id:
            try:
                predicat, t = controler(r, sujet, conf, pol, maintenant)
            except Invalide as e:
                return _rejet(e.motif)
            propres.append(predicat)
            instants.append(t)
        else:
            try:
                predicat, _ = controler(r, sujet, conf, pol, maintenant)
            except Invalide:
                continue
            autres_defavorables += predicat["verdict"] == "DEFAVORABLE"
    if not propres:
        return _rejet("aucune_attestation_pour_la_demande")
    verdicts = sorted({p["verdict"] for p in propres})
    if "DEFAVORABLE" in verdicts:
        return _rejet("verdict_defavorable", verdicts=verdicts)
    if autres_defavorables:
        return _rejet("defavorable_sur_le_meme_sujet")
    if "FAVORABLE" not in verdicts:
        return _rejet("aucun_verdict_acceptant", verdicts=verdicts)
    i = min(range(len(propres)), key=lambda k: (instants[k], propres[k]["demande"]["issue"]))
    return Decision(acceptee=True, motif="", verdicts=verdicts, request_id=request_id,
                    sujet_digest=revue.sha256_hex(revue.canonique(sujet)),
                    predicat=propres[i], instant_verifie=revue.format_instant(instants[i]))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--confiance", required=True, help="configuration CANDIDATE du consommateur v2 (JSON)")
    p.add_argument("--politique", required=True, help="politique v2 dont l'empreinte est épinglée")
    p.add_argument("--ancres", required=True, help="ancres gouvernées attendues")
    p.add_argument("--depot-local", required=True)
    p.add_argument("--alias", required=True)
    p.add_argument("--pointe", required=True)
    p.add_argument("--request-id", required=True)
    args = p.parse_args(argv)
    conf, pol = charger_confiance(args.confiance, args.politique)
    ancres = revue2.charger_ancres(pol, args.ancres)
    demande = {"format": "olistic.confiance.demande/1", "request_id": args.request_id, "depot": args.alias,
               "pointe": args.pointe, "declaration_p1": {"classe": "A", "auteur": "inconnu"}}
    revue.exiger(demande, "demande", "demande_invalide")
    with tempfile.TemporaryDirectory() as tmp:
        sujet, _ = revue2.calculer_sujet(demande, pol, ancres, str(Path(args.depot_local).resolve()),
                                         Path(tmp) / "git", protocoles=("file",))
        try:
            resultats = verifier.recuperer_resultats(conf, sujet, tmp)
            decision = evaluer(resultats, sujet, args.request_id, conf, pol,
                               datetime.datetime.now(datetime.timezone.utc))
        except revue.Refus as e:
            decision = _rejet(e.motif)
    print(json.dumps(dict(decision, nature="verification_pure_non_autorisante", protocole="revue/2"),
                     ensure_ascii=False))
    return 0 if decision.acceptee else 1


if __name__ == "__main__":
    sys.exit(main())

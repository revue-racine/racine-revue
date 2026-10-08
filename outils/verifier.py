#!/usr/bin/env python3
"""Vérificateur de référence d'une attestation de revue v1 (côté consommateur).

La cryptographie (certificat Sigstore, journal de transparence, signature DSSE)
est vérifiée par `gh attestation verify`, bundle par bundle, avec des
épinglages construits ici. Ce module ajoute le contrôle champ par champ de la
provenance, de l'énoncé in-toto et du prédicat, le recalcul du sujet, la
fraîcheur, le rejeu et la règle d'agrégation.

La configuration de confiance (`confiance`) appartient au consommateur : elle
épingle l'identité numérique de la racine, les commits de workflow acceptés, et
les empreintes EXACTES de la politique et du protocole. Rien n'est pris dans
l'attestation ni dans le dépôt de confiance distant.

Ce module est une VÉRIFICATION PURE : sa décision n'est jamais une
autorisation et ne consomme rien. Le seul chemin qui mène à une autorisation
(attestation SSH P1) est `pont_p1.verifier_consommer_et_signer`, qui consomme
le request_id de façon atomique dans le registre du dépôt de confiance.

Les bundles ne sont jamais fournis par l'appelant : ils sont lus depuis l'API
GitHub (`bundle_url`), téléchargés et décompressés ici, puis vérifiés par `gh`.
"""
import argparse
import datetime
import json
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import revue  # noqa: E402
import schema_strict  # noqa: E402
import snappy_bloc  # noqa: E402

EMETTEUR_OIDC = "https://token.actions.githubusercontent.com"
API_GITHUB = "https://api.github.com"
SUFFIXES_HOTES_BUNDLE = (".github.com", ".githubusercontent.com", ".blob.core.windows.net")
BUNDLE_COMPRESSE_MAX = 2 * 1024 * 1024
BUNDLE_MAX = 8 * 1024 * 1024
PAGES_MAX = 1000  # garde-fou contre une pagination sans fin, pas un seuil de décision
TYPE_INTOTO = "https://in-toto.io/Statement/v1"
DECLENCHEUR = "issues"
CLES_CONFIANCE = {"proprietaire", "proprietaire_id", "depot", "depot_id", "workflow", "nom_workflow", "ref",
                  "type_predicat", "commits_racine", "politique_sha256", "protocole_sha256", "generation"}


class Invalide(Exception):
    def __init__(self, motif):
        super().__init__(motif)
        self.motif = motif


class Decision(dict):
    @property
    def acceptee(self):
        return self["acceptee"]


def _rejet(motif, **extra):
    return Decision(acceptee=False, motif=motif, **extra)


# ------------------------------------------------------------ configuration

def charger_confiance(chemin_confiance, chemin_politique):
    """Configuration du consommateur + politique dont l'empreinte EXACTE est
    épinglée. Tout écart : refus."""
    conf = revue.charger_json_strict(Path(chemin_confiance).read_bytes())
    if not isinstance(conf, dict) or set(conf) != CLES_CONFIANCE:
        raise revue.Refus("confiance_invalide", "clés")
    if not conf["commits_racine"] or not all(isinstance(c, str) and len(c) == 40 for c in conf["commits_racine"]):
        raise revue.Refus("confiance_invalide", "commits_racine")
    octets = Path(chemin_politique).read_bytes()
    if revue.sha256_hex(octets) != conf["politique_sha256"]:
        raise revue.Refus("politique_non_epinglee")
    pol = revue.charger_politique(chemin_politique, finale=True)
    if pol["generation"] != conf["generation"]:
        raise revue.Refus("generation_divergente")
    r = pol["racine"]
    for cle in ("proprietaire", "proprietaire_id", "depot", "depot_id", "workflow", "nom_workflow", "ref"):
        if r[cle] != conf[cle]:
            raise revue.Refus("confiance_invalide", f"racine.{cle}")
    if pol["type_predicat"] != conf["type_predicat"]:
        raise revue.Refus("confiance_invalide", "type_predicat")
    return conf, pol


def commande_gh(conf, chemin_sujet, bundle):
    proprietaire, depot = conf["proprietaire"], conf["depot"]
    return [
        "gh", "attestation", "verify", str(chemin_sujet),
        "--bundle", str(bundle),
        "--repo", f"{proprietaire}/{depot}",
        "--signer-workflow", f"{proprietaire}/{depot}/{conf['workflow']}",
        "--source-ref", conf["ref"],
        "--cert-oidc-issuer", EMETTEUR_OIDC,
        "--predicate-type", conf["type_predicat"],
        "--deny-self-hosted-runners",
        "--format", "json",
    ]


def _http_get(url, entetes):
    """GET sans redirection vers un autre hôte que celui validé : l'URL finale
    est rendue pour être revalidée."""
    req = urllib.request.Request(url, headers=entetes)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(BUNDLE_COMPRESSE_MAX + 1), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, {}, b"", url
    except Exception as e:  # noqa: BLE001
        raise revue.Refus("telechargement_impossible", type(e).__name__)


def url_bundle_valide(url):
    if not isinstance(url, str) or not url:
        return False
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        return False
    hote = (u.hostname or "").lower()
    return (u.scheme == "https" and not u.username and not u.password and port in (None, 443)
            and any(hote.endswith(s) for s in SUFFIXES_HOTES_BUNDLE))


def lister_bundle_urls(conf, digest, http=None, jeton=None):
    """Toutes les `bundle_url` du sujet, pagination complète (en-tête Link). Un
    élément sans `bundle_url` valide fait refuser : le champ `bundle` en ligne
    n'est jamais utilisé."""
    http = http or _http_get
    prefixe = f"{API_GITHUB}/repos/{conf['proprietaire']}/{conf['depot']}/attestations/"
    url = f"{prefixe}sha256:{digest}?per_page=100"
    entetes = {"Accept": "application/vnd.github+json"}
    if jeton:
        entetes["Authorization"] = f"Bearer {jeton}"
    urls = []
    for _ in range(PAGES_MAX):
        statut, rep_entetes, corps, finale = http(url, entetes)
        if statut == 404 and not urls:
            return []
        if statut != 200 or not finale.startswith(prefixe):
            raise revue.Refus("liste_illisible", str(statut))
        try:
            page = json.loads(corps)
        except ValueError:
            raise revue.Refus("liste_illisible")
        if not isinstance(page, dict) or not isinstance(page.get("attestations"), list):
            raise revue.Refus("liste_illisible")
        for a in page["attestations"]:
            u = a.get("bundle_url") if isinstance(a, dict) else None
            if not url_bundle_valide(u):
                raise revue.Refus("bundle_url_invalide")
            urls.append(u)
        suivant = _lien_suivant(rep_entetes.get("link", ""))
        if suivant is None:
            return urls
        if not suivant.startswith(prefixe):
            raise revue.Refus("liste_illisible", "pagination hors du dépôt")
        url = suivant
    raise revue.Refus("liste_illisible", "pagination sans fin")


def _lien_suivant(link):
    for partie in link.split(","):
        morceaux = [m.strip() for m in partie.split(";")]
        if len(morceaux) >= 2 and 'rel="next"' in morceaux[1:] and morceaux[0].startswith("<") and morceaux[0].endswith(">"):
            return morceaux[0][1:-1]
    return None


def telecharger_bundle(url, http=None):
    """Bundle Sigstore JSON depuis `bundle_url` : sans jeton (hôte externe),
    hôte revalidé après redirection, snappy bloc borné, JSON objet sans clé en
    double, mediaType de bundle Sigstore. Toute anomalie : refus."""
    http = http or _http_get
    if not url_bundle_valide(url):
        raise revue.Refus("bundle_url_invalide")
    statut, _, corps, finale = http(url, {})
    if statut != 200 or not url_bundle_valide(finale):
        raise revue.Refus("telechargement_impossible", str(statut))
    if len(corps) > BUNDLE_COMPRESSE_MAX:
        raise revue.Refus("bundle_trop_grand")
    try:
        brut = snappy_bloc.decompresser(corps, BUNDLE_MAX)
        bundle = json.loads(brut, object_pairs_hook=revue._refuser_doublons, parse_constant=revue._refuser_constante)
    except ValueError:
        raise revue.Refus("bundle_illisible")
    if not isinstance(bundle, dict) or not str(bundle.get("mediaType", "")).startswith("application/vnd.dev.sigstore.bundle"):
        raise revue.Refus("bundle_illisible")
    return brut


def _verifier_crypto(conf, chemin_sujet, chemin_bundle):
    """`gh attestation verify` épinglé sur UN bundle ; rend l'unique résultat."""
    v = subprocess.run(commande_gh(conf, chemin_sujet, chemin_bundle), capture_output=True, timeout=120)
    if v.returncode != 0:
        raise revue.Refus("verification_cryptographique")
    try:
        lot = json.loads(v.stdout)
    except ValueError:
        raise revue.Refus("verification_cryptographique")
    if not isinstance(lot, list) or len(lot) != 1:
        raise revue.Refus("verification_cryptographique")
    return lot[0]


def recuperer_resultats(conf, sujet, travail, http=None, jeton=None):
    """Toutes les attestations du sujet : liste API → `bundle_url` → bundle
    téléchargé → vérification cryptographique épinglée. Tout échec : refus."""
    octets = revue.canonique(sujet)
    chemin = Path(travail) / "sujet.json"
    chemin.write_bytes(octets)
    resultats = []
    for i, u in enumerate(lister_bundle_urls(conf, revue.sha256_hex(octets), http, jeton)):
        b = Path(travail) / f"bundle-{i}.json"
        b.write_bytes(telecharger_bundle(u, http))
        resultats.append(_verifier_crypto(conf, chemin, b))
    return resultats


# --------------------------------------------------------------- provenance

def controler_certificat(cert, conf):
    """Identité complète du workflow signataire. Rend le motif du premier écart."""
    p, d = conf["proprietaire"], conf["depot"]
    base = f"https://github.com/{p}/{d}"
    signataire = f"{base}/{conf['workflow']}@{conf['ref']}"
    attendus = {
        "issuer": EMETTEUR_OIDC,
        "sourceRepositoryURI": base,
        "sourceRepositoryOwnerURI": f"https://github.com/{p}",
        "sourceRepositoryRef": conf["ref"],
        "sourceRepositoryIdentifier": str(conf["depot_id"]),
        "sourceRepositoryOwnerIdentifier": str(conf["proprietaire_id"]),
        "sourceRepositoryVisibilityAtSigning": "public",
        "buildSignerURI": signataire,
        "buildConfigURI": signataire,
        "runnerEnvironment": "github-hosted",
        "buildTrigger": DECLENCHEUR,
        "githubWorkflowTrigger": DECLENCHEUR,
        "githubWorkflowRepository": f"{p}/{d}",
        "githubWorkflowRef": conf["ref"],
        "githubWorkflowName": conf["nom_workflow"],
    }
    for champ, valeur in attendus.items():
        if cert.get(champ) != valeur:
            return f"certificat:{champ}"
    commit = cert.get("sourceRepositoryDigest")
    if commit not in conf["commits_racine"]:
        return "certificat:commit_workflow_non_epingle"
    for champ in ("buildSignerDigest", "buildConfigDigest", "githubWorkflowSHA"):
        if cert.get(champ) != commit:
            return f"certificat:{champ}"
    if not str(cert.get("runInvocationURI", "")).startswith(f"{base}/actions/runs/"):
        return "certificat:runInvocationURI"
    return None


def instant_verifie(resultat, pol, maintenant):
    """Plus ancien horodatage VÉRIFIÉ (journal de transparence ou TSA). Absent,
    illisible, futur, antérieur à la coupure ou périmé : invalide."""
    ts = resultat.get("verifiedTimestamps")
    if not isinstance(ts, list) or not ts:
        raise Invalide("horodatage_absent")
    instants = [revue.instant_utc(t.get("timestamp")) if isinstance(t, dict) else None for t in ts]
    if any(t is None for t in instants):
        raise Invalide("horodatage_illisible")
    t = min(instants)
    f = pol["fraicheur"]
    if (t - maintenant).total_seconds() > f["derive_horloge_s"]:
        raise Invalide("horodatage_futur")
    if t < revue.instant_utc(f["coupure"]):
        raise Invalide("anterieure_a_la_coupure")
    if (maintenant - t).total_seconds() > f["validite_s"]:
        raise Invalide("attestation_perimee")
    return t


def controler(resultat, sujet, conf, pol, maintenant):
    """Contrôle complet d'un résultat de vérification. Rend (prédicat, instant
    vérifié) ou lève Invalide."""
    try:
        vr = resultat["verificationResult"]
        cert = vr["signature"]["certificate"]
        enonce = vr["statement"]
    except (KeyError, TypeError):
        raise Invalide("resultat_illisible")
    motif = controler_certificat(cert, conf)
    if motif:
        raise Invalide(motif)
    if enonce.get("_type") != TYPE_INTOTO:
        raise Invalide("type_intoto")
    if enonce.get("predicateType") != conf["type_predicat"]:
        raise Invalide("type_predicat")
    predicat = enonce.get("predicate")
    if schema_strict.erreurs(predicat, revue.schema("attestation-revue")):
        raise Invalide("predicat_invalide")
    octets = revue.canonique(sujet)
    sujets = enonce.get("subject")
    if not isinstance(sujets, list) or len(sujets) != 1 or \
            sujets[0].get("digest") != {"sha256": revue.sha256_hex(octets)}:
        raise Invalide("digest_sujet")
    if sujets[0].get("name") != revue.nom_sujet(sujet, predicat["demande"]["request_id"]):
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
    if not rel["acceptable"]:
        raise Invalide("relecteur_non_acceptable")
    if predicat["relecteur"]["modele"] not in rel["modeles"]:
        raise Invalide("modele_non_autorise")
    t = instant_verifie(vr, pol, maintenant)
    instant = revue.instant_utc(predicat["instant"])
    ecart = (t - instant).total_seconds() if instant else None
    if ecart is None or not (-pol["fraicheur"]["derive_horloge_s"] <= ecart <= pol["fraicheur"]["tolerance_instant_s"]):
        raise Invalide("instant_incoherent")
    return predicat, t


def evaluer(resultats, sujet, request_id, conf, pol, maintenant):
    """Décision pour la demande `request_id` sur `sujet`.

    - `resultats` = TOUTES les attestations du sujet (liste complète, aucune
      limite de longueur ; une liste incomplète ne doit jamais arriver ici).
    - Attestations de cette demande : chacune doit passer tous les contrôles ;
      aucune DEFAVORABLE ; au moins une FAVORABLE. Les réexécutions d'une même
      demande sont donc concordantes ou rejetées, quel que soit l'ordre.
    - Attestations d'autres demandes du même sujet : seule une DEFAVORABLE
      entièrement valide compte, et elle bloque (une redemande ne lave pas un
      refus). Les INDETERMINE et les invalides sont ignorées : multiplier les
      demandes ne crée aucun déni.
    Vérification pure : le rejeu est traité par le registre de consommation,
    que seul `pont_p1.verifier_consommer_et_signer` utilise."""
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


# --------------------------------------------------------------------- CLI

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--confiance", required=True, help="configuration du consommateur (JSON)")
    p.add_argument("--politique", required=True, help="politique dont l'empreinte est épinglée")
    p.add_argument("--ancres", required=True, help="ancres gouvernées attendues")
    p.add_argument("--depot-local", required=True)
    p.add_argument("--alias", required=True)
    p.add_argument("--pointe", required=True)
    p.add_argument("--request-id", required=True)
    args = p.parse_args(argv)
    conf, pol = charger_confiance(args.confiance, args.politique)
    ancres = revue.charger_ancres(pol, args.ancres)
    demande = {"format": "olistic.confiance.demande/1", "request_id": args.request_id, "depot": args.alias,
               "pointe": args.pointe, "declaration_p1": {"classe": "A", "auteur": "inconnu"}}
    revue.exiger(demande, "demande", "demande_invalide")
    with tempfile.TemporaryDirectory() as tmp:
        sujet, _ = revue.calculer_sujet(demande, pol, ancres, str(Path(args.depot_local).resolve()),
                                        Path(tmp) / "git", protocoles=("file",))
        try:
            resultats = recuperer_resultats(conf, sujet, tmp)
            decision = evaluer(resultats, sujet, args.request_id, conf, pol,
                               datetime.datetime.now(datetime.timezone.utc))
        except revue.Refus as e:
            decision = _rejet(e.motif)
    print(json.dumps(dict(decision, nature="verification_pure_non_autorisante"), ensure_ascii=False))
    return 0 if decision.acceptee else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Revue de confiance v1 : admission, sujet, normalisation, prédicat.

Bibliothèque standard seulement. Règle unique : la demande désigne, elle
n'affirme rien. La base n'est jamais demandée : c'est l'ancre gouvernée du
dépôt (`policy/ancres-v1.json`). Tout ce qui est signé est recalculé par ce
module depuis le dépôt candidat et depuis les fichiers du dépôt de confiance.

Sous-commandes appelées par `.github/workflows/revue.yml` :
  admission       lit l'événement `issues`, écarte les doublons de request_id,
                  rend la demande canonique ou un refus
  revue           récupère ancre et pointe, calcule le sujet, relit, rend le prédicat
  preparer        recalcule le sujet de façon indépendante, contrôle le prédicat,
                  écrit les fichiers à signer
  reponse         rédige le commentaire de réponse à partir des seules sorties
  politique       contrôle la politique (`--finale` : refuse une politique non ancrée)
"""
import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # nécessaire sous `python3 -I`
import schema_strict  # noqa: E402

RACINE = Path(__file__).resolve().parent.parent
FORMAT_SUJET = "olistic.confiance.sujet-revue/1"
FORMAT_PREDICAT = "olistic.confiance.attestation-revue/1"
VERSION_PROTOCOLE = "revue/1"
FICHIER_PROTOCOLE = "protocol/revue-v1.md"
FICHIER_POLITIQUE = "policy/confiance-v1.json"
FICHIER_ANCRES = "policy/ancres-v1.json"
VERDICTS = ("FAVORABLE", "DEFAVORABLE", "INDETERMINE")
GRAVITES_BLOQUANTES = ("bloquant", "majeur")
OID_NUL = b"0" * 40


class Refus(Exception):
    """Refus fermé : aucun prédicat n'est produit. `motif` est un code stable."""

    def __init__(self, motif, detail=""):
        super().__init__(f"{motif}: {detail}" if detail else motif)
        self.motif = motif


# ---------------------------------------------------------------- encodage

def _refuser_doublons(paires):
    vu = {}
    for cle, valeur in paires:
        if cle in vu:
            raise ValueError(f"clé en double : {cle}")
        vu[cle] = valeur
    return vu


def _refuser_constante(nom):
    raise ValueError(f"constante non JSON : {nom}")


def _refuser_flottant(texte):
    raise ValueError("flottant interdit")


def charger_json_strict(octets):
    """JSON strict : UTF-8 valide, ni clé en double, ni NaN/Infinity, ni flottant."""
    texte = octets.decode("utf-8") if isinstance(octets, (bytes, bytearray)) else octets
    return json.loads(texte, object_pairs_hook=_refuser_doublons,
                      parse_constant=_refuser_constante, parse_float=_refuser_flottant)


def canonique(obj):
    """Encodage canonique, identique à `octets_observation` du P1."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(octets):
    return hashlib.sha256(octets).hexdigest()


def schema(nom):
    return json.loads((RACINE / "schemas" / f"{nom}-v1.schema.json").read_text("utf-8"))


def exiger(valeur, nom_schema, motif):
    errs = schema_strict.erreurs(valeur, schema(nom_schema))
    if errs:
        raise Refus(motif, "; ".join(errs[:5]))


def instant_utc(texte):
    """`AAAA-MM-JJTHH:MM:SS[.f]Z` → datetime UTC ; None sinon. Fuseau Z seul."""
    if not isinstance(texte, str) or not texte.endswith("Z"):
        return None
    try:
        t = datetime.datetime.fromisoformat(texte[:-1][:26] + "+00:00")
    except ValueError:
        return None
    return t.astimezone(datetime.timezone.utc)


def format_instant(t):
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------- politique

def charger_politique(chemin=None, finale=False):
    chemin = Path(chemin) if chemin else RACINE / FICHIER_POLITIQUE
    try:
        pol = charger_json_strict(chemin.read_bytes())
    except ValueError as e:
        raise Refus("politique_invalide", str(e))
    exiger(pol, "politique", "politique_invalide")
    alias = [d["alias"] for d in pol["depots"]]
    familles = [r["famille"] for r in pol["relecteurs"]]
    if len(set(alias)) != len(alias) or len(set(familles)) != len(familles):
        raise Refus("politique_invalide", "alias ou famille en double")
    if instant_utc(pol["fraicheur"]["coupure"]) is None:
        raise Refus("politique_invalide", "coupure illisible")
    for r in pol["relecteurs"]:
        if r["acceptable"] and not r["actif"]:
            raise Refus("politique_invalide", "relecteur acceptable mais inactif")
        if r["famille"] == "factice" and (r["acceptable"] or r["modeles"] != [None]):
            raise Refus("politique_invalide", "relecteur factice")
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
    """Ancres gouvernées : une entrée par dépôt de la politique, modifiée par PR
    sur `main` seulement. Une ancre nulle interdit toute revue du dépôt."""
    chemin = Path(chemin) if chemin else RACINE / FICHIER_ANCRES
    try:
        ancres = charger_json_strict(chemin.read_bytes())
    except ValueError as e:
        raise Refus("ancres_invalides", str(e))
    exiger(ancres, "ancres", "ancres_invalides")
    alias = [a["alias"] for a in ancres["ancres"]]
    if sorted(alias) != sorted(d["alias"] for d in pol["depots"]):
        raise Refus("ancres_invalides", "les ancres doivent couvrir exactement les dépôts de la politique")
    for a in ancres["ancres"]:
        if (a["commit"] is None) != (a["objet_sha256"] is None):
            raise Refus("ancres_invalides", "commit et objet_sha256 vont ensemble")
    return {a["alias"]: a for a in ancres["ancres"]}


def relecteur_actif(pol):
    actifs = [r for r in pol["relecteurs"] if r["actif"]]
    if len(actifs) != 1:
        raise Refus("politique_invalide", "exactement un relecteur actif")
    return actifs[0]


# --------------------------------------------------------------- admission

def admettre(evenement, pol, anterieures=()):
    """Rend {demande, issue, demandeur_id} ou lève Refus.

    Le titre et les étiquettes sont ignorés ; le corps ne peut contenir que la
    désignation (request_id, alias, pointe) et la déclaration P1. Une demande
    dont le request_id figure déjà dans une issue antérieure (numéro plus petit)
    d'un demandeur autorisé est un doublon : la plus ancienne gagne, quel que
    soit l'ordre d'exécution des workflows."""
    if evenement.get("action") != "opened":
        raise Refus("evenement_non_pris_en_charge")
    issue = evenement.get("issue") or {}
    auteur = issue.get("user") or {}
    autorises = {d["id"] for d in pol["demandeurs"]}
    if auteur.get("type") != "User" or auteur.get("id") not in autorises:
        raise Refus("demandeur_non_autorise")
    numero = issue.get("number")
    if not isinstance(numero, int) or isinstance(numero, bool) or numero < 1:
        raise Refus("evenement_invalide")
    demande = lire_demande(issue.get("body"), pol)
    if demande["depot"] not in {d["alias"] for d in pol["depots"]}:
        raise Refus("depot_inconnu")
    for autre in anterieures:
        if not _issue_de_demandeur(autre, autorises) or autre["number"] >= numero:
            continue
        try:
            precedente = lire_demande(autre.get("body"), pol)
        except Refus:
            continue
        if precedente["request_id"] == demande["request_id"]:
            raise Refus("request_id_deja_utilise", f"issue {autre['number']}")
    return {"demande": demande, "issue": numero, "demandeur_id": auteur["id"]}


def _issue_de_demandeur(issue, autorises):
    """Issue d'un demandeur autorisé : identité = `user.id` numérique, seul.
    Le login n'intervient jamais (un compte renommé reste lui-même ; un autre
    compte qui reprend le login reste un tiers)."""
    user = issue.get("user") or {}
    return ("pull_request" not in issue and isinstance(issue.get("number"), int)
            and user.get("type") == "User" and user.get("id") in autorises)


def lire_demande(corps, pol):
    corps = (corps or "").encode("utf-8")
    if len(corps) > pol["limites"]["corps_demande_octets"]:
        raise Refus("demande_trop_longue")
    try:
        demande = charger_json_strict(corps.strip())
    except ValueError as e:
        raise Refus("demande_illisible", str(e))
    exiger(demande, "demande", "demande_invalide")
    return demande


PAGE_ISSUES = 100
MARGE_PAGES = 12  # issues ouvertes pendant la lecture : jusqu'à 1 100 de plus


def historique_anterieur(obtenir_page, numero):
    """Toutes les issues et PR de numéro < `numero`, lues en entier.

    Aucun filtre par login : `obtenir_page(n)` rend la page n de TOUTES les issues
    du dépôt (ordre de création croissant, 100 par page). L'identité est établie
    ensuite, localement, par `user.id` seul (`_issue_de_demandeur`). Un élément
    dont l'identité ne peut pas être établie fait refuser (échec fermé), tout
    comme un historique qui excède la borne déduite de `numero`."""
    issues, page = [], 1
    while True:
        if page > numero // PAGE_ISSUES + MARGE_PAGES:
            raise Refus("historique_trop_long")
        lot = obtenir_page(page)
        if not isinstance(lot, list) or len(lot) > PAGE_ISSUES:
            raise Refus("historique_illisible")
        for item in lot:
            user = item.get("user") if isinstance(item, dict) else None
            n = item.get("number") if isinstance(item, dict) else None
            if not isinstance(n, int) or isinstance(n, bool) or not isinstance(user, dict) \
                    or not isinstance(user.get("id"), int) or isinstance(user.get("id"), bool):
                raise Refus("historique_illisible", "identité non établie")
            if n < numero:
                issues.append(item)
        if len(lot) < PAGE_ISSUES:
            return issues
        page += 1


def lister_issues_api(env, numero):
    """Historique complet par l'API GitHub, sans paramètre `creator` ni login."""
    def obtenir_page(page):
        q = urllib.parse.urlencode({"state": "all", "sort": "created", "direction": "asc",
                                    "per_page": PAGE_ISSUES, "page": page})
        req = urllib.request.Request(f"{env['GITHUB_API_URL']}/repos/{env['GITHUB_REPOSITORY']}/issues?{q}",
                                     headers={"Authorization": f"Bearer {env['GH_TOKEN']}",
                                              "Accept": "application/vnd.github+json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return charger_json_strict(r.read())
        except Exception as e:  # noqa: BLE001 — tout échec est un refus
            raise Refus("historique_illisible", type(e).__name__)
    return historique_anterieur(obtenir_page, numero)


# ------------------------------------------------------------------- sujet

class Git:
    """git sans configuration système ni globale ni d'environnement, sans hooks,
    attributs, pilotes, helpers ni sous-modules : le dépôt nu est créé ici et
    rien du candidat ne s'y configure."""

    def __init__(self, dossier, protocoles=("https",)):
        self.dossier = Path(dossier)
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.dossier),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "LC_ALL": "C",
        }
        self.config = ["-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never",
                       "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null",
                       "-c", "credential.helper=", "-c", "transfer.fsckObjects=true",
                       "-c", "fetch.recurseSubmodules=false", "-c", "submodule.recurse=false"]
        for p in protocoles:
            self.config += ["-c", f"protocol.{p}.allow=always"]
        self.dossier.mkdir(parents=True, exist_ok=True)
        self("init", "--quiet", "--bare")

    def __call__(self, *args, entree=None, ok=(0,)):
        r = subprocess.run(["git", *self.config, "--git-dir", str(self.dossier), *args],
                           input=entree, env=self.env, capture_output=True, timeout=600)
        if r.returncode not in ok:
            raise Refus("git", f"{args[0]} rc={r.returncode}")
        return r

    def texte(self, *args):
        return self(*args).stdout.decode("ascii").strip()

    def contenus_sha256(self, oids):
        """sha256 du contenu de chaque blob, par `cat-file --batch` (aucun filtre)."""
        oids = list(dict.fromkeys(oids))
        if not oids:
            return {}
        lot = self("cat-file", "--batch", entree=b"".join(o + b"\n" for o in oids)).stdout
        out, pos = {}, 0
        for oid in oids:
            fin_entete = lot.index(b"\n", pos)
            _, typ, taille = lot[pos:fin_entete].split(b" ")
            if typ != b"blob":
                raise Refus("arbre_invalide", typ.decode())
            debut = fin_entete + 1
            fin = debut + int(taille)
            out[oid] = hashlib.sha256(lot[debut:fin]).hexdigest().encode()
            pos = fin + 1
        return out


def objet_commit_sha256(git, commit):
    """sha256 de l'objet commit au format d'objet git (`commit <taille>\\0<contenu>`)."""
    brut = git("cat-file", "commit", commit).stdout
    return sha256_hex(b"commit " + str(len(brut)).encode() + b"\0" + brut)


def empreinte_arbre(git, commit):
    """sha256 indépendant de SHA-1 : manifeste trié par chemin (octets) de
    `mode SP sha256(contenu) SP chemin NUL`. Un sous-module (gitlink) est refusé."""
    sortie = git("ls-tree", "-r", "-z", "--full-tree", commit).stdout
    entrees = []
    for brut in filter(None, sortie.split(b"\0")):
        meta, chemin = brut.split(b"\t", 1)
        mode, typ, oid = meta.split(b" ")
        if typ == b"commit" or mode == b"160000":
            raise Refus("gitlink_refuse")
        if typ != b"blob":
            raise Refus("arbre_invalide", typ.decode())
        entrees.append((chemin, mode, oid))
    entrees.sort(key=lambda e: e[0])
    h = git.contenus_sha256(e[2] for e in entrees)
    return sha256_hex(b"".join(mode + b" " + h[oid] + b" " + chemin + b"\0" for chemin, mode, oid in entrees))


def empreinte_perimetre(git, base, pointe):
    """sha256 du manifeste canonique du périmètre base..pointe : pour chaque
    chemin modifié (trié par octets), `statut SP mode_avant SP h_avant SP
    mode_apres SP h_apres SP chemin NUL`, h = sha256 du contenu ou `-`."""
    sortie = git("diff-tree", "-r", "-z", "--no-renames", "--no-ext-diff", "--no-textconv",
                 "--raw", "--full-index", base, pointe).stdout
    champs = sortie.split(b"\0")
    entrees, i = [], 0
    while i < len(champs) and champs[i]:
        meta, chemin = champs[i], champs[i + 1]
        om, nm, oo, no, statut = meta.lstrip(b":").split(b" ")
        if b"160000" in (om, nm):
            raise Refus("gitlink_refuse")
        entrees.append((chemin, statut, om, oo, nm, no))
        i += 2
    entrees.sort(key=lambda e: e[0])
    h = git.contenus_sha256(o for e in entrees for o in (e[3], e[5]) if o != OID_NUL)
    lignes = []
    for chemin, statut, om, oo, nm, no in entrees:
        avant = h[oo] if oo != OID_NUL else b"-"
        apres = h[no] if no != OID_NUL else b"-"
        lignes.append(b" ".join((statut, om, avant, nm, apres, chemin)) + b"\0")
    return sha256_hex(b"".join(lignes))


def _identite_commit(git, commit):
    return {
        "commit": commit,
        "objet_sha256": objet_commit_sha256(git, commit),
        "arbre": git.texte("rev-parse", "--verify", commit + "^{tree}"),
        "arbre_sha256": empreinte_arbre(git, commit),
    }


def calculer_sujet(demande, pol, ancres, url, travail, protocoles=("https",)):
    """Récupère l'ancre gouvernée (base) et la pointe depuis `url` et recalcule
    tout le sujet. La demande ne fournit que la pointe. Retourne (sujet, git)."""
    depot = next(d for d in pol["depots"] if d["alias"] == demande["depot"])
    ancre = ancres[demande["depot"]]
    if depot["repository_id"] is None:
        raise Refus("politique_non_ancree")
    if ancre["commit"] is None:
        raise Refus("ancre_absente")
    base, pointe = ancre["commit"], demande["pointe"]
    if base == pointe:
        raise Refus("pointe_egale_ancre")
    git = Git(travail, protocoles)
    git("fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
        url, base, pointe, ok=(0, 128))
    for cle, sha in (("ancre", base), ("pointe", pointe)):
        r = git("rev-parse", "--verify", "--quiet", "--end-of-options", sha + "^{commit}", ok=(0, 1, 128))
        if r.returncode != 0 or r.stdout.decode().strip() != sha:
            raise Refus("objet_introuvable", cle)
    if objet_commit_sha256(git, base) != ancre["objet_sha256"]:
        raise Refus("ancre_divergente")
    if git("merge-base", "--is-ancestor", base, pointe, ok=(0, 1)).returncode:
        raise Refus("ancre_non_ancetre")
    sujet = {
        "format": FORMAT_SUJET,
        "depot": {"alias": depot["alias"], "repository_id": depot["repository_id"]},
        "base": _identite_commit(git, base),
        "pointe": _identite_commit(git, pointe),
        "perimetre_sha256": empreinte_perimetre(git, base, pointe),
    }
    exiger(sujet, "sujet-revue", "sujet_invalide")
    return sujet, git


def extraire_diff(git, sujet):
    return git("diff", "--no-ext-diff", "--no-textconv", "--no-color", "--binary", "--no-renames",
               sujet["base"]["commit"], sujet["pointe"]["commit"]).stdout


def url_du_depot(depot, env):
    """Lot 1 : seul le dépôt de confiance lui-même (public) est récupérable.
    Les dépôts candidats privés exigent l'identité de lecture du Lot 2."""
    if str(depot["repository_id"]) != env.get("GITHUB_REPOSITORY_ID"):
        raise Refus("depot_hors_lot1")
    return f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}.git"


def nom_sujet(sujet, request_id):
    return f"olistic-revue:{sujet['depot']['alias']}@{sujet['pointe']['commit']}#{request_id}"


# --------------------------------------------------------------- relecture

def relire(famille, diff):
    """Sortie brute du relecteur. Le relecteur ne reçoit que le diff comme
    donnée ; il n'exécute rien et ne lit aucune instruction du candidat."""
    if famille == "factice":
        return b""
    raise Refus("relecteur_non_disponible_lot1", famille)


def normaliser_verdict(famille, sortie):
    """(verdict, motif, rapport_sha256). Toute sortie non conforme devient
    INDETERMINE ; un relecteur factice ne rend jamais autre chose ; un
    FAVORABLE accompagné d'un constat bloquant ou majeur est incohérent."""
    if famille == "factice":
        return "INDETERMINE", "relecteur_factice", None
    if not sortie:
        return "INDETERMINE", "sortie_invalide", None
    empreinte = sha256_hex(sortie)
    try:
        obj = charger_json_strict(sortie)
    except (ValueError, UnicodeDecodeError):
        return "INDETERMINE", "sortie_invalide", empreinte
    if schema_strict.erreurs(obj, schema("sortie-relecteur")):
        return "INDETERMINE", "sortie_invalide", empreinte
    if obj["verdict"] == "INDETERMINE":
        return "INDETERMINE", "relecteur", empreinte
    if obj["verdict"] == "FAVORABLE" and any(c["gravite"] in GRAVITES_BLOQUANTES for c in obj["constats"]):
        return "INDETERMINE", "favorable_incoherent", empreinte
    return obj["verdict"], None, empreinte


# ---------------------------------------------------------------- prédicat

def empreintes_locales():
    return {cle: sha256_hex((RACINE / f).read_bytes())
            for cle, f in (("protocole", FICHIER_PROTOCOLE), ("politique", FICHIER_POLITIQUE),
                           ("ancres", FICHIER_ANCRES))}


def construire_predicat(sujet, admis, pol, famille, modele, verdict, motif, rapport, instant=None):
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
        "relecteur": {"famille": famille, "modele": modele},
        "verdict": verdict,
        "motif": motif,
        "rapport_sha256": rapport,
        "instant": instant or format_instant(datetime.datetime.now(datetime.timezone.utc)),
    }
    controler_invariants(predicat, pol)
    return predicat


def controler_invariants(predicat, pol):
    """Invariants du prédicat contre la politique en vigueur (côté producteur)."""
    exiger(predicat, "attestation-revue", "predicat_invalide")
    if (predicat["verdict"] == "INDETERMINE") != (predicat["motif"] is not None):
        raise Refus("predicat_invalide", "motif exigé si et seulement si INDETERMINE")
    if predicat["relecteur"]["famille"] == "factice" and predicat["verdict"] != "INDETERMINE":
        raise Refus("predicat_invalide", "relecteur factice")
    if predicat["politique"]["generation"] != pol["generation"]:
        raise Refus("predicat_invalide", "génération")
    r = next((x for x in pol["relecteurs"] if x["famille"] == predicat["relecteur"]["famille"]), None)
    if r is None or not r["actif"]:
        raise Refus("predicat_invalide", "relecteur inactif")
    if predicat["relecteur"]["modele"] not in r["modeles"]:
        raise Refus("predicat_invalide", "modèle non autorisé")


def preparer_signature(predicat_brut, admis, sujet_recalcule, pol):
    """Contrôle du job de signature : le prédicat reçu du job de revue est
    relu strictement et confronté à un sujet recalculé ici, indépendamment."""
    try:
        predicat = charger_json_strict(predicat_brut)
    except ValueError as e:
        raise Refus("predicat_invalide", str(e))
    controler_invariants(predicat, pol)
    if canonique(predicat["sujet"]) != canonique(sujet_recalcule):
        raise Refus("sujet_divergent")
    e = empreintes_locales()
    if (predicat["protocole"]["sha256"], predicat["politique"]["sha256"], predicat["ancres_sha256"]) != \
            (e["protocole"], e["politique"], e["ancres"]):
        raise Refus("empreintes_divergentes")
    attendu = {"issue": admis["issue"], "demandeur_id": admis["demandeur_id"],
               "request_id": admis["demande"]["request_id"], "declaration_p1": admis["demande"]["declaration_p1"]}
    if predicat["demande"] != attendu:
        raise Refus("demande_divergente")
    t = instant_utc(predicat["instant"])
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    if t is None or not (0 <= (maintenant - t).total_seconds() <= pol["fraicheur"]["tolerance_instant_s"]):
        raise Refus("instant_incoherent")
    octets_sujet = canonique(sujet_recalcule)
    return {
        "sujet_octets": octets_sujet,
        "sujet_digest": sha256_hex(octets_sujet),
        "sujet_nom": nom_sujet(sujet_recalcule, admis["demande"]["request_id"]),
        "predicat_octets": canonique(predicat),
        "verdict": predicat["verdict"],
    }


# --------------------------------------------------------------------- CLI

def ecrire_sorties(chemin, valeurs):
    with open(chemin, "a", encoding="utf-8") as f:
        for cle, valeur in valeurs.items():
            texte = str(valeur)
            if "\n" in texte or "\r" in texte:
                raise Refus("sortie_multiligne", cle)
            f.write(f"{cle}={texte}\n")


def _admis_depuis_env():
    return charger_json_strict(os.environ["ADMIS"].encode())


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
        print("politique conforme" + (" et ancrée" if args.finale else ""))
        return 0

    if args.cmd == "admission":
        try:
            pol = charger_politique(finale=True)
            evenement = charger_json_strict(Path(args.evenement).read_bytes())
            premier = admettre(evenement, pol)  # refus précoces, avant tout appel d'API
            admis = admettre(evenement, pol, lister_issues_api(os.environ, premier["issue"]))
        except Refus as e:
            ecrire_sorties(args.sortie, {"admis": "non", "motif": e.motif})
            print(f"refus : {e.motif}")
            return 0
        ecrire_sorties(args.sortie, {"admis": "oui", "motif": "", "demande": canonique(admis).decode()})
        return 0

    if args.cmd == "revue":
        try:
            pol = charger_politique(finale=True)
            ancres = charger_ancres(pol)
            admis = _admis_depuis_env()
            depot = next(d for d in pol["depots"] if d["alias"] == admis["demande"]["depot"])
            sujet, git = calculer_sujet(admis["demande"], pol, ancres, url_du_depot(depot, os.environ), args.travail)
            rel = relecteur_actif(pol)
            diff = extraire_diff(git, sujet)
            if len(diff) > pol["limites"]["diff_octets"]:
                verdict, motif, rapport = "INDETERMINE", "diff_trop_grand", None
            else:
                verdict, motif, rapport = normaliser_verdict(rel["famille"], relire(rel["famille"], diff))
            predicat = construire_predicat(sujet, admis, pol, rel["famille"], rel["modeles"][0],
                                           verdict, motif, rapport)
        except Refus as e:
            ecrire_sorties(args.sortie, {"statut": "refus", "motif": e.motif})
            print(f"refus : {e.motif}")
            return 0
        ecrire_sorties(args.sortie, {"statut": "pret", "motif": "", "predicat": canonique(predicat).decode()})
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
        ecrire_sorties(args.sortie, {
            "sujet_digest": "sha256:" + prep["sujet_digest"],
            "sujet_nom": prep["sujet_nom"],
            "verdict": prep["verdict"],
        })
        return 0

    if args.cmd == "reponse":
        e = os.environ
        lignes = ["Réponse automatique du protocole revue/1. Ce commentaire n'est pas une preuve : "
                  "seule l'attestation signée fait foi."]
        if e.get("ADMIS_OUI") != "oui":
            lignes.append(f"- statut : refusée à l'admission ({e.get('MOTIF_ADMISSION') or 'inconnu'})")
        elif e.get("STATUT_REVUE") != "pret":
            lignes.append(f"- statut : refusée avant attestation ({e.get('MOTIF_REVUE') or 'inconnu'})")
        elif e.get("RESULTAT_ATTESTATION") != "success":
            lignes.append("- statut : échec de l'attestation (aucune preuve émise)")
        else:
            lignes.append(f"- statut : attestée, verdict `{e.get('VERDICT')}`")
            lignes.append(f"- sujet : `{e.get('SUJET_DIGEST')}`")
            lignes.append(f"- attestation : {e.get('URL_ATTESTATION')}")
        Path(args.fichier).write_text("\n".join(lignes) + "\n", encoding="utf-8")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())

"""Oracle INDÉPENDANT des vecteurs critiques de revue/2 : encodage canonique,
sujet, digest et nom. Réécrit d'après le texte du protocole (revue-v1 §4,
revue-v2 §4), SANS importer `outils/` ni réutiliser ses algorithmes :

- encodage JSON écrit à la main (pas de `json.dumps`) ;
- objet commit : octets bruts encadrés puis contrôlés par leur SHA-1 git ;
- arbre : un `cat-file blob` par fichier (pas de `--batch`), chaque blob
  contrôlé par son SHA-1 git ;
- périmètre : différence calculée entre deux listes `ls-tree` (pas de
  `diff-tree`).

Une erreur commune au producteur et au consommateur (qui partagent
`outils/revue.py`) ne se retrouve donc pas ici."""
import hashlib
import subprocess

ENV_GIT = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "LC_ALL": "C"}


# -------------------------------------------------------------- encodage

def _chaine(s):
    out = ['"']
    for c in s:
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c == "\n":
            out.append("\\n")
        elif c == "\r":
            out.append("\\r")
        elif c == "\t":
            out.append("\\t")
        elif c == "\b":
            out.append("\\b")
        elif c == "\f":
            out.append("\\f")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def _texte(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _chaine(v)
    if isinstance(v, list):
        return "[" + ",".join(_texte(x) for x in v) + "]"
    if isinstance(v, dict):
        cles = sorted(v, key=lambda k: [ord(c) for c in k])
        return "{" + ",".join(_chaine(k) + ":" + _texte(v[k]) for k in cles) + "}"
    raise TypeError(type(v).__name__)


def canonique(v):
    return _texte(v).encode("utf-8")


# ------------------------------------------------------------------- git

def _git(depot, *args):
    return subprocess.run(["git", "-C", str(depot), *args], env=ENV_GIT, check=True, capture_output=True).stdout


def objet_commit_sha256(depot, commit):
    brut = _git(depot, "cat-file", "commit", commit)
    cadre = b"commit " + str(len(brut)).encode() + b"\x00" + brut
    assert hashlib.sha1(cadre).hexdigest() == commit, "cadre d'objet commit incorrect"
    return hashlib.sha256(cadre).hexdigest()


def _liste(depot, commit):
    """{chemin (octets): (mode, oid)} pour tous les blobs de l'arbre."""
    out = {}
    for brut in _git(depot, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\x00"):
        if not brut:
            continue
        meta, chemin = brut.split(b"\t", 1)
        mode, typ, oid = meta.split(b" ")
        assert typ == b"blob", typ
        out[chemin] = (mode, oid)
    return out


def _contenu_sha256(depot, oid):
    contenu = _git(depot, "cat-file", "blob", oid.decode())
    assert hashlib.sha1(b"blob " + str(len(contenu)).encode() + b"\x00" + contenu).hexdigest() == oid.decode()
    return hashlib.sha256(contenu).hexdigest().encode()


def arbre(depot, commit):
    return _git(depot, "rev-parse", commit + "^{tree}").decode().strip()


def arbre_sha256(depot, commit):
    l = _liste(depot, commit)
    lignes = [mode + b" " + _contenu_sha256(depot, oid) + b" " + chemin + b"\x00"
              for chemin, (mode, oid) in sorted(l.items())]
    return hashlib.sha256(b"".join(lignes)).hexdigest()


def _type(mode):
    return mode[:3]  # 100 = fichier, 120 = lien symbolique


def perimetre_sha256(depot, base, pointe):
    avant, apres = _liste(depot, base), _liste(depot, pointe)
    lignes = []
    for chemin in sorted(set(avant) | set(apres)):
        a, p = avant.get(chemin), apres.get(chemin)
        if a == p:
            continue
        if a is None:
            statut = b"A"
        elif p is None:
            statut = b"D"
        elif _type(a[0]) != _type(p[0]):
            statut = b"T"
        else:
            statut = b"M"
        mode_a, h_a = (a[0], _contenu_sha256(depot, a[1])) if a else (b"000000", b"-")
        mode_p, h_p = (p[0], _contenu_sha256(depot, p[1])) if p else (b"000000", b"-")
        lignes.append(b" ".join((statut, mode_a, h_a, mode_p, h_p, chemin)) + b"\x00")
    return hashlib.sha256(b"".join(lignes)).hexdigest()


def identite(depot, commit):
    return {"commit": commit, "objet_sha256": objet_commit_sha256(depot, commit),
            "arbre": arbre(depot, commit), "arbre_sha256": arbre_sha256(depot, commit)}


def sujet(depot, base, pointe, alias, repository_id, format_sujet="olistic.confiance.sujet-revue/2"):
    return {"format": format_sujet, "depot": {"alias": alias, "repository_id": repository_id},
            "base": identite(depot, base), "pointe": identite(depot, pointe),
            "perimetre_sha256": perimetre_sha256(depot, base, pointe)}


def digest(s):
    return hashlib.sha256(canonique(s)).hexdigest()


def nom(s, request_id, prefixe="olistic-revue2"):
    return f"{prefixe}:{s['depot']['alias']}@{s['pointe']['commit']}#{request_id}"

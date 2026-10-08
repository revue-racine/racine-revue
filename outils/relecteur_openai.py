"""Relecteur `openai-responses` du protocole revue/2 (protocol/revue-v2.md §5).

Bibliothèque standard seulement. Un seul appel `POST /v1/responses`, sans
outil, sans stockage, sans reprise ; le relecteur ne reçoit que le diff comme
donnée et la consigne fixe de ce dépôt. Rien du candidat n'est exécuté.

Deux niveaux, jamais confondus :
  - l'ENVELOPPE fournisseur (transport HTTP, statut, modèle, éléments de
    sortie) : toute anomalie lève `revue.Refus` avec un code stable, et aucun
    prédicat n'est produit ;
  - la SORTIE DU RELECTEUR : l'unique `output_text` d'une enveloppe valide,
    rendue telle quelle (octets UTF-8) à la normalisation de §5, qui seule
    décide FAVORABLE / DEFAVORABLE / INDETERMINE.

La clé n'apparaît que dans l'en-tête `Authorization` : aucun message
d'erreur, aucune exception, aucune sortie ne la reprend. L'identité du modèle
est celle que le fournisseur déclare ; elle n'est pas prouvée.
"""
import copy
import http.client
import json
import re
import signal
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # nécessaire sous `python3 -I`
import revue  # noqa: E402

HOTE = "api.openai.com"
PORT = 443
CHEMIN = "/v1/responses"
DELAI_TOTAL_S = 300.0
DELAI_SOCKET_S = 30.0
TAILLE_MAX = 1024 * 1024
LECTURE = 65536
MAX_OUTPUT_TOKENS = 32000
EFFORT = "medium"
NOM_FORMAT = "sortie_relecteur_v1"
# Format admis d'une clé, vérifié AVANT toute construction d'en-tête : une clé
# hors format (retour à la ligne, espace, caractère de contrôle) ne doit jamais
# atteindre http.client, dont les erreurs d'en-tête reprennent la valeur.
FORMAT_CLE = re.compile(r"[A-Za-z0-9_-]{20,512}")
FICHIER_CONSIGNE = Path(__file__).resolve().parent / "consigne-relecteur-v2.txt"

# Projection du schéma local vers Structured Outputs (§5.3) : liste blanche.
CONSERVES = frozenset({"type", "properties", "required", "additionalProperties", "enum",
                       "items", "minItems", "maxItems", "pattern"})
SUPPRIMES = frozenset({"$schema", "$id", "title", "description", "minLength", "maxLength"})


class _Echeance(BaseException):
    """Levée par la minuterie murale ; BaseException pour ne jamais être
    absorbée par un `except Exception` d'une bibliothèque."""


# ------------------------------------------------------------- projection

def projeter(schema):
    """Schéma local → schéma Structured Outputs. Ne fait que relâcher : toute
    instance valide localement l'est pour le schéma projeté. Tout mot-clé
    inconnu, objet ouvert ou partiellement requis fait échouer (échec fermé)."""
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise revue.Refus("projection_invalide", "racine non objet")
    return _projeter(schema, "$")


def _projeter(noeud, chemin):
    if not isinstance(noeud, dict):
        raise revue.Refus("projection_invalide", chemin)
    inconnus = set(noeud) - CONSERVES - SUPPRIMES
    if inconnus:
        raise revue.Refus("projection_invalide", f"{chemin} : {sorted(inconnus)}")
    out = {}
    for cle, valeur in noeud.items():
        if cle in SUPPRIMES:
            continue
        if cle == "properties":
            out[cle] = {k: _projeter(v, f"{chemin}.{k}") for k, v in valeur.items()}
        elif cle == "items":
            out[cle] = _projeter(valeur, f"{chemin}[]")
        else:
            out[cle] = copy.deepcopy(valeur)
    if "properties" in out:
        if out.get("additionalProperties") is not False:
            raise revue.Refus("projection_invalide", f"{chemin} : objet ouvert")
        if sorted(out.get("required", [])) != sorted(out["properties"]):
            raise revue.Refus("projection_invalide", f"{chemin} : toutes les clés doivent être requises")
    return out


# ---------------------------------------------------------------- requête

def encadrer(diff):
    """Diff encadré par une borne qui dépend de son propre contenu. Ce n'est
    PAS une frontière de sécurité : le contenu reste non fiable."""
    borne = "DIFF-" + revue.sha256_hex(diff)
    texte = diff.decode("utf-8", errors="replace")
    return f"<<{borne}>>\n{texte}\n<</{borne}>>\n"


def construire_requete(modele, diff, schema_sortie):
    return {
        "model": modele,
        "instructions": FICHIER_CONSIGNE.read_text("utf-8"),
        "input": [{"role": "user", "content": [{"type": "input_text", "text": encadrer(diff)}]}],
        "text": {"format": {"type": "json_schema", "name": NOM_FORMAT, "strict": True,
                            "schema": projeter(schema_sortie)}},
        "store": False,
        "max_output_tokens": MAX_OUTPUT_TOKENS,
        "reasoning": {"effort": EFFORT},
    }


# -------------------------------------------------------------- transport

def contexte_tls():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise revue.Refus("relecteur_configuration", "tls")
    return ctx


def connexion_defaut():
    """Connexion directe à l'hôte constant : http.client ne suit aucune
    redirection, ne lit aucune variable de mandataire et ne réessaie jamais."""
    return http.client.HTTPSConnection(HOTE, PORT, timeout=DELAI_SOCKET_S, context=contexte_tls())


def _echeance(signum, frame):
    raise _Echeance()


_NON_ARME = object()


def appeler(cle, corps, connexion=None, delai_total=DELAI_TOTAL_S, taille_max=TAILLE_MAX):
    """Un seul POST. Rend le corps de réponse (octets) d'un statut 200, ou lève
    `revue.Refus`. Aucune exception ne porte la clé ni le contenu échangé."""
    if not isinstance(cle, str) or not cle:
        raise revue.Refus("relecteur_cle_absente")
    if FORMAT_CLE.fullmatch(cle) is None:
        raise revue.Refus("relecteur_cle_invalide")
    precedent, conn = _NON_ARME, None
    try:
        try:
            try:
                precedent = signal.signal(signal.SIGALRM, _echeance)
                signal.setitimer(signal.ITIMER_REAL, delai_total)
            except (ValueError, OSError):  # hors du fil principal, ou minuterie indisponible
                raise revue.Refus("relecteur_minuterie")
            conn = (connexion or connexion_defaut)()
            conn.request("POST", CHEMIN, body=corps, headers={
                "Authorization": "Bearer " + cle,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": "racine-revue/2",
            })
            rep = conn.getresponse()
            statut = rep.status
            if statut != 200:
                if 300 <= statut < 400:
                    raise revue.Refus("relecteur_redirection")
                if statut == 429:
                    raise revue.Refus("relecteur_quota")
                if 400 <= statut < 500:
                    raise revue.Refus("relecteur_http_client")
                raise revue.Refus("relecteur_http_serveur")
            if (rep.getheader("Content-Encoding") or "identity").strip().lower() != "identity":
                raise revue.Refus("relecteur_encodage")
            morceaux, total = [], 0
            while True:
                bloc = rep.read(LECTURE)
                if not bloc:
                    break
                total += len(bloc)
                if total > taille_max:
                    raise revue.Refus("relecteur_trop_grand")
                morceaux.append(bloc)
            return b"".join(morceaux)
        except revue.Refus:
            raise
        except _Echeance:
            raise revue.Refus("relecteur_delai")
        except (OSError, http.client.HTTPException):  # ssl.SSLError et socket.timeout compris
            raise revue.Refus("relecteur_connexion")
        except Exception:  # noqa: BLE001 — tout le reste : échec fermé, sans détail
            raise revue.Refus("relecteur_interne")
    except _Echeance:  # minuterie échue pendant le traitement d'une autre erreur
        raise revue.Refus("relecteur_delai")
    finally:
        if precedent is not _NON_ARME:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
            except OSError:
                pass  # minuterie jamais armée : rien à désarmer
            signal.signal(signal.SIGALRM, precedent)
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


# --------------------------------------------------------------- enveloppe

def _json_enveloppe(octets):
    """JSON de l'enveloppe : UTF-8, sans clé en double ni NaN ; les flottants
    (temperature, top_p…) sont admis mais gardés en texte, jamais interprétés."""
    try:
        return json.loads(octets.decode("utf-8"), object_pairs_hook=revue._refuser_doublons,
                          parse_constant=revue._refuser_constante, parse_float=str)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise revue.Refus("relecteur_enveloppe_illisible")


def analyser_enveloppe(octets, modele):
    """Enveloppe Responses → octets UTF-8 de l'unique `output_text`.
    Statut, modèle et nature de chaque élément sont contrôlés ; tout écart
    lève Refus. Le texte rendu n'est PAS validé ici (§5 le normalise)."""
    env = _json_enveloppe(octets)
    if not isinstance(env, dict) or env.get("object") != "response":
        raise revue.Refus("relecteur_enveloppe_illisible")
    if env.get("status") != "completed":
        raise revue.Refus("relecteur_statut")
    if env.get("error") is not None or env.get("incomplete_details") is not None:
        raise revue.Refus("relecteur_statut")
    if env.get("model") != modele:
        raise revue.Refus("relecteur_modele_inattendu")
    sortie = env.get("output")
    if not isinstance(sortie, list):
        raise revue.Refus("relecteur_enveloppe_illisible")
    textes = []
    for element in sortie:
        t = element.get("type") if isinstance(element, dict) else None
        if t not in ("message", "reasoning"):
            raise revue.Refus("relecteur_element_inattendu")
        if t == "reasoning":
            continue
        if element.get("role", "assistant") != "assistant" or not isinstance(element.get("content"), list):
            raise revue.Refus("relecteur_enveloppe_illisible")
        for partie in element["content"]:
            tp = partie.get("type") if isinstance(partie, dict) else None
            if tp == "refusal":
                raise revue.Refus("relecteur_refus_modele")
            if tp != "output_text" or not isinstance(partie.get("text"), str):
                raise revue.Refus("relecteur_element_inattendu")
            textes.append(partie["text"])
    if len(textes) != 1:
        raise revue.Refus("relecteur_sortie_absente")
    return textes[0].encode("utf-8")


# ------------------------------------------------------------------ relire

def relire(cle, modele, diff, schema_sortie, connexion=None):
    """Sortie brute du relecteur (octets), ou Refus sur toute anomalie
    d'enveloppe. Le code candidat n'est jamais exécuté ; seul le diff, comme
    donnée, quitte le runner."""
    corps = json.dumps(construire_requete(modele, diff, schema_sortie), ensure_ascii=False,
                       separators=(",", ":")).encode("utf-8")
    return analyser_enveloppe(appeler(cle, corps, connexion), modele)

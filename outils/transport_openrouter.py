"""Transport HTTP strict pour l'adaptateur OpenRouter de ``revue/3``.

Le module ne décide ni de la famille, ni du budget, ni du verdict. Il sait
seulement effectuer une requête HTTPS vers l'un des deux chemins fermés du lot :
le précontrôle de la clé puis l'inférence. Il ne suit aucune redirection, ne lit
aucun mandataire de l'environnement et ne réessaie jamais.

Le point d'entrée de l'adaptateur 3A.2 refuse ce transport réel : les tests et
le lot courant utilisent exclusivement un transport simulé. Cette brique est
donc testée comme un composant isolé, sans appel fournisseur.
"""
from dataclasses import dataclass
import http.client
import json
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import relecteur_openai as transport_v2  # noqa: E402
import revue  # noqa: E402

HOTE = "openrouter.ai"
PORT = 443
CHEMIN_BUDGET = "/api/v1/key"
CHEMIN_INFERENCE = "/api/v1/chat/completions"
DELAI_SOCKET_S = 30.0
DELAI_TOTAL_S = 300.0
TAILLE_BUDGET_MAX = 128 * 1024
TAILLE_INFERENCE_MAX = 1024 * 1024
LECTURE = 65536
METHODES = {CHEMIN_BUDGET: "GET", CHEMIN_INFERENCE: "POST"}
ENTETES_INFERENCE = {
    "X-OpenRouter-Metadata": "enabled",
    "X-OpenRouter-Cache": "false",
}


@dataclass(frozen=True)
class Requete:
    methode: str
    chemin: str
    corps: bytes | None


@dataclass(frozen=True)
class Reponse:
    corps: bytes
    entetes: dict


def requete_budget():
    return Requete("GET", CHEMIN_BUDGET, None)


def requete_inference(corps):
    return Requete("POST", CHEMIN_INFERENCE, corps)


def valider_requete(requete):
    if not isinstance(requete, Requete):
        raise revue.Refus("openrouter_requete_invalide")
    if requete.chemin not in METHODES or requete.methode != METHODES[requete.chemin]:
        raise revue.Refus("openrouter_route_interdite")
    if requete.chemin == CHEMIN_BUDGET and requete.corps is not None:
        raise revue.Refus("openrouter_requete_invalide")
    if requete.chemin == CHEMIN_INFERENCE and not isinstance(requete.corps, bytes):
        raise revue.Refus("openrouter_requete_invalide")
    return requete


def contexte_tls():
    contexte = ssl.create_default_context()
    contexte.minimum_version = ssl.TLSVersion.TLSv1_2
    if contexte.verify_mode != ssl.CERT_REQUIRED or not contexte.check_hostname:
        raise revue.Refus("openrouter_configuration")
    return contexte


def connexion_defaut():
    """Connexion directe : ``http.client`` n'utilise pas les variables proxy."""
    return http.client.HTTPSConnection(
        HOTE, PORT, timeout=DELAI_SOCKET_S, context=contexte_tls()
    )


def _entetes(requete, cle):
    entetes = {
        "Authorization": "Bearer " + cle,
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "User-Agent": "racine-revue/3A.2",
    }
    if requete.chemin == CHEMIN_INFERENCE:
        entetes["Content-Type"] = "application/json"
        entetes.update(ENTETES_INFERENCE)
    return entetes


def _taille_max(requete):
    return TAILLE_BUDGET_MAX if requete.chemin == CHEMIN_BUDGET else TAILLE_INFERENCE_MAX


def _lire_entetes(reponse):
    """Ne conserve que les en-têtes utiles, jamais une valeur d'authentification."""
    return {
        nom.lower(): reponse.getheader(nom)
        for nom in ("Content-Encoding", "Content-Length", "X-OpenRouter-Cache-Status")
        if reponse.getheader(nom) is not None
    }


def _echanger(minuterie, etat, cle, requete, connexion, delai_total, taille_max):
    try:
        minuterie.armer(delai_total)
        etat["conn"] = conn = (connexion or connexion_defaut)()
        conn.request(
            requete.methode,
            requete.chemin,
            body=requete.corps,
            headers=_entetes(requete, cle),
        )
        rep = conn.getresponse()
        minuterie.verifier()
        statut = rep.status
        if statut != 200:
            if 300 <= statut < 400:
                raise revue.Refus("openrouter_redirection")
            if statut == 429:
                raise revue.Refus("openrouter_quota")
            if 400 <= statut < 500:
                raise revue.Refus("openrouter_http_client")
            raise revue.Refus("openrouter_http_serveur")
        entetes = _lire_entetes(rep)
        if (entetes.get("content-encoding") or "identity").strip().lower() != "identity":
            raise revue.Refus("openrouter_encodage")
        annoncee = entetes.get("content-length")
        if annoncee is not None:
            try:
                annoncee = int(annoncee)
            except (TypeError, ValueError):
                raise revue.Refus("openrouter_entete_invalide")
            if annoncee < 0 or annoncee > taille_max:
                raise revue.Refus("openrouter_trop_grand")
        morceaux, total = [], 0
        while True:
            bloc = rep.read(LECTURE)
            minuterie.verifier()
            if not bloc:
                break
            total += len(bloc)
            if total > taille_max:
                raise revue.Refus("openrouter_trop_grand")
            morceaux.append(bloc)
        if annoncee is not None and total != annoncee:
            raise revue.Refus("openrouter_reponse_tronquee")
        return Reponse(b"".join(morceaux), entetes)
    except revue.Refus:
        raise
    except (OSError, http.client.HTTPException, ssl.SSLError):
        raise revue.Refus("openrouter_connexion")
    except Exception:  # échec fermé ; aucun détail sensible ne sort
        raise revue.Refus("openrouter_interne")


def appeler(cle, requete, connexion=None, delai_total=DELAI_TOTAL_S, taille_max=None):
    """Effectue exactement une requête, sans retry, et rend des octets bornés."""
    valider_requete(requete)
    if not isinstance(cle, str) or not cle:
        raise revue.Refus("openrouter_cle_absente")
    if not transport_v2.cle_utilisable(cle):
        raise revue.Refus("openrouter_cle_invalide")
    limite = _taille_max(requete) if taille_max is None else taille_max
    minuterie = transport_v2._Minuterie()
    etat = {"conn": None}
    try:
        try:
            resultat = _echanger(
                minuterie, etat, cle, requete, connexion, delai_total, limite
            )
        except BaseException:
            if not transport_v2._nettoyer(minuterie, etat):
                raise revue.Refus("openrouter_nettoyage") from None
            raise
        if not transport_v2._nettoyer(minuterie, etat):
            raise revue.Refus("openrouter_nettoyage")
        minuterie.verifier()
        return resultat
    except transport_v2._Echeance:
        motif = (
            "openrouter_delai"
            if transport_v2._nettoyer(minuterie, etat)
            else "openrouter_nettoyage"
        )
        raise revue.Refus(motif) from None


class TransportHTTPS:
    """Transport réel isolé. Le point d'entrée 3A.2 le refuse explicitement."""

    simule = False

    def __init__(self, connexion=None):
        self.connexion = connexion
        self.appels = 0

    def envoyer(self, cle, requete):
        self.appels += 1
        return appeler(cle, requete, connexion=self.connexion)


def serialiser_json(objet):
    return json.dumps(
        objet, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")

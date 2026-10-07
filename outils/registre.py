#!/usr/bin/env python3
"""Registre de consommation des request_id (protocole §6, §8).

Source de vérité : des étiquettes git du dépôt de confiance, créées par l'API
GitHub depuis le job protégé. La création d'une référence est atomique côté
serveur (une seconde création du même nom échoue en 422) et la règle
`etiquettes-immuables` interdit d'en déplacer ou d'en supprimer une. L'hôte des
agents n'a aucun rôle sur ce dépôt : il ne peut ni créer ni modifier ces refs.

États d'un request_id, dérivés des refs présentes :

    DISPONIBLE   aucune ref
    RESERVE      refs/tags/consommation/<rid>/reserve       (liaison figée)
    SIGNE        + refs/tags/consommation/<rid>/fin  {etat: SIGNE, document_sha256}
    ECHEC        + refs/tags/consommation/<rid>/fin  {etat: ECHEC, motif}

`reserve` et `fin` ne se créent qu'une fois chacune : deux réservations, deux
fins ou un retour à DISPONIBLE sont impossibles. Un RESERVE sans fin (exécution
interrompue) se diagnostique par `etat()` et se clôt explicitement en ECHEC par
`clore_en_echec` ; il ne redevient jamais disponible.
"""
import base64
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import revue  # noqa: E402

DISPONIBLE, RESERVE, SIGNE, ECHEC = "DISPONIBLE", "RESERVE", "SIGNE", "ECHEC"
PREFIXE = "refs/tags/consommation"


def _ref(request_id, feuille):
    if not isinstance(request_id, str) or len(request_id) != 32 or any(c not in "0123456789abcdef" for c in request_id):
        raise revue.Refus("request_id_invalide")
    return f"{PREFIXE}/{request_id}/{feuille}"


class RegistreConsommation:
    """Registre à création unique. `transport` : `creer_ref(nom, contenu) -> bool`
    (True si créée, False si elle existait) et `lire_ref(nom) -> bytes | None`."""

    def __init__(self, transport):
        if transport is None:
            raise revue.Refus("registre_absent")
        self._t = transport

    def _lire(self, rid, feuille):
        brut = self._t.lire_ref(_ref(rid, feuille))
        if brut is None:
            return None
        try:
            return revue.charger_json_strict(brut)
        except ValueError:
            raise revue.Refus("registre_illisible")

    def etat(self, rid):
        reserve, fin = self._lire(rid, "reserve"), self._lire(rid, "fin")
        if reserve is None:
            if fin is not None:
                raise revue.Refus("registre_incoherent")
            return DISPONIBLE, None
        if fin is None:
            return RESERVE, reserve
        if fin.get("etat") not in (SIGNE, ECHEC) or fin.get("liaison") != reserve.get("liaison"):
            raise revue.Refus("registre_incoherent")
        return fin["etat"], fin

    def reserver(self, rid, liaison):
        contenu = revue.canonique({"etat": RESERVE, "liaison": liaison})
        if not self._t.creer_ref(_ref(rid, "reserve"), contenu):
            raise revue.Refus("request_id_deja_reserve")

    def controler_reservation(self, rid, liaison):
        """La réservation lue maintenant est exactement celle posée, sans fin."""
        etat, detail = self.etat(rid)
        if etat != RESERVE or revue.canonique(detail.get("liaison")) != revue.canonique(liaison):
            raise revue.Refus("reservation_substituee")

    def _clore(self, rid, liaison, etat, **champs):
        contenu = revue.canonique({"etat": etat, "liaison": liaison, **champs})
        if not self._t.creer_ref(_ref(rid, "fin"), contenu):
            raise revue.Refus("request_id_deja_clos")

    def marquer_signe(self, rid, liaison, document_sha256):
        self._clore(rid, liaison, SIGNE, document_sha256=document_sha256)

    def marquer_echec(self, rid, liaison, motif):
        self._clore(rid, liaison, ECHEC, motif=motif)

    def clore_en_echec(self, rid, motif):
        """Clôture explicite d'une réservation orpheline (exécution interrompue)."""
        etat, detail = self.etat(rid)
        if etat != RESERVE:
            raise revue.Refus("rien_a_clore", etat)
        self.marquer_echec(rid, detail["liaison"], motif)


class TransportRefsGitHub:
    """Refs du dépôt de confiance via l'API Git Data. Chaque ref pointe vers un
    commit sans parent dont le message est le contenu JSON. `http(methode, url,
    corps) -> (statut, json)` ; défaut : urllib avec le jeton du job."""

    def __init__(self, api, depot, jeton, http=None):
        self._base = f"{api}/repos/{depot}"
        self._http = http or self._http_urllib(jeton)

    @staticmethod
    def _http_urllib(jeton):
        def http(methode, url, corps=None):
            req = urllib.request.Request(url, method=methode,
                                         data=None if corps is None else json.dumps(corps).encode(),
                                         headers={"Authorization": f"Bearer {jeton}",
                                                  "Accept": "application/vnd.github+json"})
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    return r.status, json.loads(r.read() or b"null")
            except urllib.error.HTTPError as e:
                return e.code, None
            except Exception as e:  # noqa: BLE001
                raise revue.Refus("registre_injoignable", type(e).__name__)
        return http

    def _appel(self, methode, chemin, corps=None, attendus=(200, 201)):
        statut, rep = self._http(methode, self._base + chemin, corps)
        if statut not in attendus:
            raise revue.Refus("registre_injoignable", f"{methode} {statut}")
        return statut, rep

    def creer_ref(self, nom, contenu):
        _, blob = self._appel("POST", "/git/blobs", {"content": base64.b64encode(contenu).decode(), "encoding": "base64"})
        _, arbre = self._appel("POST", "/git/trees", {"tree": [{"path": "etat.json", "mode": "100644", "type": "blob",
                                                                  "sha": blob["sha"]}]})
        _, commit = self._appel("POST", "/git/commits", {"message": contenu.decode("utf-8"), "tree": arbre["sha"],
                                                         "parents": []})
        statut, _ = self._appel("POST", "/git/refs", {"ref": nom, "sha": commit["sha"]}, attendus=(201, 422))
        if statut == 201:
            return True
        if self.lire_ref(nom) is None:  # 422 pour une autre raison qu'une ref existante
            raise revue.Refus("registre_injoignable", "422")
        return False

    def lire_ref(self, nom):
        statut, ref = self._appel("GET", "/git/ref/" + urllib.parse.quote(nom[len("refs/"):]), attendus=(200, 404))
        if statut == 404:
            return None
        if not isinstance(ref, dict) or ref.get("ref") != nom or (ref.get("object") or {}).get("type") != "commit":
            raise revue.Refus("registre_illisible")
        _, commit = self._appel("GET", f"/git/commits/{ref['object']['sha']}")
        return commit["message"].encode("utf-8")

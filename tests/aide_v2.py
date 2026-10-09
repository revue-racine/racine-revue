"""Outils communs des tests revue/2 : politique v2 ancrée de test, enveloppes
Responses fabriquées, serveur HTTP local (127.0.0.1) aux comportements
injectables. Aucun réseau externe, aucune clé réelle."""
import copy
import datetime
import http.client
import http.server
import json
import threading
import time

import aide
from aide import revue
import relecteur_openai
import revue2

MODELE = "gpt-6.1-sol"
# Clé factice : ne ressemble à aucun format de clé réel (contrôle test_bundle).
CLE = "cle-de-test-9f8e7d6c5b4a39281706f5e4d3c2b1a0"
SORTIE_FAVORABLE = b'{"verdict":"FAVORABLE","constats":[]}'


def politique_v2_ancree(acceptable=False, actif=True, modele=MODELE, **surcharges):
    pol = json.loads((aide.RACINE / "policy/confiance-v2.json").read_text("utf-8"))
    pol["racine"].update(proprietaire=aide.PROPRIETAIRE, proprietaire_id=aide.PROPRIETAIRE_ID,
                         depot=aide.DEPOT, depot_id=aide.DEPOT_ID)
    pol["demandeurs"] = [{"login": "operateur", "id": aide.DEMANDEUR_ID}]
    pol["depots"] = [{"alias": "auto-test", "repository_id": aide.DEPOT_ID},
                     {"alias": "candidat", "repository_id": aide.CANDIDAT_ID}]
    pol["relecteurs"] = [{"famille": "openai-responses", "actif": actif, "acceptable": acceptable,
                          "modeles": [modele]}]
    pol.update(surcharges)
    return pol


def confiance_v2(pol=None, **surcharges):
    pol = pol or politique_v2_ancree()
    e = revue2.empreintes_locales()
    conf = aide.confiance(type_predicat=revue2.TYPE_PREDICAT, politique_sha256=e["politique"],
                          protocole_sha256=e["protocole"], generation=pol["generation"])
    conf.update(surcharges)
    return conf


def sujet_v2_pour(candidat, pointe, pol=None):
    import tempfile
    from pathlib import Path
    pol = pol or politique_v2_ancree()
    with tempfile.TemporaryDirectory() as tmp:
        s, _ = revue2.calculer_sujet(aide.demande(pointe), pol, candidat.ancres(), str(candidat.chemin),
                                     Path(tmp) / "g", protocoles=("file",))
    return s


def predicat_v2(sujet, verdict="FAVORABLE", motif=None, rapport="0" * 64, pol=None, request_id=aide.RID,
                issue=7, instant=None):
    pol = pol or politique_v2_ancree()
    if verdict == "INDETERMINE" and motif is None:
        motif = "relecteur"
    instant = instant or revue.format_instant(aide.MAINTENANT - datetime.timedelta(minutes=5))
    return revue2.construire_predicat(copy.deepcopy(sujet), aide.admis(request_id, issue), pol,
                                      revue2.relecteur_actif(pol), verdict, motif, rapport, instant=instant)


def resultat_v2(pred, sujet=None, **kw):
    sujet = sujet if sujet is not None else pred["sujet"]
    kw.setdefault("nom", revue2.nom_sujet(sujet, pred["demande"]["request_id"]))
    kw.setdefault("type_predicat", revue2.TYPE_PREDICAT)
    return aide.resultat(pred, sujet=sujet, **kw)


def enveloppe(texte=SORTIE_FAVORABLE.decode(), modele=MODELE, status="completed", sortie=None, **surcharges):
    """Enveloppe Responses plausible ; flottants inclus (temperature, top_p),
    comme dans une vraie réponse."""
    if sortie is None:
        sortie = [{"type": "reasoning", "id": "rs_1", "summary": []},
                  {"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
                   "content": [{"type": "output_text", "text": texte, "annotations": []}]}]
    env = {"id": "resp_1", "object": "response", "created_at": 1791400000, "status": status,
           "error": None, "incomplete_details": None, "model": modele, "output": sortie,
           "temperature": 1.0, "top_p": 1.0, "store": False,
           "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}}
    env.update(surcharges)
    return json.dumps(env).encode()


# ------------------------------------------------------ serveur HTTP local

class ServeurLocal:
    """Serveur HTTP 127.0.0.1 à port éphémère. `mode` :
    ok | redirection | quota | client | serveur | goutte | gros | gzip | silence."""

    def __init__(self, mode="ok", corps=None, taille=0):
        self.mode, self.corps, self.taille = mode, corps if corps is not None else enveloppe(), taille
        self.requetes, self.connexions = [], 0
        self.verrou = threading.Lock()
        serveur = self

        class Gestionnaire(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                corps = self.rfile.read(n)
                with serveur.verrou:
                    serveur.connexions += 1
                    serveur.requetes.append((self.path, dict(self.headers), corps))
                serveur._repondre(self)

        class Serveur(http.server.ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass  # client qui ferme la connexion : attendu dans ces tests

        self._srv = Serveur(("127.0.0.1", 0), Gestionnaire)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        self._fil = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def _repondre(self, h):
        m = self.mode
        try:
            if m in ("redirection", "quota", "client", "serveur"):
                code = {"redirection": 302, "quota": 429, "client": 401, "serveur": 503}[m]
                h.send_response(code)
                if m == "redirection":
                    h.send_header("Location", "http://127.0.0.1:1/ailleurs")
                h.send_header("Content-Length", "0")
                h.end_headers()
                return
            if m == "silence":
                time.sleep(30)
                return
            corps = self.corps
            if m == "gros":
                corps = b"x" * self.taille
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            if m == "gzip":
                h.send_header("Content-Encoding", "gzip")
            h.send_header("Content-Length", str(len(corps) if m != "goutte" else 10 ** 6))
            h.end_headers()
            if m == "goutte":
                for _ in range(200):
                    h.wfile.write(b" ")
                    h.wfile.flush()
                    time.sleep(0.05)
                return
            h.wfile.write(corps)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def __enter__(self):
        self._fil.start()
        return self

    def __exit__(self, *a):
        self._srv.shutdown()
        self._srv.server_close()

    def connexion(self, timeout=5):
        return lambda: http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)


def relire_local(serveur, diff=b"diff --git a/x b/x\n", cle=CLE, modele=MODELE):
    return relecteur_openai.relire(cle, modele, diff, revue.schema("sortie-relecteur"), serveur.connexion())

"""Transport OpenRouter testé avec connexions simulées, sans socket ni réseau."""
import os
import ssl
import unittest
from unittest import mock

import aide  # noqa: F401
from aide import revue
import aide_openrouter as ao
import relecteur_openai as v2
import transport_openrouter as th


class FausseConnexion:
    def __init__(self, corps=b"{}", statut=200, entetes=None, sur_reponse=None, sur_lecture=None):
        self.corps = corps
        self.statut = statut
        self.entetes = entetes or {}
        self.sur_reponse = sur_reponse
        self.sur_lecture = sur_lecture
        self.requetes = []
        self.fermetures = 0
        self.lectures = 0

    def request(self, methode, chemin, body=None, headers=None):
        self.requetes.append((methode, chemin, body, headers))

    def getresponse(self):
        if self.sur_reponse:
            self.sur_reponse()
        return self

    @property
    def status(self):
        return self.statut

    def getheader(self, nom):
        return self.entetes.get(nom)

    def read(self, taille):
        self.lectures += 1
        if self.sur_lecture:
            action, self.sur_lecture = self.sur_lecture, None
            action()
        bloc, self.corps = self.corps[:taille], self.corps[taille:]
        return bloc

    def close(self):
        self.fermetures += 1


class TestTransportOpenRouter(unittest.TestCase):
    def appeler(self, conn, requete=None, **kwargs):
        return th.appeler(
            ao.CLE,
            requete or th.requete_inference(b"{}"),
            connexion=lambda: conn,
            **kwargs,
        )

    def motif(self, conn, requete=None, **kwargs):
        with self.assertRaises(revue.Refus) as cm:
            self.appeler(conn, requete, **kwargs)
        return cm.exception.motif

    def test_url_methode_et_endpoint_fermes(self):
        cas = (
            th.Requete("GET", th.CHEMIN_INFERENCE, None),
            th.Requete("POST", th.CHEMIN_BUDGET, b"{}"),
            th.Requete("POST", "/api/v1/responses", b"{}"),
            th.Requete("POST", "https://evil.invalid/", b"{}"),
        )
        for requete in cas:
            with self.assertRaises(revue.Refus) as cm:
                th.valider_requete(requete)
            self.assertIn(
                cm.exception.motif,
                {"openrouter_route_interdite", "openrouter_requete_invalide"},
            )

    def test_succes_post_porte_les_entetes_stricts(self):
        conn = FausseConnexion(b'{"ok":true}')
        reponse = self.appeler(conn)
        self.assertEqual(reponse.corps, b'{"ok":true}')
        self.assertEqual(len(conn.requetes), 1)
        methode, chemin, corps, entetes = conn.requetes[0]
        self.assertEqual((methode, chemin, corps), ("POST", th.CHEMIN_INFERENCE, b"{}"))
        self.assertEqual(entetes["X-OpenRouter-Metadata"], "enabled")
        self.assertEqual(entetes["X-OpenRouter-Cache"], "false")
        self.assertEqual(entetes["Accept-Encoding"], "identity")
        self.assertEqual(entetes["Authorization"], "Bearer " + ao.CLE)

    def test_budget_est_get_sans_corps(self):
        conn = FausseConnexion()
        self.appeler(conn, th.requete_budget())
        methode, chemin, corps, entetes = conn.requetes[0]
        self.assertEqual((methode, chemin, corps), ("GET", th.CHEMIN_BUDGET, None))
        self.assertNotIn("Content-Type", entetes)
        self.assertNotIn("X-OpenRouter-Metadata", entetes)

    def test_redirection_refusee_et_jamais_suivie(self):
        conn = FausseConnexion(statut=302, entetes={"Location": "https://evil.invalid"})
        self.assertEqual(self.motif(conn), "openrouter_redirection")
        self.assertEqual(len(conn.requetes), 1)

    def test_aucun_retry_apres_erreur(self):
        for statut, motif in (
            (400, "openrouter_http_client"),
            (429, "openrouter_quota"),
            (503, "openrouter_http_serveur"),
        ):
            conn = FausseConnexion(statut=statut)
            self.assertEqual(self.motif(conn), motif)
            self.assertEqual(len(conn.requetes), 1)

    def test_tls_verifie_et_proxy_ignore(self):
        captures = []

        class Capture:
            def __init__(self, hote, port, timeout, context):
                captures.append((hote, port, timeout, context))

            def set_tunnel(self, *_a, **_kw):
                raise AssertionError("aucun tunnel")

        environnement = dict(
            os.environ,
            HTTPS_PROXY="http://127.0.0.1:9",
            https_proxy="http://127.0.0.1:9",
            ALL_PROXY="http://127.0.0.1:9",
        )
        with mock.patch.dict(os.environ, environnement), mock.patch.object(
            th.http.client, "HTTPSConnection", Capture
        ):
            th.connexion_defaut()
        hote, port, timeout, contexte = captures[0]
        self.assertEqual((hote, port, timeout), ("openrouter.ai", 443, th.DELAI_SOCKET_S))
        self.assertEqual(contexte.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(contexte.check_hostname)
        self.assertGreaterEqual(contexte.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_encodage_taille_et_troncature_refuses(self):
        self.assertEqual(
            self.motif(FausseConnexion(b"x", entetes={"Content-Encoding": "gzip"})),
            "openrouter_encodage",
        )
        self.assertEqual(
            self.motif(FausseConnexion(b"x" * 11), taille_max=10),
            "openrouter_trop_grand",
        )
        self.assertEqual(
            self.motif(FausseConnexion(b"court", entetes={"Content-Length": "10"})),
            "openrouter_reponse_tronquee",
        )
        self.assertEqual(
            self.motif(FausseConnexion(b"x", entetes={"Content-Length": "invalide"})),
            "openrouter_entete_invalide",
        )

    def test_erreur_reseau_opaque(self):
        secret = ao.CLE

        def connexion():
            raise OSError("panne " + secret)

        with self.assertRaises(revue.Refus) as cm:
            th.appeler(secret, th.requete_budget(), connexion=connexion)
        self.assertEqual(cm.exception.motif, "openrouter_connexion")
        self.assertNotIn(secret, str(cm.exception) + repr(cm.exception.args))

    def test_timeout_mural_simule(self):
        def sonner():
            v2.signal.getsignal(v2.signal.SIGALRM)(v2.signal.SIGALRM, None)

        conn = FausseConnexion(b"encore", sur_lecture=sonner)
        self.assertEqual(self.motif(conn, delai_total=60), "openrouter_delai")
        self.assertEqual(conn.fermetures, 1)
        self.assertEqual(v2.signal.getitimer(v2.signal.ITIMER_REAL), (0.0, 0.0))

    def test_cle_absente_ou_dangereuse_refusee_avant_connexion(self):
        appels = []

        def connexion():
            appels.append(1)
            return FausseConnexion()

        for cle, motif in (("", "openrouter_cle_absente"), (ao.CLE + "\n", "openrouter_cle_invalide")):
            with self.assertRaises(revue.Refus) as cm:
                th.appeler(cle, th.requete_budget(), connexion=connexion)
            self.assertEqual(cm.exception.motif, motif)
        self.assertEqual(appels, [])

    def test_aucune_bibliotheque_de_proxy_redirection_ou_retry(self):
        texte = (ao.RACINE / "outils/transport_openrouter.py").read_text("utf-8")
        for interdit in ("urllib", "requests", "getproxies", "set_tunnel", "HTTPRedirectHandler"):
            self.assertNotIn(interdit, texte)
        self.assertNotIn("for tentative", texte.lower())


if __name__ == "__main__":
    unittest.main()

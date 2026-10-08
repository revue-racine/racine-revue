"""Récupération des bundles conforme à l'API actuelle : `bundle_url`, snappy
bloc, aucun bundle fourni par l'appelant, échec fermé partout."""
import json
import tempfile
import unittest
from unittest import mock

import aide
from aide import revue
import snappy_bloc
import verifier

DIGEST = "d" * 64
PREFIXE = f"https://api.github.com/repos/{aide.PROPRIETAIRE}/{aide.DEPOT}/attestations/"
BUNDLE = json.dumps({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "x": 1}).encode()
URL = "https://tmp-attestations.githubusercontent.com/b/1"
URL_AZURE = "https://tmaproduction.blob.core.windows.net/attestations/1409404929/bundle.json.sn"


def page(attestations, suivant=None):
    entetes = {"link": f'<{suivant}>; rel="next"'} if suivant else {}
    return 200, entetes, json.dumps({"attestations": attestations}).encode()


class Http:
    def __init__(self, reponses):
        self.reponses, self.vus = reponses, []

    def __call__(self, url, entetes):
        self.vus.append((url, entetes))
        r = self.reponses[url] if url in self.reponses else (404, {}, b"")
        if isinstance(r, Exception):
            raise r
        return (*r, url) if len(r) == 3 else r


class TestListe(unittest.TestCase):
    def lister(self, reponses):
        return verifier.lister_bundle_urls(aide.confiance(), DIGEST, Http(reponses))

    def motif(self, reponses):
        with self.assertRaises(revue.Refus) as cm:
            self.lister(reponses)
        return cm.exception.motif

    def test_bundle_url_valide_et_pagination(self):
        p1, p2 = f"{PREFIXE}sha256:{DIGEST}?per_page=100", f"{PREFIXE}sha256:{DIGEST}?after=abc"
        urls = self.lister({p1: page([{"bundle": None, "bundle_url": URL}], suivant=p2),
                            p2: page([{"bundle_url": URL + "2"}])})
        self.assertEqual(urls, [URL, URL + "2"])

    def test_bundle_url_azure_valide(self):
        p1 = f"{PREFIXE}sha256:{DIGEST}?per_page=100"
        self.assertEqual(
            self.lister({p1: page([{"bundle_url": URL_AZURE}])}),
            [URL_AZURE],
        )

    def test_aucune_attestation(self):
        self.assertEqual(self.lister({}), [])

    def test_bundle_url_absente_null_ou_vide(self):
        p1 = f"{PREFIXE}sha256:{DIGEST}?per_page=100"
        for a in ({}, {"bundle_url": None}, {"bundle_url": ""}, {"bundle": {"mediaType": "x"}}):
            self.assertEqual(self.motif({p1: page([a])}), "bundle_url_invalide", a)

    def test_bundle_url_inattendue(self):
        p1 = f"{PREFIXE}sha256:{DIGEST}?per_page=100"
        for u in ("http://tmp-attestations.githubusercontent.com/b/1", "https://exemple.invalid/b/1",
                  "https://githubusercontent.com.exemple.invalid/b",
                  "https://tmaproduction.blob.core.windows.net.exemple.invalid/b",
                  "https://u:p" + "@" + "api.github.com/b",
                  "https://api.github.com:8443/b", "file:///etc/passwd", 42):
            self.assertEqual(self.motif({p1: page([{"bundle_url": u}])}), "bundle_url_invalide", u)

    def test_pagination_hors_du_depot_ou_liste_illisible(self):
        p1 = f"{PREFIXE}sha256:{DIGEST}?per_page=100"
        self.assertEqual(self.motif({p1: page([], suivant="https://api.github.com/repos/intrus/x/attestations/y")}),
                         "liste_illisible")
        self.assertEqual(self.motif({p1: (200, {}, b"pas du json")}), "liste_illisible")
        self.assertEqual(self.motif({p1: (500, {}, b"")}), "liste_illisible")


class TestTelechargement(unittest.TestCase):
    def telecharger(self, reponse):
        return verifier.telecharger_bundle(URL, Http({URL: reponse}))

    def motif(self, reponse):
        with self.assertRaises(revue.Refus) as cm:
            self.telecharger(reponse)
        return cm.exception.motif

    def test_bundle_valide_sans_jeton(self):
        h = Http({URL: (200, {}, aide.snappy_litteral(BUNDLE))})
        self.assertEqual(verifier.telecharger_bundle(URL, h), BUNDLE)
        self.assertNotIn("Authorization", h.vus[0][1])

    def test_telechargement_en_echec(self):
        self.assertEqual(self.motif((500, {}, b"")), "telechargement_impossible")
        self.assertEqual(self.motif((404, {}, b"")), "telechargement_impossible")
        with self.assertRaises(revue.Refus):
            verifier.telecharger_bundle(URL, Http({URL: revue.Refus("telechargement_impossible")}))

    def test_redirection_vers_un_hote_inattendu(self):
        self.assertEqual(self.motif((200, {}, aide.snappy_litteral(BUNDLE), "https://exemple.invalid/x")),
                         "telechargement_impossible")

    def test_contenu_altere(self):
        cas = {
            "non compressé": BUNDLE,
            "snappy tronqué": aide.snappy_litteral(BUNDLE)[:-5],
            "longueur annoncée fausse": b"\x7f" + aide.snappy_litteral(BUNDLE)[1:],
            "pas un bundle": aide.snappy_litteral(b'{"mediaType":"text/plain"}'),
            "clé en double": aide.snappy_litteral(b'{"mediaType":"application/vnd.dev.sigstore.bundle+json","a":1,"a":2}'),
            "liste": aide.snappy_litteral(b"[]"),
            "décalage hors borne": bytes([9, 0x09, 0x03]),
        }
        for nom, corps in cas.items():
            self.assertEqual(self.motif((200, {}, corps)), "bundle_illisible", nom)

    def test_bundle_trop_grand(self):
        self.assertEqual(self.motif((200, {}, b"\x00" * (verifier.BUNDLE_COMPRESSE_MAX + 1))), "bundle_trop_grand")

    def test_snappy_vecteurs(self):
        self.assertEqual(snappy_bloc.decompresser(bytes([9, 0x08]) + b"abc" + bytes([0x09, 0x03]), 100), b"abcabcabc")
        with self.assertRaises(ValueError):
            snappy_bloc.decompresser(aide.snappy_litteral(b"x" * 100), 10)


class TestChaine(unittest.TestCase):
    """recuperer_resultats : liste → bundle_url → téléchargement → crypto."""

    @classmethod
    def setUpClass(cls):
        cls.cand = aide.DepotCandidat()
        cls.sujet = aide.sujet_pour(cls.cand, cls.cand.c3)

    @classmethod
    def tearDownClass(cls):
        cls.cand.nettoyer()

    def test_bout_en_bout_et_bundle_altere(self):
        gh = aide.FauxGitHub()
        gh.publier(aide.resultat(aide.predicat(self.sujet)))
        with mock.patch.object(verifier, "_verifier_crypto", gh.verifier_crypto), tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(len(verifier.recuperer_resultats(aide.confiance(), self.sujet, tmp, http=gh.http)), 1)
            faux = aide.predicat(self.sujet, issue=99)  # contenu différent, non signé par la racine
            gh.publier(aide.resultat(faux), signe=False)
            with self.assertRaises(revue.Refus) as cm:
                verifier.recuperer_resultats(aide.confiance(), self.sujet, tmp, http=gh.http)
            self.assertEqual(cm.exception.motif, "verification_cryptographique")


if __name__ == "__main__":
    unittest.main()

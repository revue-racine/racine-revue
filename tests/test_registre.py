"""Registre de consommation : création unique atomique, états explicites,
concurrence, rejeu, interruption et clôture explicite."""
import threading
import unittest

import aide
from aide import revue
import registre as R

RID = aide.RID
LIAISON = {"request_id": RID, "sujet_sha256": "0" * 64}


class TestRegistre(unittest.TestCase):
    def setUp(self):
        self.t = aide.TransportMemoire()
        self.r = R.RegistreConsommation(self.t)

    def motif(self, f, *a):
        with self.assertRaises(revue.Refus) as cm:
            f(*a)
        return cm.exception.motif

    def test_absence_de_registre(self):
        self.assertEqual(self.motif(R.RegistreConsommation, None), "registre_absent")

    def test_cycle_nominal(self):
        self.assertEqual(self.r.etat(RID), (R.DISPONIBLE, None))
        self.r.reserver(RID, LIAISON)
        self.assertEqual(self.r.etat(RID)[0], R.RESERVE)
        self.r.controler_reservation(RID, LIAISON)
        self.r.marquer_signe(RID, LIAISON, "1" * 64)
        etat, detail = self.r.etat(RID)
        self.assertEqual((etat, detail["document_sha256"]), (R.SIGNE, "1" * 64))

    def test_double_consommation(self):
        self.r.reserver(RID, LIAISON)
        self.assertEqual(self.motif(self.r.reserver, RID, LIAISON), "request_id_deja_reserve")

    def test_reserveurs_simultanes_une_seule_reussite(self):
        succes, barriere = [], threading.Barrier(32)

        def tenter(i):
            barriere.wait()
            try:
                self.r.reserver(RID, dict(LIAISON, essai=i))
                succes.append(i)
            except revue.Refus:
                pass
        fils = [threading.Thread(target=tenter, args=(i,)) for i in range(32)]
        [f.start() for f in fils]
        [f.join() for f in fils]
        self.assertEqual(len(succes), 1)

    def test_rejeu_apres_succes_et_apres_echec(self):
        self.r.reserver(RID, LIAISON)
        self.r.marquer_signe(RID, LIAISON, "1" * 64)
        self.assertEqual(self.motif(self.r.reserver, RID, LIAISON), "request_id_deja_reserve")
        self.assertEqual(self.motif(self.r.marquer_echec, RID, LIAISON, "x"), "request_id_deja_clos")
        autre = "e" * 32
        self.r.reserver(autre, LIAISON)
        self.r.marquer_echec(autre, LIAISON, "panne")
        self.assertEqual(self.r.etat(autre)[0], R.ECHEC)
        self.assertEqual(self.motif(self.r.marquer_signe, autre, LIAISON, "1" * 64), "request_id_deja_clos")

    def test_fin_unique_signe_ou_echec(self):
        self.r.reserver(RID, LIAISON)
        resultats = []

        def clore(f):
            try:
                f()
                resultats.append("ok")
            except revue.Refus:
                resultats.append("refus")
        fils = [threading.Thread(target=clore, args=(lambda: self.r.marquer_signe(RID, LIAISON, "1" * 64),)),
                threading.Thread(target=clore, args=(lambda: self.r.marquer_echec(RID, LIAISON, "x"),))]
        [f.start() for f in fils]
        [f.join() for f in fils]
        self.assertEqual(sorted(resultats), ["ok", "refus"])

    def test_interruption_puis_cloture_explicite(self):
        self.r.reserver(RID, LIAISON)
        etat, detail = self.r.etat(RID)
        self.assertEqual((etat, detail["liaison"]), (R.RESERVE, LIAISON))  # diagnostic
        self.r.clore_en_echec(RID, "interruption")
        self.assertEqual(self.r.etat(RID)[0], R.ECHEC)
        self.assertEqual(self.motif(self.r.reserver, RID, LIAISON), "request_id_deja_reserve")
        self.assertEqual(self.motif(self.r.clore_en_echec, RID, "x"), "rien_a_clore")

    def test_reservation_substituee(self):
        self.r.reserver(RID, LIAISON)
        self.assertEqual(self.motif(self.r.controler_reservation, RID, dict(LIAISON, sujet_sha256="1" * 64)),
                         "reservation_substituee")

    def test_etat_incoherent(self):
        self.t.refs[f"{R.PREFIXE}/{RID}/fin"] = b'{"etat":"SIGNE","liaison":{}}'
        self.assertEqual(self.motif(self.r.etat, RID), "registre_incoherent")

    def test_request_id_invalide(self):
        for rid in ("", "../x", "A" * 32, "0" * 31):
            self.assertEqual(self.motif(self.r.reserver, rid, LIAISON), "request_id_invalide")


class FauxApiGit:
    """API Git Data minimale : blobs, arbres, commits, refs (201 / 422 / 404)."""

    def __init__(self):
        self.objets, self.refs, self.n, self.verrou = {}, {}, 0, threading.Lock()
        self.statut_force = None

    def __call__(self, methode, url, corps=None):
        if self.statut_force:
            return self.statut_force, None
        chemin = url.split("/repos/proprio/racine", 1)[1]
        with self.verrou:
            if methode == "POST" and chemin in ("/git/blobs", "/git/trees", "/git/commits"):
                self.n += 1
                sha = f"{self.n:040x}"
                self.objets[sha] = corps
                return 201, {"sha": sha}
            if methode == "POST" and chemin == "/git/refs":
                if corps["ref"] in self.refs:
                    return 422, None
                self.refs[corps["ref"]] = corps["sha"]
                return 201, {"ref": corps["ref"]}
            if methode == "GET" and chemin.startswith("/git/ref/"):
                nom = "refs/" + chemin[len("/git/ref/"):]
                if nom not in self.refs:
                    return 404, None
                return 200, {"ref": nom, "object": {"type": "commit", "sha": self.refs[nom]}}
            if methode == "GET" and chemin.startswith("/git/commits/"):
                return 200, {"message": self.objets[chemin.rsplit("/", 1)[1]]["message"]}
        return 500, None


class TestTransportGitHub(unittest.TestCase):
    def setUp(self):
        self.api = FauxApiGit()
        self.r = R.RegistreConsommation(R.TransportRefsGitHub("https://api.github.com", "proprio/racine", "x",
                                                              http=self.api))

    def test_cycle_par_l_api(self):
        self.r.reserver(RID, LIAISON)
        self.assertIn(f"refs/tags/consommation/{RID}/reserve", self.api.refs)
        self.assertEqual(self.r.etat(RID)[0], R.RESERVE)
        with self.assertRaises(revue.Refus):
            self.r.reserver(RID, LIAISON)  # 422 + ref existante
        self.r.marquer_signe(RID, LIAISON, "1" * 64)
        self.assertEqual(self.r.etat(RID)[0], R.SIGNE)

    def test_erreurs_api_echec_ferme(self):
        self.api.statut_force = 500
        with self.assertRaises(revue.Refus) as cm:
            self.r.reserver(RID, LIAISON)
        self.assertEqual(cm.exception.motif, "registre_injoignable")
        with self.assertRaises(revue.Refus):
            self.r.etat(RID)

    def test_422_sans_ref_existante(self):
        api = self.api
        original = api.__call__

        class Api422(FauxApiGit):
            pass
        r = R.RegistreConsommation(R.TransportRefsGitHub(
            "https://api.github.com", "proprio/racine", "x",
            http=lambda m, u, c=None: (422, None) if u.endswith("/git/refs") else original(m, u, c)))
        with self.assertRaises(revue.Refus) as cm:
            r.reserver(RID, LIAISON)
        self.assertEqual(cm.exception.motif, "registre_injoignable")


if __name__ == "__main__":
    unittest.main()

"""Job de signature : rien n'est signé sans recalcul indépendant."""
import datetime
import unittest

import aide
from aide import revue


class TestPreparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cand = aide.DepotCandidat()
        cls.sujet = aide.sujet_pour(cls.cand, cls.cand.c3)
        cls.pol = aide.politique_ancree()

    @classmethod
    def tearDownClass(cls):
        cls.cand.nettoyer()

    def maintenant(self, **kw):
        return revue.format_instant(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(**kw))

    def pred(self, **kw):
        kw.setdefault("instant", self.maintenant(seconds=10))
        return aide.predicat(self.sujet, **kw)

    def preparer(self, pred, sujet=None, admis=None, pol=None):
        return revue.preparer_signature(revue.canonique(pred), admis or aide.admis(), sujet or self.sujet,
                                        pol or self.pol)

    def refus(self, pred, **kw):
        with self.assertRaises(revue.Refus) as cm:
            self.preparer(pred, **kw)
        return cm.exception.motif

    def test_predicat_conforme_et_nom_de_sujet(self):
        prep = self.preparer(self.pred())
        self.assertEqual(prep["sujet_digest"], revue.sha256_hex(revue.canonique(self.sujet)))
        self.assertEqual(prep["sujet_nom"], f"olistic-revue:candidat@{self.cand.c3}#{aide.RID}")

    def test_mauvais_commit(self):
        autre = aide.sujet_pour(self.cand, self.cand.c2)
        self.assertEqual(self.refus(aide.predicat(autre, instant=self.maintenant(seconds=10))), "sujet_divergent")

    def test_champs_du_sujet_alteres(self):
        for chemin in (("pointe", "arbre"), ("pointe", "arbre_sha256"), ("pointe", "objet_sha256"),
                       ("base", "commit"), ("base", "objet_sha256")):
            p = self.pred()
            p["sujet"][chemin[0]][chemin[1]] = ("0" * 40) if chemin[1] in ("arbre", "commit") else ("0" * 64)
            self.assertEqual(self.refus(p), "sujet_divergent", chemin)
        p = self.pred()
        p["sujet"]["perimetre_sha256"] = "0" * 64
        self.assertEqual(self.refus(p), "sujet_divergent")
        p = self.pred()
        p["sujet"]["depot"]["repository_id"] = 1
        self.assertEqual(self.refus(p), "sujet_divergent")

    def test_verdict_hors_enumeration(self):
        for v in ("APPROUVE", "favorable", "FAVORABLE_AVEC_CORRECTIONS", None, True):
            p = self.pred()
            p["verdict"] = v
            self.assertEqual(self.refus(p), "predicat_invalide", v)

    def test_champ_ajoute(self):
        p = self.pred()
        p["approbation"] = "approbateur"
        self.assertEqual(self.refus(p), "predicat_invalide")

    def test_invariants_motif(self):
        p = self.pred(verdict="INDETERMINE")
        p["motif"] = None
        self.assertEqual(self.refus(p), "predicat_invalide")
        p = self.pred()
        p["motif"] = "relecteur"
        self.assertEqual(self.refus(p), "predicat_invalide")

    def test_factice_favorable_refuse(self):
        p = self.pred()
        p["relecteur"] = {"famille": "factice", "modele": None}
        self.assertEqual(self.refus(p), "predicat_invalide")

    def test_relecteur_inactif_ou_modele_non_autorise(self):
        self.assertEqual(self.refus(self.pred(), pol=aide.politique_ancree(actif=False, acceptable=False)),
                         "predicat_invalide")
        p = self.pred()
        p["relecteur"]["modele"] = "autre-modele"
        self.assertEqual(self.refus(p), "predicat_invalide")

    def test_generation_differente(self):
        p = self.pred()
        p["politique"]["generation"] = 2
        self.assertEqual(self.refus(p), "predicat_invalide")

    def test_empreintes_divergentes(self):
        for cle in ("protocole", "politique"):
            p = self.pred()
            p[cle]["sha256"] = "0" * 64
            self.assertEqual(self.refus(p), "empreintes_divergentes", cle)
        p = self.pred()
        p["ancres_sha256"] = "0" * 64
        self.assertEqual(self.refus(p), "empreintes_divergentes")

    def test_demande_divergente(self):
        for admis in (aide.admis(issue=8), aide.admis(request_id="f" * 32), aide.admis(classe="B"),
                      aide.admis(auteur="codex")):
            self.assertEqual(self.refus(self.pred(), admis=admis), "demande_divergente")

    def test_instant_incoherent(self):
        for instant in (self.maintenant(hours=2), self.maintenant(seconds=-120), "2026-10-07T00:00:00+02:00"):
            p = self.pred()
            p["instant"] = instant
            self.assertIn(self.refus(p), ("instant_incoherent", "predicat_invalide"), instant)

    def test_predicat_illisible(self):
        with self.assertRaises(revue.Refus):
            revue.preparer_signature(b'{"format":1,"format":2}', aide.admis(), self.sujet, self.pol)


if __name__ == "__main__":
    unittest.main()

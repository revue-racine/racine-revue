"""Prédicat v2 : produit sous acceptable:false, invariants, recalcul
indépendant au job de signature."""
import datetime
import unittest

import aide
from aide import revue
import aide_v2
import revue2


class TestPredicatV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cand = aide.DepotCandidat()
        cls.sujet = aide_v2.sujet_v2_pour(cls.cand, cls.cand.c3)
        cls.pol = aide_v2.politique_v2_ancree()

    @classmethod
    def tearDownClass(cls):
        cls.cand.nettoyer()

    def maintenant(self, **kw):
        return revue.format_instant(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(**kw))

    def pred(self, **kw):
        kw.setdefault("instant", self.maintenant(seconds=10))
        return aide_v2.predicat_v2(self.sujet, **kw)

    def refus(self, pred, pol=None, sujet=None, admis=None):
        with self.assertRaises(revue2.Refus) as cm:
            revue2.preparer_signature(revue.canonique(pred), admis or aide.admis(), sujet or self.sujet, pol or self.pol)
        return cm.exception.motif

    def test_produit_sous_acceptable_false_pour_chaque_verdict(self):
        for verdict, motif in (("FAVORABLE", None), ("DEFAVORABLE", None), ("INDETERMINE", "relecteur"),
                               ("INDETERMINE", "sortie_invalide")):
            p = self.pred(verdict=verdict, motif=motif)
            self.assertEqual(p["relecteur"], {"famille": "openai-responses", "modele": "gpt-6.1-sol",
                                              "acceptable": False})
            self.assertEqual(p["format"], "olistic.confiance.attestation-revue/2")
            self.assertEqual(p["protocole"]["version"], "revue/2")
            self.assertEqual(p["politique"]["generation"], 2)
            prep = revue2.preparer_signature(revue.canonique(p), aide.admis(), self.sujet, self.pol)
            self.assertEqual(prep["verdict"], verdict)

    def test_sujet_et_nom_v2(self):
        self.assertEqual(self.sujet["format"], "olistic.confiance.sujet-revue/2")
        prep = revue2.preparer_signature(revue.canonique(self.pred()), aide.admis(), self.sujet, self.pol)
        self.assertEqual(prep["sujet_nom"], f"olistic-revue2:candidat@{self.cand.c3}#{aide.RID}")
        self.assertEqual(prep["sujet_digest"], revue.sha256_hex(revue.canonique(self.sujet)))

    def test_acceptable_falsifie_refuse(self):
        p = self.pred()
        p["relecteur"]["acceptable"] = True
        self.assertEqual(self.refus(p), "predicat_invalide")

    def test_famille_ou_modele_hors_politique(self):
        for rel in ({"famille": "codex", "modele": "gpt-6.1-sol", "acceptable": False},
                    {"famille": "factice", "modele": "gpt-6.1-sol", "acceptable": False},
                    {"famille": "openai-responses", "modele": "autre", "acceptable": False},
                    {"famille": "openai-responses", "modele": None, "acceptable": False}):
            p = self.pred()
            p["relecteur"] = rel
            self.assertEqual(self.refus(p), "predicat_invalide", rel)

    def test_motifs_v1_hors_enumeration_v2(self):
        for motif in ("relecteur_factice", "delai_depasse", "erreur_relecteur"):
            p = self.pred(verdict="INDETERMINE", motif=None)
            p["motif"] = motif
            self.assertEqual(self.refus(p), "predicat_invalide", motif)

    def test_rapport_exige_sauf_sans_relecture(self):
        p = self.pred()
        p["rapport_sha256"] = None
        self.assertEqual(self.refus(p), "predicat_invalide")
        with self.assertRaises(revue2.Refus):
            aide_v2.predicat_v2(self.sujet, verdict="INDETERMINE", motif="diff_trop_grand", rapport="0" * 64)
        aide_v2.predicat_v2(self.sujet, verdict="INDETERMINE", motif="diff_trop_grand", rapport=None)

    def test_predicat_v1_refuse_par_le_v2(self):
        v1 = aide.predicat(aide.sujet_pour(self.cand, self.cand.c3), instant=self.maintenant(seconds=10))
        self.assertEqual(self.refus(v1), "predicat_invalide")

    def test_sujet_v1_diverge(self):
        sujet_v1 = aide.sujet_pour(self.cand, self.cand.c3)
        self.assertNotEqual(revue.canonique(sujet_v1), revue.canonique(self.sujet))
        self.assertEqual(self.refus(self.pred(), sujet=sujet_v1), "sujet_divergent")

    def test_empreintes_et_generation(self):
        for cle in ("protocole", "politique"):
            p = self.pred()
            p[cle]["sha256"] = "0" * 64
            self.assertEqual(self.refus(p), "empreintes_divergentes", cle)
        p = self.pred()
        p["politique"]["generation"] = 3
        self.assertEqual(self.refus(p), "predicat_invalide")

    def test_empreintes_locales_v2_distinctes_du_v1(self):
        e1, e2 = revue.empreintes_locales(), revue2.empreintes_locales()
        self.assertNotEqual(e1["protocole"], e2["protocole"])
        self.assertNotEqual(e1["politique"], e2["politique"])
        self.assertEqual(e1["ancres"], e2["ancres"])

    def test_demande_divergente_et_instant(self):
        self.assertEqual(self.refus(self.pred(), admis=aide.admis(issue=8)), "demande_divergente")
        self.assertIn(self.refus(self.pred(instant=self.maintenant(hours=2))), ("instant_incoherent",))


if __name__ == "__main__":
    unittest.main()

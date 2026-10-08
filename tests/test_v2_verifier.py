"""Vérificateur candidat v2 : rejet déterministe `relecteur_non_acceptable`
sous la génération 2, quel que soit le verdict ; séparation stricte v1 / v2."""
import json
import tempfile
import unittest
from pathlib import Path

import aide
from aide import revue
import aide_v2
import revue2
import verifier
import verifier2

T = aide.MAINTENANT


class TestVerifierV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cand = aide.DepotCandidat()
        cls.sujet = aide_v2.sujet_v2_pour(cls.cand, cls.cand.c3)
        cls.sujet_v1 = aide.sujet_pour(cls.cand, cls.cand.c3)

    @classmethod
    def tearDownClass(cls):
        cls.cand.nettoyer()

    def evaluer(self, resultats, pol=None, conf=None, sujet=None):
        pol = pol or aide_v2.politique_v2_ancree()
        return verifier2.evaluer(resultats, sujet or self.sujet, aide.RID, conf or aide_v2.confiance_v2(pol), pol, T)

    def bon(self, pol=None, **kw):
        return aide_v2.resultat_v2(aide_v2.predicat_v2(self.sujet, pol=pol, **kw))

    def test_generation_2_rejet_deterministe_quel_que_soit_le_verdict(self):
        for verdict, motif in (("FAVORABLE", None), ("DEFAVORABLE", None), ("INDETERMINE", "relecteur"),
                               ("INDETERMINE", "sortie_invalide"), ("INDETERMINE", "diff_trop_grand")):
            rapport = None if motif == "diff_trop_grand" else "0" * 64
            d = self.evaluer([self.bon(verdict=verdict, motif=motif, rapport=rapport)])
            self.assertFalse(d.acceptee)
            self.assertEqual(d["motif"], "relecteur_non_acceptable", verdict)

    def test_refus_independant_de_la_fraicheur(self):
        """`relecteur_non_acceptable` précède la fraîcheur : même périmée ou
        antérieure à la coupure, l'attestation est rejetée pour ce motif."""
        r = self.bon()
        r["verificationResult"]["verifiedTimestamps"] = [{"timestamp": "2020-01-01T00:00:00Z"}]
        self.assertEqual(self.evaluer([r])["motif"], "relecteur_non_acceptable")

    def test_acceptable_ne_vient_jamais_du_predicat(self):
        r = self.bon()
        r["verificationResult"]["statement"]["predicate"]["relecteur"]["acceptable"] = True
        self.assertEqual(self.evaluer([r])["motif"], "acceptable_divergent")

    def test_promotion_ulterieure_ne_lave_pas_une_attestation_de_generation_2(self):
        """Une politique où le relecteur devient acceptable a une autre empreinte :
        l'attestation produite sous la génération 2 reste rejetée."""
        ancienne = self.bon()
        promue = aide_v2.politique_v2_ancree(acceptable=True, generation=3)
        conf = aide_v2.confiance_v2(promue, politique_sha256="1" * 64, generation=3)
        self.assertEqual(self.evaluer([ancienne], pol=promue, conf=conf)["motif"], "politique_differente")

    def test_mecanique_d_acceptation_intacte_si_acceptable(self):
        """Contrôle de non-régression de l'agrégation : sous une politique de
        TEST acceptable (jamais livrée), une FAVORABLE valide serait acceptée."""
        pol = aide_v2.politique_v2_ancree(acceptable=True)
        d = self.evaluer([self.bon(pol=pol)], pol=pol)
        self.assertTrue(d.acceptee, d)
        d = self.evaluer([self.bon(pol=pol), self.bon(pol=pol, verdict="DEFAVORABLE", request_id="f" * 32)], pol=pol)
        self.assertEqual(d["motif"], "defavorable_sur_le_meme_sujet")

    def test_provenance_toujours_controlee_d_abord(self):
        cert = aide.certificat_conforme(commit="b" * 40)
        r = aide_v2.resultat_v2(aide_v2.predicat_v2(self.sujet), cert=cert)
        self.assertEqual(self.evaluer([r])["motif"], "certificat:commit_workflow_non_epingle")

    def test_attestation_v1_rejetee_par_le_v2(self):
        r = aide.resultat(aide.predicat(self.sujet_v1))
        self.assertEqual(self.evaluer([r])["motif"], "type_predicat")
        r = aide.resultat(aide.predicat(self.sujet_v1), type_predicat=revue2.TYPE_PREDICAT, sujet=self.sujet_v1)
        self.assertEqual(self.evaluer([r])["motif"], "predicat_invalide")

    def test_attestation_v2_rejetee_par_le_v1_souverain(self):
        """Le vérificateur v1 inchangé, avec sa configuration v1, ne reconnaît
        jamais une attestation v2."""
        r = self.bon()
        d = verifier.evaluer([r], self.sujet, aide.RID, aide.confiance(), aide.politique_ancree(), T)
        self.assertEqual(d["motif"], "type_predicat")
        d = verifier.evaluer([r], self.sujet_v1, aide.RID, aide.confiance(), aide.politique_ancree(), T)
        self.assertFalse(d.acceptee)

    def test_digests_v1_et_v2_disjoints(self):
        self.assertNotEqual(revue.sha256_hex(revue.canonique(self.sujet)),
                            revue.sha256_hex(revue.canonique(self.sujet_v1)))

    def test_nom_de_sujet_v1_refuse(self):
        r = self.bon()
        r["verificationResult"]["statement"]["subject"][0]["name"] = revue.nom_sujet(self.sujet, aide.RID)
        self.assertEqual(self.evaluer([r])["motif"], "nom_sujet")

    def ecrire(self, obj, octets=None):
        f = Path(tempfile.mkdtemp()) / "x.json"
        f.write_bytes(octets if octets is not None else json.dumps(obj).encode())
        return f

    def test_configuration_candidate(self):
        pol_octets = (aide.RACINE / "policy/confiance-v2.json").read_bytes()
        pol = json.loads(pol_octets)
        conf = {**aide_v2.confiance_v2(pol), "proprietaire": pol["racine"]["proprietaire"],
                "proprietaire_id": pol["racine"]["proprietaire_id"], "depot": pol["racine"]["depot"],
                "depot_id": pol["racine"]["depot_id"], "politique_sha256": revue.sha256_hex(pol_octets)}
        c, p = verifier2.charger_confiance(self.ecrire(conf), aide.RACINE / "policy/confiance-v2.json")
        self.assertEqual(p["generation"], 2)
        for alteration, motif in (({"type_predicat": "urn:olistic:confiance:attestation-revue:1"}, "confiance_invalide"),
                                  ({"politique_sha256": "0" * 64}, "politique_non_epinglee"),
                                  ({"generation": 1}, "generation_divergente")):
            with self.assertRaises(revue.Refus) as cm:
                verifier2.charger_confiance(self.ecrire({**conf, **alteration}), aide.RACINE / "policy/confiance-v2.json")
            self.assertEqual(cm.exception.motif, motif)
        with self.assertRaises(revue.Refus):
            verifier2.charger_confiance(self.ecrire(conf), aide.RACINE / "policy/confiance-v1.json")


if __name__ == "__main__":
    unittest.main()

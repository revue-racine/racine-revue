"""Politique et ancres : livrées conformes, refusées tant qu'elles ne sont pas ancrées."""
import json
import tempfile
import unittest
from pathlib import Path

import aide
from aide import revue


class TestPolitique(unittest.TestCase):
    def ecrire(self, obj):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(obj, f)
        f.close()
        self.addCleanup(Path(f.name).unlink)
        return f.name

    def refus(self, pol, finale=True):
        with self.assertRaises(revue.Refus) as cm:
            revue.charger_politique(self.ecrire(pol), finale=finale)
        return cm.exception.motif

    def test_livree_conforme(self):
        # Vrai avant comme après l'ancrage : l'état ancré de la politique livrée
        # est exigé par l'étape `politique --finale` de controles.yml.
        revue.charger_ancres(revue.charger_politique())

    def test_non_ancree_refusee_en_finale(self):
        for champ in ("proprietaire", "proprietaire_id", "depot", "depot_id"):
            with self.subTest(champ=champ):
                pol = aide.politique_ancree()
                pol["racine"][champ] = None
                self.assertEqual(self.refus(pol), "politique_non_ancree")
        self.assertEqual(self.refus(aide.politique_ancree(demandeurs=[])), "politique_non_ancree")
        pol = aide.politique_ancree()
        pol["depots"][1]["repository_id"] = None
        self.assertEqual(self.refus(pol), "politique_non_ancree")

    def test_ancree_acceptee(self):
        revue.charger_politique(self.ecrire(aide.politique_ancree()), finale=True)

    def test_lot1_factice_seul_actif_et_non_acceptable(self):
        pol = revue.charger_politique()
        self.assertEqual(pol["relecteurs"], [{"famille": "factice", "actif": True, "acceptable": False, "modeles": [None]}])
        self.assertEqual(revue.relecteur_actif(pol)["famille"], "factice")

    def test_factice_acceptable_refuse(self):
        pol = aide.politique_ancree(codex=False)
        pol["relecteurs"][0]["acceptable"] = True
        self.assertEqual(self.refus(pol), "politique_invalide")

    def test_acceptable_mais_inactif_refuse(self):
        self.assertEqual(self.refus(aide.politique_ancree(actif=False, acceptable=True)), "politique_invalide")

    def test_coupure_illisible(self):
        pol = aide.politique_ancree()
        pol["fraicheur"]["coupure"] = "2026-13-45T00:00:00Z"
        self.assertEqual(self.refus(pol), "politique_invalide")

    def test_auto_test_doit_designer_la_racine(self):
        pol = aide.politique_ancree()
        pol["depots"][0]["repository_id"] = 1
        self.assertEqual(self.refus(pol), "politique_invalide")

    def test_alias_ou_famille_en_double(self):
        pol = aide.politique_ancree()
        pol["depots"].append({"alias": "candidat", "repository_id": 5})
        self.assertEqual(self.refus(pol, finale=False), "politique_invalide")

    def test_ancres_couvrent_exactement_les_depots(self):
        pol = aide.politique_ancree()
        for ancres in ([{"alias": "auto-test", "commit": None, "objet_sha256": None}],
                       [{"alias": "auto-test", "commit": "a" * 40, "objet_sha256": None},
                        {"alias": "candidat", "commit": None, "objet_sha256": None}]):
            with self.assertRaises(revue.Refus):
                revue.charger_ancres(pol, self.ecrire({"format": "olistic.confiance.ancres/1", "ancres": ancres}))


if __name__ == "__main__":
    unittest.main()

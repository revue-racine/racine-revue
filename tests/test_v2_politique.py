"""Politique v2 : génération 2, relecteur `openai-responses` non acceptable,
aucun relecteur factice, distincte de la politique v1 qui reste figée."""
import json
import tempfile
import unittest
from pathlib import Path

import aide
import aide_v2
import revue2


class TestPolitiqueV2(unittest.TestCase):
    def ecrire(self, obj):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(obj, f)
        f.close()
        self.addCleanup(Path(f.name).unlink)
        return f.name

    def refus(self, pol, finale=True):
        with self.assertRaises(revue2.Refus) as cm:
            revue2.charger_politique(self.ecrire(pol), finale=finale)
        return cm.exception.motif

    def test_livree_conforme_ancree_et_non_autorisante(self):
        pol = revue2.charger_politique(finale=True)
        revue2.charger_ancres(pol)
        self.assertEqual(pol["format"], "olistic.confiance.politique/2")
        self.assertEqual(pol["generation"], 2)
        self.assertEqual(pol["type_predicat"], "urn:olistic:confiance:attestation-revue:2")
        self.assertEqual(pol["relecteurs"], [{"famille": "openai-responses", "actif": True, "acceptable": False,
                                              "modeles": ["gpt-6.1-sol"]}])

    def test_identite_et_demandeurs_identiques_au_v1(self):
        v1 = json.loads((aide.RACINE / "policy/confiance-v1.json").read_text("utf-8"))
        v2 = revue2.charger_politique()
        for cle in ("racine", "demandeurs", "depots", "limites"):
            self.assertEqual(v2[cle], v1[cle], cle)

    def test_factice_ou_codex_refuse_en_v2(self):
        for famille in ("factice", "codex"):
            pol = aide_v2.politique_v2_ancree()
            pol["relecteurs"][0]["famille"] = famille
            self.assertEqual(self.refus(pol), "politique_invalide", famille)

    def test_modele_nul_refuse(self):
        pol = aide_v2.politique_v2_ancree()
        pol["relecteurs"][0]["modeles"] = [None]
        self.assertEqual(self.refus(pol), "politique_invalide")

    def test_generation_1_ou_type_v1_refuses(self):
        self.assertEqual(self.refus(aide_v2.politique_v2_ancree(generation=1)), "politique_invalide")
        self.assertEqual(self.refus(aide_v2.politique_v2_ancree(type_predicat="urn:olistic:confiance:attestation-revue:1")),
                         "politique_invalide")
        self.assertEqual(self.refus(aide_v2.politique_v2_ancree(format="olistic.confiance.politique/1")),
                         "politique_invalide")

    def test_politique_v1_refusee_par_le_chargeur_v2(self):
        with self.assertRaises(revue2.Refus):
            revue2.charger_politique(aide.RACINE / "policy/confiance-v1.json")

    def test_acceptable_mais_inactif_refuse(self):
        self.assertEqual(self.refus(aide_v2.politique_v2_ancree(acceptable=True, actif=False)), "politique_invalide")

    def test_exactement_un_relecteur_actif(self):
        with self.assertRaises(revue2.Refus):
            revue2.relecteur_actif(aide_v2.politique_v2_ancree(actif=False))

    def test_non_ancree_refusee(self):
        pol = aide_v2.politique_v2_ancree()
        pol["racine"]["depot_id"] = None
        self.assertEqual(self.refus(pol), "politique_non_ancree")
        self.assertEqual(self.refus(aide_v2.politique_v2_ancree(demandeurs=[])), "politique_non_ancree")

    def test_auto_test_doit_designer_la_racine(self):
        pol = aide_v2.politique_v2_ancree()
        pol["depots"][0]["repository_id"] = 1
        self.assertEqual(self.refus(pol), "politique_invalide")


if __name__ == "__main__":
    unittest.main()

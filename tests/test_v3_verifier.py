"""Vérificateur v3 : cohérence synthétique, refus causaux, aucune crypto."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import aide
from aide import revue
import aide_v3
import revue3
import verifier3


class TestVerifierV3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidat = aide.DepotCandidat()
        cls.politique = aide_v3.politique_v3_ancree()
        cls.sujet = aide_v3.sujet_v3_pour(cls.candidat, cls.candidat.c3, cls.politique)

    @classmethod
    def tearDownClass(cls):
        cls.candidat.nettoyer()

    def predicat(self, **kwargs):
        return aide_v3.predicat_v3(self.sujet, self.politique, **kwargs)

    def verifier(self, predicat, sujet=None):
        return verifier3.verifier_synthetique(predicat, sujet or self.sujet, self.politique)

    def ecrire(self, objet):
        fichier = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(objet, fichier)
        fichier.close()
        self.addCleanup(Path(fichier.name).unlink)
        return fichier.name

    def test_favorable_verifie_reste_non_autorisant(self):
        decision = self.verifier(self.predicat(verdict="FAVORABLE"))
        self.assertTrue(decision.verifiee)
        self.assertFalse(decision.autorisante)
        self.assertEqual(decision.nature, "synthetique-hors-ligne")
        self.assertEqual(decision.motif, "politique_dormante")
        self.assertEqual(decision.verdict, "FAVORABLE")

    def test_sujet_embarque_divergent_refuse(self):
        predicat = self.predicat()
        predicat["sujet"]["perimetre_sha256"] = "1" * 64
        decision = self.verifier(predicat)
        self.assertFalse(decision.verifiee)
        self.assertEqual(decision.motif, "sujet_divergent")

    def test_sujet_attendu_divergent_refuse(self):
        attendu = copy.deepcopy(self.sujet)
        attendu["pointe"]["arbre_sha256"] = "2" * 64
        decision = self.verifier(self.predicat(), attendu)
        self.assertFalse(decision.verifiee)
        self.assertEqual(decision.motif, "sujet_divergent")

    def test_empreintes_incoherentes_refusees(self):
        for chemin in (("protocole", "sha256"), ("politique", "sha256"), (None, "ancres_sha256")):
            predicat = self.predicat()
            if chemin[0] is None:
                predicat[chemin[1]] = "3" * 64
            else:
                predicat[chemin[0]][chemin[1]] = "3" * 64
            decision = self.verifier(predicat)
            self.assertFalse(decision.verifiee, chemin)
            self.assertEqual(decision.motif, "empreintes_divergentes", chemin)

    def test_politique_substituee_refusee_en_appel_de_fonction(self):
        politique_substituee = copy.deepcopy(self.politique)
        politique_substituee["limites"]["diff_octets"] -= 1

        decision = verifier3.verifier_synthetique(
            self.predicat(), self.sujet, politique_substituee
        )
        self.assertFalse(decision.verifiee)
        self.assertEqual(decision.motif, "politique_non_epinglee")

        with self.assertRaises(revue.Refus) as cm:
            revue3.selectionner_famille("codex", politique_substituee)
        self.assertEqual(cm.exception.motif, "politique_non_epinglee")

        with self.assertRaises(revue.Refus) as cm:
            aide_v3.predicat_v3(self.sujet, politique_substituee)
        self.assertEqual(cm.exception.motif, "politique_non_epinglee")

    def test_politique_substituee_refusee_par_cli(self):
        politique_substituee = copy.deepcopy(self.politique)
        politique_substituee["limites"]["diff_octets"] -= 1
        resultat = subprocess.run(
            [sys.executable, "-I", str(aide.RACINE / "outils/verifier3.py"),
             "--predicat", self.ecrire(self.predicat()),
             "--sujet", self.ecrire(self.sujet),
             "--politique", self.ecrire(politique_substituee)],
            cwd=aide.RACINE,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(resultat.returncode, 1)
        decision = json.loads(resultat.stdout)
        self.assertFalse(decision["verifiee"])
        self.assertFalse(decision["autorisante"])
        self.assertEqual(decision["motif"], "politique_non_epinglee")

    def test_famille_divergente_ou_identique_refusee(self):
        predicat = self.predicat()
        predicat["relecteur"]["famille"] = "gpt-codex-family"
        decision = self.verifier(predicat)
        self.assertFalse(decision.verifiee)
        self.assertEqual(decision.motif, "famille_relecture_divergente")

        predicat = self.predicat()
        predicat["demande"]["declaration_p1"]["auteur"] = "claude"
        decision = self.verifier(predicat)
        self.assertFalse(decision.verifiee)
        self.assertEqual(decision.motif, "famille_relecture_indisponible")

    def test_marqueurs_crypto_et_autorisation_refuses(self):
        mutations = (
            ("verification", "cryptographie_effective", True),
            ("verification", "signature_effective", True),
            ("verification", "provenance_effective", True),
            (None, "autorisation", True),
        )
        for bloc, cle, valeur in mutations:
            predicat = self.predicat()
            if bloc is None:
                predicat[cle] = valeur
            else:
                predicat[bloc][cle] = valeur
            decision = self.verifier(predicat)
            self.assertFalse(decision.verifiee, cle)
            self.assertEqual(decision.motif, "attestation_invalide", cle)

    def test_liste_des_controles_reportes_est_exacte(self):
        predicat = self.predicat()
        predicat["verification"]["controles_reportes"].reverse()
        decision = self.verifier(predicat)
        self.assertFalse(decision.verifiee)
        self.assertEqual(decision.motif, "attestation_invalide")

    def test_attestation_mal_formee_refusee(self):
        for mutation in (
            lambda p: p.update({"inconnu": 1}),
            lambda p: p.pop("sujet"),
            lambda p: p.update({"rapport_sha256": "x"}),
            lambda p: p.update({"motif": "synthetique"}),
        ):
            predicat = self.predicat()
            mutation(predicat)
            self.assertFalse(self.verifier(predicat).verifiee)

    def test_verification_cryptographique_est_explicitement_absente(self):
        with self.assertRaises(revue.Refus) as cm:
            verifier3.verifier_cryptographique(self.predicat())
        self.assertEqual(cm.exception.motif, "verification_cryptographique_non_implementee")


if __name__ == "__main__":
    unittest.main()

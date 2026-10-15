"""Contrat revue/3 : espace distinct, politique dormante et sélection fermée."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema

import aide
from aide import revue
import aide_v3
import revue3
import schema_strict


class TestContratV3(unittest.TestCase):
    def ecrire(self, objet):
        fichier = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(objet, fichier)
        fichier.close()
        self.addCleanup(Path(fichier.name).unlink)
        return fichier.name

    def ecrire_octets(self, octets):
        fichier = tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False)
        fichier.write(octets)
        fichier.close()
        self.addCleanup(Path(fichier.name).unlink)
        return fichier.name

    def refus_politique(self, politique):
        with self.assertRaises(revue3.Refus) as cm:
            revue3.charger_politique(self.ecrire(politique))
        return cm.exception.motif

    def test_politique_livree_est_dormante_et_vide(self):
        politique = revue3.charger_politique()
        self.assertEqual(politique["etat"], "dormant")
        self.assertEqual(politique["generation"], 3)
        self.assertEqual(politique["selection"], [{
            "famille_auteur": "gpt-codex-family",
            "famille_relecture": "claude-family",
        }])
        self.assertEqual(politique["relecteurs"], [{
            "famille": "claude-family",
            "actif": False,
            "acceptable": False,
            "modeles": [],
            "fournisseurs": [],
            "endpoints": [],
        }])

    def test_epinglage_fichier_compare_les_octets_exacts(self):
        octets = revue3.octets_politique_canonique()
        copie_exacte = self.ecrire_octets(octets)
        self.assertEqual(revue3.charger_politique(copie_exacte), revue3.charger_politique())

        # Même objet JSON, mais octets différents : un chemin est épinglé aux
        # octets livrés, pas seulement à sa valeur décodée.
        reformatee = self.ecrire_octets(revue.canonique(revue3.charger_politique()))
        with self.assertRaises(revue.Refus) as cm:
            revue3.charger_politique(reformatee)
        self.assertEqual(cm.exception.motif, "politique_non_epinglee")

    def test_cli_politique_refuse_une_substitution_explicitement(self):
        substituee = aide_v3.politique_v3_ancree()
        substituee["limites"]["diff_octets"] -= 1
        resultat = subprocess.run(
            [sys.executable, "-I", str(aide.RACINE / "outils/revue3.py"),
             "politique", "--fichier", self.ecrire(substituee)],
            cwd=aide.RACINE,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(resultat.returncode, 1)
        self.assertEqual(json.loads(resultat.stdout), {
            "motif": "politique_non_epinglee",
            "statut": "refus",
        })

    def test_activation_refusee_meme_pour_un_verdict_favorable(self):
        with self.assertRaises(revue3.Refus) as cm:
            revue3.verifier_activation(revue3.charger_politique(), verdict="FAVORABLE")
        self.assertEqual(cm.exception.motif, "politique_dormante")

    def test_schema_interdit_activation_et_identites_non_validees(self):
        for cle, valeur in (
            ("actif", True),
            ("acceptable", True),
            ("modeles", ["modele-non-verifie"]),
            ("fournisseurs", ["fournisseur-non-verifie"]),
            ("endpoints", ["https://exemple.invalid"]),
        ):
            politique = aide_v3.politique_v3_ancree()
            politique["relecteurs"][0][cle] = valeur
            self.assertEqual(self.refus_politique(politique), "politique_invalide", cle)

    def test_selection_codex_vers_claude_sans_fallback(self):
        politique = aide_v3.politique_v3_ancree()
        for auteur in ("codex", "gpt", "gpt-6-codex", "chatgpt-codex"):
            self.assertEqual(revue3.selectionner_famille(auteur, politique), "claude-family")
        for auteur, motif in (("inconnu", "auteur_inconnu"),
                              ("claude", "famille_relecture_indisponible")):
            with self.assertRaises(revue3.Refus) as cm:
                revue3.selectionner_famille(auteur, politique)
            self.assertEqual(cm.exception.motif, motif)

    def test_famille_identique_a_celle_de_l_auteur_refusee(self):
        politique = aide_v3.politique_v3_ancree()
        politique["selection"][0]["famille_relecture"] = "gpt-codex-family"
        politique["relecteurs"][0]["famille"] = "gpt-codex-family"
        self.assertEqual(self.refus_politique(politique), "famille_non_independante")

    def test_famille_inconnue_refusee_par_le_schema(self):
        politique = aide_v3.politique_v3_ancree()
        politique["relecteurs"][0]["famille"] = "famille-inconnue"
        self.assertEqual(self.refus_politique(politique), "politique_invalide")

    def test_sujet_v3_est_disjoint_et_nomme_distinctement(self):
        candidat = aide.DepotCandidat()
        try:
            sujet = aide_v3.sujet_v3_pour(candidat, candidat.c3)
            sujet_v1 = aide.sujet_pour(candidat, candidat.c3)
        finally:
            candidat.nettoyer()
        self.assertEqual(sujet["format"], "olistic.confiance.sujet-revue/3")
        self.assertNotEqual(revue.canonique(sujet), revue.canonique(sujet_v1))
        self.assertTrue(revue3.nom_sujet(sujet, aide.RID).startswith("olistic-revue3:"))

    def test_schemas_v3_stricts_concordent_avec_jsonschema(self):
        candidat = aide.DepotCandidat()
        try:
            sujet = aide_v3.sujet_v3_pour(candidat, candidat.c3)
        finally:
            candidat.nettoyer()
        politique = aide_v3.politique_v3_ancree()
        predicat = aide_v3.predicat_v3(sujet, politique)
        cas = {
            "politique": [politique, {**politique, "etat": "actif"}, {**politique, "inconnu": 1}],
            "sujet-revue": [sujet, {**sujet, "format": "olistic.confiance.sujet-revue/2"},
                             {**sujet, "perimetre_sha256": "x"}],
            "attestation-revue": [predicat, {**predicat, "autorisation": True},
                                    {**predicat, "Approval-Attestation": "interdit"}],
        }
        for nom, valeurs in cas.items():
            schema = revue3.schema(nom)
            reference = jsonschema.Draft202012Validator(schema)
            for valeur in valeurs:
                self.assertEqual(schema_strict.valide(valeur, schema), reference.is_valid(valeur), nom)

    def test_aucune_approval_attestation_dans_le_predicat(self):
        candidat = aide.DepotCandidat()
        try:
            predicat = aide_v3.predicat_v3(aide_v3.sujet_v3_pour(candidat, candidat.c3))
        finally:
            candidat.nettoyer()
        self.assertNotIn("Approval-Attestation", json.dumps(predicat))
        altere = copy.deepcopy(predicat)
        altere["Approval-Attestation"] = "interdit"
        self.assertTrue(schema_strict.erreurs(altere, revue3.schema("attestation-revue")))


if __name__ == "__main__":
    unittest.main()

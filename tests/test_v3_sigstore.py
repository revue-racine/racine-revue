"""Variante Sigstore revue/3 : preuve, provenance et contrat, hors ligne."""
import copy
import datetime
import tempfile
import unittest
from pathlib import Path

import aide
from aide import revue
import aide_v3
import aide_v3_crypto as crypto
import verifier3


class TestSigstoreV3(unittest.TestCase):
    def setUp(self):
        self.b = crypto.BancV3()
        self.addCleanup(self.b.fermer)

    def test_favorable_prouve_et_conforme_reste_inacceptable_p1(self):
        self.b.publier()
        decision = self.b.verifier()
        self.assertTrue(decision.cryptographiquement_valide)
        self.assertTrue(decision.conforme_au_contrat)
        self.assertFalse(decision.acceptable_p1)
        self.assertEqual(decision.motif, "politique_dormante")
        self.assertEqual(decision.verdict, "FAVORABLE")
        self.assertEqual(decision.nature, "cryptographique-sigstore")

    def test_favorable_et_defavorable_autre_demande_bloquent_dans_tout_ordre(self):
        favorable = crypto.resultat_v3(crypto.predicat_crypto(self.b.sujet))
        predicat_defavorable = crypto.predicat_crypto(
            self.b.sujet, request_id="f" * 32, verdict="DEFAVORABLE"
        )
        predicat_defavorable["demande"]["issue"] = 8
        defavorable = crypto.resultat_v3(predicat_defavorable)
        decisions = []
        for ordre in ((favorable, defavorable), (defavorable, favorable)):
            self.b.reinitialiser_attestations()
            for resultat in ordre:
                self.b.gh.publier(resultat)
            decision = self.b.verifier()
            decisions.append(decision)
            self.assertTrue(decision.cryptographiquement_valide)
            self.assertTrue(decision.conforme_au_contrat)
            self.assertFalse(decision.acceptable_p1)
            self.assertEqual(decision.verdict, "DEFAVORABLE")
            self.assertEqual(decision.motif, "defavorable_sur_le_meme_sujet")
            self.assertEqual(
                decision.predicat["demande"]["request_id"], "f" * 32
            )
            self.assertEqual(decision.predicat["verdict"], "DEFAVORABLE")
        self.assertEqual(decisions[0], decisions[1])

    def test_favorable_puis_defavorable_meme_demande_bloquent_dans_tout_ordre(self):
        favorable = crypto.resultat_v3(crypto.predicat_crypto(self.b.sujet))
        instant_ulterieur = revue.format_instant(
            crypto.MAINTENANT - datetime.timedelta(minutes=4, seconds=30)
        )
        defavorable = crypto.resultat_v3(crypto.predicat_crypto(
            self.b.sujet, verdict="DEFAVORABLE", instant=instant_ulterieur
        ))
        decisions = []
        for ordre in ((favorable, defavorable), (defavorable, favorable)):
            self.b.reinitialiser_attestations()
            for resultat in ordre:
                self.b.gh.publier(resultat)
            decision = self.b.verifier()
            decisions.append(decision)
            self.assertTrue(decision.cryptographiquement_valide)
            self.assertTrue(decision.conforme_au_contrat)
            self.assertFalse(decision.acceptable_p1)
            self.assertEqual(decision.verdict, "DEFAVORABLE")
            self.assertEqual(decision.motif, "verdict_defavorable")
            self.assertEqual(decision.predicat["verdict"], "DEFAVORABLE")
        self.assertEqual(decisions[0], decisions[1])

    def test_defavorable_seule_est_un_refus_contractuel_coherent(self):
        self.b.publier(verdict="DEFAVORABLE")
        decision = self.b.verifier()
        self.assertTrue(decision.cryptographiquement_valide)
        self.assertTrue(decision.conforme_au_contrat)
        self.assertFalse(decision.acceptable_p1)
        self.assertEqual(decision.verdict, "DEFAVORABLE")
        self.assertEqual(decision.motif, "verdict_defavorable")
        self.assertEqual(decision.predicat["verdict"], "DEFAVORABLE")

    def test_motif_incoherent_avec_le_verdict_est_non_conforme(self):
        predicat = crypto.predicat_crypto(self.b.sujet, verdict="DEFAVORABLE")
        predicat["motif"] = "synthetique"
        self.b.gh.publier(crypto.resultat_v3(predicat))
        decision = self.b.verifier()
        self.assertTrue(decision.cryptographiquement_valide)
        self.assertFalse(decision.conforme_au_contrat)
        self.assertFalse(decision.acceptable_p1)
        self.assertIsNone(decision.verdict)
        self.assertEqual(decision.motif, "predicat_invalide")

    def test_r1_autres_demandes_seules_restent_crypto_valides_sans_correspondance(self):
        for verdict in ("FAVORABLE", "DEFAVORABLE"):
            with self.subTest(verdict=verdict):
                self.b.reinitialiser_attestations()
                predicat = crypto.predicat_crypto(
                    self.b.sujet, request_id="f" * 32, verdict=verdict
                )
                self.b.gh.publier(crypto.resultat_v3(predicat))
                decision = self.b.verifier()
                self.assertTrue(decision.cryptographiquement_valide)
                self.assertFalse(decision.conforme_au_contrat)
                self.assertFalse(decision.acceptable_p1)
                self.assertIsNone(decision.verdict)
                self.assertEqual(
                    decision.motif, "aucune_attestation_pour_la_demande"
                )

    def test_attestation_absente_ou_signature_invalide(self):
        decision = self.b.verifier()
        self.assertEqual(
            (decision.cryptographiquement_valide, decision.conforme_au_contrat),
            (False, False),
        )
        self.assertEqual(decision.motif, "aucune_attestation_pour_la_demande")

        self.b.publier(signe=False)
        decision = self.b.verifier()
        self.assertFalse(decision.cryptographiquement_valide)
        self.assertEqual(decision.motif, "verification_cryptographique")

    def test_identite_signataire_inattendue(self):
        predicat = crypto.predicat_crypto(self.b.sujet)
        certificat = crypto.certificat_v3()
        certificat["issuer"] = "https://issuer.test.invalid"
        self.b.gh.publier(crypto.resultat_v3(predicat, certificat=certificat))
        decision = self.b.verifier()
        self.assertTrue(decision.cryptographiquement_valide)
        self.assertFalse(decision.conforme_au_contrat)
        self.assertEqual(decision.motif, "certificat:issuer")

    def test_mauvais_depot_workflow_ou_commit(self):
        cas = {
            "sourceRepositoryURI": "https://github.com/test/intrus",
            "githubWorkflowName": "intrus",
            "sourceRepositoryDigest": "b" * 40,
        }
        for champ, valeur in cas.items():
            with self.subTest(champ=champ):
                predicat = crypto.predicat_crypto(self.b.sujet)
                certificat = crypto.certificat_v3()
                certificat[champ] = valeur
                self.b.gh.publier(crypto.resultat_v3(predicat, certificat=certificat))
                decision = self.b.verifier()
                self.assertTrue(decision.cryptographiquement_valide)
                self.assertFalse(decision.conforme_au_contrat)
                self.assertTrue(decision.motif.startswith("certificat:"), decision)
                self.b.reinitialiser_attestations()

    def test_commit_arbre_et_sujet_substitues(self):
        for chemin in (("pointe", "commit"), ("pointe", "arbre"), (None, "perimetre_sha256")):
            with self.subTest(champ=chemin):
                predicat = crypto.predicat_crypto(self.b.sujet)
                if chemin[0] is None:
                    predicat["sujet"][chemin[1]] = "b" * 64
                else:
                    predicat["sujet"][chemin[0]][chemin[1]] = "b" * 40
                self.b.gh.publier(crypto.resultat_v3(predicat, sujet=self.b.sujet))
                decision = self.b.verifier()
                self.assertTrue(decision.cryptographiquement_valide)
                self.assertFalse(decision.conforme_au_contrat)
                self.assertEqual(decision.motif, "sujet_divergent")
                self.b.gh.par_digest.clear()

    def test_empreintes_politique_protocole_ou_ancres_divergentes(self):
        cas = (("politique", "sha256"), ("protocole", "sha256"), (None, "ancres_sha256"))
        for bloc, champ in cas:
            with self.subTest(bloc=bloc):
                predicat = crypto.predicat_crypto(self.b.sujet)
                if bloc is None:
                    predicat[champ] = "b" * 64
                else:
                    predicat[bloc][champ] = "b" * 64
                self.b.gh.publier(crypto.resultat_v3(predicat))
                decision = self.b.verifier()
                self.assertTrue(decision.cryptographiquement_valide)
                self.assertFalse(decision.conforme_au_contrat)
                self.assertIn(decision.motif, {"politique_differente", "protocole_different"})
                self.b.gh.par_digest.clear()

    def test_famille_identique_a_l_auteur_refusee(self):
        predicat = crypto.predicat_crypto(self.b.sujet)
        predicat["demande"]["declaration_p1"]["auteur"] = "claude"
        self.b.gh.publier(crypto.resultat_v3(predicat))
        decision = self.b.verifier()
        self.assertTrue(decision.cryptographiquement_valide)
        self.assertFalse(decision.conforme_au_contrat)
        self.assertEqual(decision.motif, "famille_relecture_indisponible")

    def test_modele_fournisseur_et_endpoint_doivent_etre_epingles(self):
        for champ in ("modele", "fournisseur", "endpoint"):
            with self.subTest(champ=champ):
                predicat = crypto.predicat_crypto(self.b.sujet)
                predicat["relecteur"][champ] = "inconnu-test"
                self.b.gh.publier(crypto.resultat_v3(predicat))
                decision = self.b.verifier()
                self.assertTrue(decision.cryptographiquement_valide)
                self.assertFalse(decision.conforme_au_contrat)
                self.assertEqual(decision.motif, f"{champ}_non_admis")
                self.b.gh.par_digest.clear()

    def test_attestation_expiree(self):
        predicat = crypto.predicat_crypto(self.b.sujet)
        self.b.gh.publier(crypto.resultat_v3(predicat))
        with tempfile.TemporaryDirectory() as tmp:
            decision = verifier3.verifier_cryptographique(
                self.b.confiance_path,
                self.b.politique_path,
                self.b.sujet,
                aide.RID,
                Path(tmp),
                maintenant=crypto.MAINTENANT + datetime.timedelta(days=8),
            )
        self.assertTrue(decision.cryptographiquement_valide)
        self.assertFalse(decision.conforme_au_contrat)
        self.assertEqual(decision.motif, "attestation_perimee")

    def test_revocation_par_empreinte_de_l_enonce(self):
        resultat = crypto.resultat_v3(crypto.predicat_crypto(self.b.sujet))
        self.b.gh.publier(resultat)
        self.b.ecrire_confiance(crypto.confiance_v3(
            revocations=[crypto.empreinte_enonce(resultat)]
        ))
        decision = self.b.verifier()
        self.assertTrue(decision.cryptographiquement_valide)
        self.assertFalse(decision.conforme_au_contrat)
        self.assertEqual(decision.motif, "attestation_revoquee")

    def test_synthetique_signee_reste_refusee(self):
        predicat = aide_v3.predicat_v3(self.b.sujet)
        self.b.gh.publier(crypto.resultat_v3(predicat))
        decision = self.b.verifier()
        self.assertTrue(decision.cryptographiquement_valide)
        self.assertFalse(decision.conforme_au_contrat)
        self.assertFalse(decision.acceptable_p1)
        self.assertEqual(decision.motif, "attestation_synthetique_refusee")

    def test_attestation_v1_ou_v2_presentee_comme_v3(self):
        for type_predicat in (
            "urn:olistic:confiance:attestation-revue:1",
            "urn:olistic:confiance:attestation-revue:2",
        ):
            with self.subTest(type_predicat=type_predicat):
                predicat = crypto.predicat_crypto(self.b.sujet)
                self.b.gh.publier(crypto.resultat_v3(
                    predicat, type_predicat=type_predicat
                ))
                decision = self.b.verifier()
                self.assertTrue(decision.cryptographiquement_valide)
                self.assertFalse(decision.conforme_au_contrat)
                self.assertEqual(decision.motif, "type_predicat")
                self.b.gh.par_digest.clear()

    def test_bundle_modifie_n_est_pas_une_preuve(self):
        resultat = crypto.resultat_v3(crypto.predicat_crypto(self.b.sujet))
        empreinte = self.b.gh.publier(resultat)
        self.b.gh.signes.remove(empreinte)
        decision = self.b.verifier()
        self.assertFalse(decision.cryptographiquement_valide)
        self.assertFalse(decision.conforme_au_contrat)
        self.assertEqual(decision.motif, "verification_cryptographique")

    def test_request_id_substitue_n_est_pas_rattache_a_la_demande(self):
        autre = "f" * 32
        predicat = crypto.predicat_crypto(self.b.sujet, request_id=autre)
        self.b.gh.publier(crypto.resultat_v3(predicat, sujet=self.b.sujet))
        decision = self.b.verifier()
        self.assertTrue(decision.cryptographiquement_valide)
        self.assertFalse(decision.conforme_au_contrat)
        self.assertEqual(decision.motif, "aucune_attestation_pour_la_demande")

    def test_configuration_ne_rend_jamais_l_identite_acceptable(self):
        conf = crypto.confiance_v3()
        conf["acceptable_p1"] = True
        self.b.ecrire_confiance(conf)
        self.b.publier()
        decision = self.b.verifier()
        self.assertFalse(decision.cryptographiquement_valide)
        self.assertFalse(decision.conforme_au_contrat)
        self.assertFalse(decision.acceptable_p1)
        self.assertEqual(decision.motif, "confiance_v3_invalide")


if __name__ == "__main__":
    unittest.main()

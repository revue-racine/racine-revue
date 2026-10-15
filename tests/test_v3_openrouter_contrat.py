"""Contrat dormant, sélection de famille et requête OpenRouter fermée."""
import copy
import json
import unittest

import aide  # noqa: F401
from aide import revue
import aide_openrouter as ao
import relecteur_openrouter as ro
import transport_openrouter as th


class TestContratOpenRouter(unittest.TestCase):
    def motif_config(self, config):
        with self.assertRaises(revue.Refus) as cm:
            ro.charger_configuration(config)
        return cm.exception.motif

    def test_nominal_reste_simule_non_acceptable_et_non_autorisant(self):
        resultat = ao.executer()
        self.assertEqual(resultat.verdict, "FAVORABLE")
        self.assertFalse(resultat.acceptable_future)
        self.assertFalse(resultat.autorisante)
        self.assertEqual(resultat.tentatives_inference, 1)
        self.assertIn("broadcast_compte_non_verifie", resultat.limites_non_verifiees)
        self.assertIn("identite_modele_non_cryptographique", resultat.limites_non_verifiees)
        self.assertIn("plugins_compte_non_verifies", resultat.limites_non_verifiees)

    def test_configuration_doit_rester_dormante(self):
        for cle, valeur in (("etat", "actif"), ("actif", True), ("acceptable", True)):
            config = ao.configuration(**{cle: valeur})
            self.assertIn(
                self.motif_config(config),
                {"openrouter_configuration_invalide", "openrouter_activation_interdite"},
            )

    def test_configuration_fermee_sans_modele_par_defaut(self):
        config = ao.configuration()
        config["inconnu"] = True
        self.assertEqual(self.motif_config(config), "openrouter_configuration_invalide")
        config = ao.configuration()
        config.pop("modele")
        self.assertEqual(self.motif_config(config), "openrouter_configuration_invalide")
        self.assertFalse(hasattr(ro, "MODELE"))

    def test_modele_non_verifie_ou_alias_flottant_refuse(self):
        self.assertEqual(
            self.motif_config(ao.configuration(modele_verifie=True)),
            "openrouter_modele_non_verifie",
        )
        for modele in (
            "openrouter/auto",
            "anthropic/claude-latest",
            "anthropic/claude-preview",
            "anthropic/claude-sonnet:free",
        ):
            self.assertIn(
                self.motif_config(ao.configuration(modele=modele)),
                {
                    "openrouter_alias_flottant",
                    "openrouter_famille_modele_incoherente",
                    "openrouter_modele_invalide",
                    "openrouter_profil_incoherent",
                },
                modele,
            )

    def test_profil_simule_ferme_refuse_toute_valeur_inconnue(self):
        self.assertEqual(
            self.motif_config(ao.configuration(profil="inconnu")),
            "openrouter_profil_inconnu",
        )
        self.assertEqual(
            self.motif_config(ao.configuration(fournisseur="autre")),
            "openrouter_profil_incoherent",
        )

    def test_famille_du_modele_et_endpoint_coherents(self):
        self.assertEqual(
            self.motif_config(ao.configuration(modele="openai/gpt-5-20261001")),
            "openrouter_profil_incoherent",
        )
        self.assertEqual(
            self.motif_config(ao.configuration(endpoint_fournisseur="google-vertex/us-east5")),
            "openrouter_profil_incoherent",
        )
        self.assertEqual(
            self.motif_config(ao.configuration(endpoint_exige=False)),
            "openrouter_endpoint_non_epingle",
        )

    def test_meme_famille_que_l_auteur_et_auteur_inconnu_refuses(self):
        for auteur, motif in (("claude", "famille_relecture_indisponible"), ("autre", "auteur_inconnu")):
            with self.assertRaises(revue.Refus) as cm:
                ao.executer(auteur=auteur)
            self.assertEqual(cm.exception.motif, motif)
        with self.assertRaises(revue.Refus) as cm:
            ao.executer(config=ao.configuration(famille_relecture="gpt-codex-family"))
        self.assertIn(
            cm.exception.motif,
            {
                "openrouter_famille_modele_incoherente",
                "openrouter_famille_non_independante",
                "openrouter_profil_incoherent",
            },
        )

    def test_parametres_obligatoires_strictement_construits(self):
        transport = ao.TransportSimule()
        ao.executer(transport=transport)
        self.assertEqual(transport.appels, 2)
        _, budget = transport.requetes[0]
        _, inference = transport.requetes[1]
        self.assertEqual((budget.methode, budget.chemin), ("GET", "/api/v1/key"))
        self.assertEqual((inference.methode, inference.chemin), ("POST", "/api/v1/chat/completions"))
        corps = json.loads(inference.corps)
        self.assertEqual(
            set(corps),
            {
                "model",
                "messages",
                "response_format",
                "temperature",
                "max_tokens",
                "stream",
                "provider",
            },
        )
        self.assertEqual(
            corps["provider"],
            {
                "order": ["anthropic"],
                "only": ["anthropic"],
                "allow_fallbacks": False,
                "require_parameters": True,
                "data_collection": "deny",
                "zdr": True,
            },
        )
        self.assertFalse(corps["stream"])
        self.assertNotIn("tools", corps)
        self.assertNotIn("plugins", corps)
        self.assertNotIn("models", corps)

    def test_zdr_collecte_fallback_et_epinglage_sont_explicites(self):
        config = ro.charger_configuration(ao.configuration())
        corps, _ = ro.construire_requete(config, b"+x\n", revue.schema("sortie-relecteur"))
        fournisseur = corps["provider"]
        self.assertIs(fournisseur["zdr"], True)
        self.assertEqual(fournisseur["data_collection"], "deny")
        self.assertIs(fournisseur["allow_fallbacks"], False)
        self.assertEqual(fournisseur["order"], [config.endpoint_fournisseur])
        self.assertEqual(fournisseur["only"], [config.endpoint_fournisseur])
        self.assertIs(fournisseur["require_parameters"], True)

    def test_broadcast_ne_peut_pas_etre_autoproclame_par_la_configuration(self):
        admin = copy.deepcopy(ro.ADMIN_NON_VERIFIE)
        admin["broadcast"] = "desactive"
        self.assertEqual(
            self.motif_config(ao.configuration(controles_administratifs=admin)),
            "openrouter_controle_administratif_non_supporte",
        )

    def test_transport_reel_refuse_avant_tout_appel(self):
        class SousClasseReelle(th.TransportHTTPS):
            simule = True

        for transport in (
            th.TransportHTTPS(connexion=lambda: None),
            SousClasseReelle(connexion=lambda: None),
        ):
            transport.simule = True
            with self.assertRaises(revue.Refus) as cm:
                ao.executer(transport=transport)
            self.assertEqual(cm.exception.motif, "openrouter_adaptateur_dormant")
            self.assertEqual(transport.appels, 0)

    def test_transport_simule_sans_compteur_probant_est_refuse(self):
        class SansCompteur:
            simule = True

            def envoyer(self, _cle, _requete):
                raise AssertionError("aucun appel attendu")

        for valeur in (None, True, -1, "0"):
            transport = SansCompteur()
            if valeur is not None:
                transport.appels = valeur
            with self.assertRaises(revue.Refus) as cm:
                ao.executer(transport=transport)
            self.assertEqual(cm.exception.motif, "openrouter_compteur_appels")

    def test_diff_et_requete_bornes(self):
        with self.assertRaises(revue.Refus) as cm:
            ao.executer(config=ao.configuration(diff_octets=2), diff=b"trois")
        self.assertEqual(cm.exception.motif, "openrouter_diff_invalide")
        with self.assertRaises(revue.Refus) as cm:
            ao.executer(config=ao.configuration(requete_octets=1))
        self.assertEqual(cm.exception.motif, "openrouter_requete_trop_grande")


if __name__ == "__main__":
    unittest.main()

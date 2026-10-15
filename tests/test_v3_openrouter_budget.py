"""Précontrôle budgétaire à vie, strict et antérieur à l'inférence."""
import json
import unittest

import aide  # noqa: F401
from aide import revue
import aide_openrouter as ao
import relecteur_openrouter as ro
import transport_openrouter as th


class TestBudgetOpenRouter(unittest.TestCase):
    def motif(self, reponse, config=None):
        transport = ao.TransportSimule([reponse, ao.inference()])
        with self.assertRaises(revue.Refus) as cm:
            ao.executer(transport=transport, config=config)
        self.assertEqual(transport.appels, 1)
        return cm.exception.motif

    def test_limite_a_vie_exacte_et_budget_non_epuise(self):
        config = ro.charger_configuration(ao.configuration())
        limite, restant = ro.controler_budget(ao.budget().corps, config)
        self.assertEqual(str(limite), "100")
        self.assertEqual(str(restant), "75")

    def test_limite_absente_refusee(self):
        objet = json.loads(ao.budget().corps)
        objet["data"].pop("limit")
        reponse = th.Reponse(json.dumps(objet).encode(), {})
        self.assertEqual(self.motif(reponse), "openrouter_budget_invalide")

    def test_limite_reinitialisable_refusee(self):
        for reset in ("daily", "weekly", "monthly"):
            self.assertEqual(
                self.motif(ao.budget(limit_reset=reset)),
                "openrouter_budget_reinitialisable",
                reset,
            )

    def test_limite_epuisee_refusee(self):
        self.assertEqual(
            self.motif(ao.budget(limit_remaining=0, usage=100)),
            "openrouter_budget_epuise",
        )

    def test_limite_incompatible_avec_la_politique_attendue(self):
        self.assertEqual(
            self.motif(ao.budget(limit=200, limit_remaining=175, usage=25)),
            "openrouter_budget_politique_incompatible",
        )

    def test_donnees_financieres_incoherentes_refusees(self):
        for changements in (
            {"limit_remaining": 101, "usage": 0},
            {"limit_remaining": 70, "usage": 25},
            {"limit_remaining": -1, "usage": 101},
            {"usage": -1, "limit_remaining": 101},
        ):
            self.assertEqual(
                self.motif(ao.budget(**changements)),
                "openrouter_budget_incoherent",
                changements,
            )

    def test_byok_refuse_dans_le_precontrole(self):
        for changements in (
            {"byok_usage": 1},
            {"include_byok_in_limit": True},
        ):
            self.assertEqual(self.motif(ao.budget(**changements)), "openrouter_byok")

    def test_cle_de_gestion_ou_de_provisionnement_refusee(self):
        for changements in (
            {"is_management_key": True},
            {"is_provisioning_key": True},
        ):
            self.assertEqual(self.motif(ao.budget(**changements)), "openrouter_cle_inadaptee")

    def test_schema_budget_ferme_et_json_strict(self):
        objet = json.loads(ao.budget().corps)
        objet["data"]["surprise"] = 1
        self.assertEqual(
            self.motif(th.Reponse(json.dumps(objet).encode(), {})),
            "openrouter_budget_invalide",
        )
        self.assertEqual(
            self.motif(th.Reponse(b'{"data":{"limit":1,"limit":2}}', {})),
            "openrouter_budget_illisible",
        )

    def test_budget_attendu_n_est_pas_code_comme_decision_definitive(self):
        config = ao.configuration(budget_max_vie="250.50")
        resultat = ao.executer(
            config=config,
            transport=ao.TransportSimule(
                [ao.budget(limit=250.5, limit_remaining=200.5, usage=50), ao.inference()]
            ),
        )
        self.assertFalse(resultat.autorisante)

    def test_champs_documentes_recents_sont_controles_strictement(self):
        effectif = {
            "budget_id": None,
            "guardrail_id": "controle-test",
            "include_byok": False,
            "limit_usd": 100,
            "remaining_usd": 75,
            "reset_interval": None,
            "resets_at": None,
            "scope": "member",
            "spend_usd": 25,
        }
        reponse = ao.budget(
            allowed_data_regions=["global", "europe"],
            budgets=[effectif],
            effective_budget=effectif,
            free_model_daily_requests={"limit": 50, "remaining": 38, "used": 12},
            rate_limit={"interval": "1h", "requests": 1000, "note": "obsolete"},
            organization_id=None,
            workspace_id="espace-test",
        )
        config = ro.charger_configuration(ao.configuration())
        self.assertEqual(ro.controler_budget(reponse.corps, config), (100, 75))

        effectif_vie = {**effectif, "reset_interval": "lifetime"}
        self.assertEqual(
            ro.controler_budget(
                ao.budget(effective_budget=effectif_vie).corps, config
            ),
            (100, 75),
        )

    def test_budget_effectif_periodique_byok_ou_incoherent_refuse(self):
        base = {
            "budget_id": None,
            "guardrail_id": "controle-test",
            "include_byok": False,
            "limit_usd": 100,
            "remaining_usd": 75,
            "reset_interval": None,
            "resets_at": None,
            "scope": "member",
            "spend_usd": 25,
        }
        cas = (
            ({**base, "reset_interval": "weekly", "resets_at": "demain"}, "openrouter_budget_reinitialisable"),
            ({**base, "include_byok": True}, "openrouter_byok"),
            ({**base, "remaining_usd": 70}, "openrouter_budget_incoherent"),
            ({**base, "limit_usd": 200, "remaining_usd": 175}, "openrouter_budget_politique_incompatible"),
        )
        for effectif, motif in cas:
            self.assertEqual(self.motif(ao.budget(effective_budget=effectif)), motif)

    def test_echec_du_precontrole_interdit_l_inference(self):
        transport = ao.TransportSimule(
            [ao.budget(limit_reset="monthly"), AssertionError("inférence interdite")]
        )
        with self.assertRaises(revue.Refus) as cm:
            ao.executer(transport=transport)
        self.assertEqual(cm.exception.motif, "openrouter_budget_reinitialisable")
        self.assertEqual(transport.appels, 1)


if __name__ == "__main__":
    unittest.main()

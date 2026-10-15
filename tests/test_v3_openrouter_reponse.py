"""Validation fermée de la réponse et des métadonnées de routage."""
import json
import unittest

import aide  # noqa: F401
from aide import revue
import aide_openrouter as ao
import transport_openrouter as th


def modifier(reponse, fonction):
    objet = json.loads(reponse.corps)
    fonction(objet)
    return th.Reponse(json.dumps(objet, separators=(",", ":")).encode(), reponse.entetes)


class TestReponseOpenRouter(unittest.TestCase):
    def motif(self, reponse):
        transport = ao.TransportSimule([ao.budget(), reponse])
        with self.assertRaises(revue.Refus) as cm:
            ao.executer(transport=transport)
        self.assertEqual(transport.appels, 2)
        return cm.exception.motif

    def test_modele_rapporte_exactement(self):
        self.assertEqual(
            self.motif(ao.inference(modele="anthropic/claude-autre-20250101")),
            "openrouter_modele_inattendu",
        )

    def test_fournisseur_rapporte_exactement(self):
        self.assertEqual(
            self.motif(ao.inference(fournisseur="Autre")),
            "openrouter_fournisseur_inattendu",
        )

    def test_tentative_supplementaire_refusee(self):
        self.assertEqual(
            self.motif(ao.inference(tentative=2)),
            "openrouter_routage_inattendu",
        )

    def test_fallback_ou_routage_ambigu_refuse(self):
        self.assertEqual(
            self.motif(ao.inference(total_endpoints=2)),
            "openrouter_routage_ambigu",
        )
        self.assertEqual(
            self.motif(ao.inference(strategy="fallback")),
            "openrouter_routage_inattendu",
        )
        reponse = modifier(
            ao.inference(),
            lambda x: x["openrouter_metadata"]["endpoints"]["available"].append(
                {"model": ao.MODELE, "provider": "Other", "selected": False}
            ),
        )
        self.assertEqual(self.motif(reponse), "openrouter_routage_ambigu")

    def test_byok_refuse_dans_deux_metadonnees(self):
        self.assertEqual(self.motif(ao.inference(is_byok=True)), "openrouter_byok")
        reponse = modifier(
            ao.inference(), lambda x: x["usage"].update({"is_byok": True})
        )
        self.assertEqual(self.motif(reponse), "openrouter_byok")

    def test_cache_de_reponse_refuse(self):
        for etat in ("HIT", "MISS"):
            self.assertEqual(
                self.motif(
                    ao.inference(entetes={"x-openrouter-cache-status": etat})
                ),
                "openrouter_cache_inattendu",
            )

    def test_outil_fournisseur_refuse(self):
        reponse = modifier(
            ao.inference(),
            lambda x: x["usage"].update(
                {
                    "server_tool_use_details": {
                        "tool_calls_executed": 1,
                        "tool_calls_requested": 1,
                    }
                }
            ),
        )
        self.assertEqual(self.motif(reponse), "openrouter_outil_inattendu")

    def test_schema_enveloppe_ferme(self):
        reponse = modifier(ao.inference(), lambda x: x.update({"surprise": 1}))
        self.assertEqual(self.motif(reponse), "openrouter_enveloppe_invalide")
        reponse = modifier(
            ao.inference(), lambda x: x["openrouter_metadata"].update({"surprise": 1})
        )
        self.assertEqual(self.motif(reponse), "openrouter_routage_ambigu")

    def test_sous_structures_usage_fermees(self):
        for champ, valeur in (
            ("cost_details", {"surprise": 1}),
            ("prompt_tokens_details", {"surprise": 1}),
            ("completion_tokens_details", {"surprise": 1}),
            ("cost", -1),
        ):
            reponse = modifier(
                ao.inference(), lambda x, c=champ, v=valeur: x["usage"].update({c: v})
            )
            self.assertEqual(
                self.motif(reponse), "openrouter_enveloppe_invalide", champ
            )

    def test_json_invalide_ou_cle_dupliquee_refuse(self):
        self.assertEqual(
            self.motif(th.Reponse(b"pas-json", {})),
            "openrouter_enveloppe_illisible",
        )
        self.assertEqual(
            self.motif(th.Reponse(b'{"id":"a","id":"b"}', {})),
            "openrouter_enveloppe_illisible",
        )

    def test_sortie_structuree_invalide_refusee(self):
        for contenu in (
            "pas-json",
            '{"verdict":"FAVORABLE","constats":[],"inconnu":1}',
            '{"verdict":"favorable","constats":[]}',
        ):
            self.assertEqual(
                self.motif(ao.inference(contenu=contenu)),
                "openrouter_sortie_invalide",
                contenu,
            )

    def test_verdict_favorable_contradictoire_refuse(self):
        contenu = ao.sortie(
            constats=[
                {"gravite": "bloquant", "titre": "Blocage", "detail": "x"}
            ]
        )
        self.assertEqual(
            self.motif(ao.inference(contenu=contenu)),
            "openrouter_sortie_contradictoire",
        )

    def test_indetermine_coherent_reste_non_autorisant(self):
        resultat = ao.executer(
            transport=ao.TransportSimule(
                [ao.budget(), ao.inference(contenu=ao.sortie(verdict="INDETERMINE"))]
            )
        )
        self.assertEqual(resultat.verdict, "INDETERMINE")
        self.assertEqual(resultat.motif, "relecteur")
        self.assertFalse(resultat.autorisante)

    def test_endpoint_exact_demande_mais_non_deduit_de_la_reponse(self):
        resultat = ao.executer()
        self.assertEqual(resultat.endpoint_demande, "anthropic")
        self.assertIn(
            "endpoint_non_rapporte_par_la_reponse", resultat.limites_non_verifiees
        )
        self.assertFalse(resultat.acceptable_future)


if __name__ == "__main__":
    unittest.main()

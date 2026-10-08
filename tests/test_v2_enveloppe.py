"""Enveloppe fournisseur : toute anomalie → Refus (aucune attestation) ; seule
une enveloppe valide livre sa sortie, jamais validée ici (§5 la normalise)."""
import json
import unittest

import aide  # noqa: F401
from aide import revue
import aide_v2
from aide_v2 import MODELE, enveloppe
import relecteur_openai as ro


def message(*parties):
    return {"type": "message", "role": "assistant", "content": list(parties)}


def texte(t):
    return {"type": "output_text", "text": t, "annotations": []}


class TestEnveloppe(unittest.TestCase):
    def motif(self, octets, modele=MODELE):
        with self.assertRaises(revue.Refus) as cm:
            ro.analyser_enveloppe(octets, modele)
        return cm.exception.motif

    def test_valide_rend_les_octets_exacts_du_texte(self):
        t = '{"verdict":"DEFAVORABLE","constats":[{"gravite":"majeur","titre":"é","detail":"x"}]}'
        self.assertEqual(ro.analyser_enveloppe(enveloppe(t), MODELE), t.encode("utf-8"))

    def test_flottants_admis_dans_l_enveloppe_mais_pas_dans_la_sortie(self):
        sortie = ro.analyser_enveloppe(enveloppe('{"verdict":"FAVORABLE","constats":[],"x":1.5}'), MODELE)
        self.assertEqual(revue.normaliser_verdict("openai-responses", sortie)[:2], ("INDETERMINE", "sortie_invalide"))

    def test_texte_invalide_passe_l_enveloppe_et_devient_indetermine(self):
        for t in ("", "pas du json", '{"verdict":"favorable","constats":[]}', '{"verdict":"FAVORABLE"}'):
            sortie = ro.analyser_enveloppe(enveloppe(t), MODELE)
            self.assertEqual(revue.normaliser_verdict("openai-responses", sortie)[:2],
                             ("INDETERMINE", "sortie_invalide"), t)

    def test_illisible(self):
        for corps in (b"", b"\xff", b"[]", b"null", b'{"object":"response","object":"response"}',
                      b'{"object":"autre","status":"completed"}', b"NaN", b'{"a":NaN}'):
            self.assertEqual(self.motif(corps), "relecteur_enveloppe_illisible", corps)

    def test_statut_non_termine_ou_erreur(self):
        for env in (enveloppe(status="incomplete", incomplete_details={"reason": "max_output_tokens"}),
                    enveloppe(status="failed"), enveloppe(status="in_progress"), enveloppe(status=None),
                    enveloppe(error={"code": "server_error"}),
                    enveloppe(incomplete_details={"reason": "content_filter"})):
            self.assertEqual(self.motif(env), "relecteur_statut")

    def test_modele_exact_octet_pour_octet(self):
        for m in ("gpt-6.1-sol-2026-09-29", "GPT-6.1-SOL", "gpt-6.1-sol ", "openai/gpt-6.1-sol", None):
            self.assertEqual(self.motif(enveloppe(modele=m)), "relecteur_modele_inattendu", m)

    def test_appel_d_outil_ou_element_inconnu_refuse(self):
        for el in ({"type": "function_call", "name": "x", "arguments": "{}"}, {"type": "web_search_call"},
                   {"type": "computer_call"}, {"type": "code_interpreter_call"}, "chaine", None):
            self.assertEqual(self.motif(enveloppe(sortie=[el, message(texte("{}"))])),
                             "relecteur_element_inattendu", el)

    def test_refus_du_modele(self):
        env = enveloppe(sortie=[message({"type": "refusal", "refusal": "non"})])
        self.assertEqual(self.motif(env), "relecteur_refus_modele")

    def test_partie_inconnue_ou_texte_non_chaine(self):
        for p in ({"type": "output_audio"}, {"type": "output_text", "text": 1}, {"type": "output_text"}):
            self.assertEqual(self.motif(enveloppe(sortie=[message(p)])), "relecteur_element_inattendu", p)

    def test_role_ou_contenu_inattendu(self):
        self.assertEqual(self.motif(enveloppe(sortie=[{"type": "message", "role": "user",
                                                        "content": [texte("{}")]}])),
                         "relecteur_enveloppe_illisible")
        self.assertEqual(self.motif(enveloppe(sortie=[{"type": "message", "role": "assistant"}])),
                         "relecteur_enveloppe_illisible")
        self.assertEqual(self.motif(enveloppe(output="x")), "relecteur_enveloppe_illisible")

    def test_exactement_un_texte(self):
        self.assertEqual(self.motif(enveloppe(sortie=[])), "relecteur_sortie_absente")
        self.assertEqual(self.motif(enveloppe(sortie=[{"type": "reasoning", "summary": []}])),
                         "relecteur_sortie_absente")
        self.assertEqual(self.motif(enveloppe(sortie=[message(texte("{}"), texte("{}"))])),
                         "relecteur_sortie_absente")
        self.assertEqual(self.motif(enveloppe(sortie=[message(texte("{}")), message(texte("{}"))])),
                         "relecteur_sortie_absente")

    def test_relire_de_bout_en_bout_local(self):
        with aide_v2.ServeurLocal() as s:
            self.assertEqual(aide_v2.relire_local(s), aide_v2.SORTIE_FAVORABLE)
            corps = json.loads(s.requetes[0][2])
        self.assertEqual(corps["model"], MODELE)
        self.assertIs(corps["store"], False)
        self.assertNotIn("tools", corps)


if __name__ == "__main__":
    unittest.main()

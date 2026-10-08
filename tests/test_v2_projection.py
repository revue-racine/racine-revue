"""Projection mécanique du schéma de sortie local vers Structured Outputs :
liste blanche, relâchement seulement, échec fermé."""
import copy
import json
import unittest

import jsonschema

import aide  # noqa: F401
from aide import revue
import relecteur_openai as ro


def local():
    return revue.schema("sortie-relecteur")


ATTENDUE = {
    "type": "object", "additionalProperties": False, "required": ["verdict", "constats"],
    "properties": {
        "verdict": {"enum": ["FAVORABLE", "DEFAVORABLE", "INDETERMINE"]},
        "constats": {"type": "array", "maxItems": 200, "items": {
            "type": "object", "additionalProperties": False, "required": ["gravite", "titre", "detail"],
            "properties": {
                "gravite": {"enum": ["bloquant", "majeur", "mineur", "info"]},
                "titre": {"type": "string"},
                "detail": {"type": "string"},
            }}},
    },
}


class TestProjection(unittest.TestCase):
    def test_projection_de_reference(self):
        self.assertEqual(ro.projeter(local()), ATTENDUE)

    def test_ne_touche_pas_au_schema_local(self):
        s = local()
        avant = json.dumps(s, sort_keys=True)
        ro.projeter(s)
        self.assertEqual(json.dumps(s, sort_keys=True), avant)

    def test_seuls_les_mots_cles_de_longueur_et_les_metadonnees_disparaissent(self):
        def cles(n, acc):
            if isinstance(n, dict):
                acc.update(n)
                for v in n.values():
                    cles(v, acc)
            return acc
        retires = cles(local(), set()) - cles(ro.projeter(local()), set())
        retires -= {"verdict", "constats", "gravite", "titre", "detail"}  # noms de propriétés, conservés ailleurs
        self.assertEqual(retires, {"$schema", "$id", "title", "description", "minLength", "maxLength"})

    def test_projection_valide_et_relachante(self):
        jsonschema.Draft202012Validator.check_schema(ro.projeter(local()))
        loc, api = jsonschema.Draft202012Validator(local()), jsonschema.Draft202012Validator(ro.projeter(local()))
        exemples = [
            {"verdict": "FAVORABLE", "constats": []},
            {"verdict": "DEFAVORABLE", "constats": [{"gravite": "bloquant", "titre": "t", "detail": "d" * 4000}]},
            {"verdict": "INDETERMINE", "constats": [{"gravite": "info", "titre": "x" * 300, "detail": ""}] * 200},
        ]
        for e in exemples:
            self.assertTrue(loc.is_valid(e))
            self.assertTrue(api.is_valid(e), e)
        # Relâchement : le schéma API admet ce que le local refuse ; le local reste l'autorité.
        trop_long = {"verdict": "FAVORABLE", "constats": [{"gravite": "info", "titre": "", "detail": "d" * 4001}]}
        self.assertFalse(loc.is_valid(trop_long))
        self.assertTrue(api.is_valid(trop_long))
        self.assertEqual(revue.normaliser_verdict("openai-responses", json.dumps(trop_long).encode())[:2],
                         ("INDETERMINE", "sortie_invalide"))

    def test_mot_cle_inconnu_refuse(self):
        for ajout in ({"if": {}}, {"anyOf": []}, {"format": "date"}, {"$ref": "#/x"}, {"default": 1}):
            s = local()
            s["properties"]["verdict"].update(ajout)
            with self.assertRaises(revue.Refus, msg=ajout):
                ro.projeter(s)

    def test_objet_ouvert_ou_cle_facultative_refuses(self):
        s = local()
        s["properties"]["constats"]["items"]["required"] = ["gravite", "titre"]
        with self.assertRaises(revue.Refus):
            ro.projeter(s)
        s = local()
        del s["additionalProperties"]
        with self.assertRaises(revue.Refus):
            ro.projeter(s)

    def test_racine_non_objet_refusee(self):
        with self.assertRaises(revue.Refus):
            ro.projeter({"type": "array", "items": {}})

    def test_requete_porte_la_projection_et_rien_d_autre(self):
        r = ro.construire_requete("m", b"diff", local())
        self.assertEqual(r["text"]["format"], {"type": "json_schema", "name": "sortie_relecteur_v1",
                                               "strict": True, "schema": ATTENDUE})
        self.assertEqual(set(r), {"model", "instructions", "input", "text", "store", "max_output_tokens", "reasoning"})
        self.assertIs(r["store"], False)
        self.assertNotIn("tools", r)
        self.assertNotIn("tool_choice", r)
        self.assertEqual(copy.deepcopy(r["model"]), "m")


if __name__ == "__main__":
    unittest.main()

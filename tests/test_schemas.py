"""Schémas : valides, fermés, et validateur maison concordant avec jsonschema."""
import json
import unittest

import jsonschema

import aide
from aide import revue
import schema_strict

SCHEMAS = aide.RACINE / "schemas"


def tous():
    return {p.name: json.loads(p.read_text("utf-8")) for p in SCHEMAS.glob("*.json")}


def objets(s):
    if isinstance(s, dict):
        if s.get("type") == "object" or "properties" in s:
            yield s
        for v in s.values():
            yield from objets(v)
    elif isinstance(s, list):
        for v in s:
            yield from objets(v)


class TestSchemas(unittest.TestCase):
    def test_inventaire(self):
        v1 = {f"{n}-v1.schema.json" for n in
              ("demande", "sujet-revue", "sortie-relecteur", "attestation-revue", "politique", "ancres")}
        v2 = {f"{n}-v2.schema.json" for n in ("sujet-revue", "attestation-revue", "politique")}
        self.assertEqual(set(tous()), v1 | v2)

    def test_meta_schema_2020_12(self):
        for nom, s in tous().items():
            jsonschema.Draft202012Validator.check_schema(s)

    def test_tous_les_objets_sont_fermes(self):
        for nom, s in tous().items():
            for o in objets(s):
                self.assertIs(o.get("additionalProperties"), False, nom)

    def test_sujet_identique_dans_l_attestation(self):
        s = tous()
        sujet = {k: v for k, v in s["sujet-revue-v1.schema.json"].items()
                 if k not in ("$schema", "$id", "title", "description", "$defs")}
        att = s["attestation-revue-v1.schema.json"]["$defs"]
        self.assertEqual(att["sujet"], sujet)
        self.assertEqual(att["identite_commit"], s["sujet-revue-v1.schema.json"]["$defs"]["identite_commit"])

    def test_concordance_avec_jsonschema(self):
        pol = aide.politique_ancree()
        cand = aide.DepotCandidat()
        try:
            sujet = aide.sujet_pour(cand, cand.c3)
        finally:
            cand.nettoyer()
        pred = aide.predicat(sujet)
        d = aide.demande("c" * 40)
        cas = {
            "politique": [pol, json.loads((aide.RACINE / "policy/confiance-v1.json").read_text()),
                          {**pol, "generation": 0}, {**pol, "version": True}, {**pol, "inconnu": 1}],
            "ancres": [json.loads((aide.RACINE / "policy/ancres-v1.json").read_text()), {"format": "x", "ancres": []}],
            "sujet-revue": [sujet, {**sujet, "perimetre_sha256": "x"},
                            {**sujet, "base": {**sujet["base"], "objet_sha256": None}}],
            "attestation-revue": [pred, {**pred, "verdict": "FAVORABLE_AVEC_CORRECTIONS"}, {**pred, "motif": "autre"},
                                  {**pred, "rapport_sha256": None}, {**pred, "instant": "2026-10-07"},
                                  {**pred, "demande": {**pred["demande"], "request_id": "x"}}],
            "demande": [d, {**d, "base": "b" * 40}, {"format": "x"}, []],
            "sortie-relecteur": [{"verdict": "FAVORABLE", "constats": []}, {"verdict": "FAVORABLE"},
                                 {"verdict": "FAVORABLE", "constats": [{"gravite": "info", "titre": "", "detail": ""}]}],
        }
        for nom, valeurs in cas.items():
            sch = revue.schema(nom)
            ref = jsonschema.Draft202012Validator(sch)
            for v in valeurs:
                self.assertEqual(schema_strict.valide(v, sch), ref.is_valid(v), f"{nom}: {v!r:.120}")

    def test_validateur_maison_refuse_un_mot_cle_inconnu(self):
        with self.assertRaises(schema_strict.SchemaInvalide):
            schema_strict.valide({}, {"type": "object", "if": {}})
        with self.assertRaises(schema_strict.SchemaInvalide):
            schema_strict.valide({}, {"type": "object", "properties": {}})

    def test_booleen_n_est_pas_un_entier(self):
        self.assertFalse(schema_strict.valide(True, {"type": "integer"}))
        self.assertFalse(schema_strict.valide(1, {"const": True}))


if __name__ == "__main__":
    unittest.main()

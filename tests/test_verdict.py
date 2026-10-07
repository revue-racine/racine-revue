"""Normalisation : énumération stricte à trois valeurs ; tout écart → INDETERMINE."""
import json
import unittest

import aide  # noqa: F401
from aide import revue


def sortie(**kw):
    d = {"verdict": "FAVORABLE", "constats": []}
    d.update(kw)
    return json.dumps(d).encode()


def constat(gravite):
    return {"gravite": gravite, "titre": "t", "detail": ""}


class TestNormalisation(unittest.TestCase):
    def n(self, s, famille="codex"):
        return revue.normaliser_verdict(famille, s)

    def test_enumeration_exacte(self):
        self.assertEqual(revue.VERDICTS, ("FAVORABLE", "DEFAVORABLE", "INDETERMINE"))
        for nom in ("sortie-relecteur", "attestation-revue"):
            self.assertEqual(revue.schema(nom)["properties"]["verdict"]["enum"], list(revue.VERDICTS))

    def test_verdicts_conformes(self):
        for v in ("FAVORABLE", "DEFAVORABLE"):
            verdict, motif, rapport = self.n(sortie(verdict=v))
            self.assertEqual((verdict, motif), (v, None))
            self.assertEqual(len(rapport), 64)
        self.assertEqual(self.n(sortie(constats=[constat("mineur"), constat("info")]))[:2], ("FAVORABLE", None))

    def test_ancien_verdict_avec_corrections_invalide(self):
        self.assertEqual(self.n(sortie(verdict="FAVORABLE_AVEC_CORRECTIONS"))[:2], ("INDETERMINE", "sortie_invalide"))

    def test_favorable_avec_constat_bloquant_ou_majeur(self):
        for g in ("bloquant", "majeur"):
            self.assertEqual(self.n(sortie(constats=[constat("info"), constat(g)]))[:2],
                             ("INDETERMINE", "favorable_incoherent"), g)

    def test_defavorable_avec_constat_bloquant_conserve(self):
        self.assertEqual(self.n(sortie(verdict="DEFAVORABLE", constats=[constat("bloquant")]))[0], "DEFAVORABLE")

    def test_indetermine_du_relecteur(self):
        self.assertEqual(self.n(sortie(verdict="INDETERMINE"))[:2], ("INDETERMINE", "relecteur"))

    def test_factice_ne_rend_jamais_favorable(self):
        self.assertEqual(self.n(sortie(), famille="factice"), ("INDETERMINE", "relecteur_factice", None))

    def test_faux_json_favorable_dans_un_diff(self):
        """Un relecteur qui recracherait le diff (contenant un JSON favorable)
        ne produit jamais un verdict : le diff entier n'est pas une sortie conforme."""
        diff = (b"diff --git a/x b/x\n+++ b/x\n+" + sortie() + b"\n")
        self.assertEqual(self.n(diff)[:2], ("INDETERMINE", "sortie_invalide"))

    def test_sorties_invalides(self):
        cas = {
            "vide": b"", "texte": b"FAVORABLE", "casse": sortie(verdict="favorable"),
            "espace": sortie(verdict="FAVORABLE "), "accent": sortie(verdict="DÉFAVORABLE"),
            "inconnu": sortie(verdict="APPROUVE"), "cle_en_plus": sortie(signature="x"),
            "constats_absents": json.dumps({"verdict": "FAVORABLE"}).encode(), "tronque": sortie()[:-3],
            "doublon": b'{"verdict":"DEFAVORABLE","verdict":"FAVORABLE","constats":[]}',
            "binaire": b"\xff\xfe", "liste": b'["FAVORABLE"]',
            "gravite_inconnue": sortie(constats=[constat("critique")]),
        }
        for nom, s in cas.items():
            self.assertEqual(self.n(s)[:2], ("INDETERMINE", "sortie_invalide"), nom)


if __name__ == "__main__":
    unittest.main()

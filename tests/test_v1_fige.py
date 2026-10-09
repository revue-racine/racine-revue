"""Artefacts revue/1 figés : chaque octet du contrat v1 (protocole, schémas,
politique, ancres, règles, producteur, vérificateur, pont, registre) est
épinglé à son état de la base 8ba07c61fc47e284c86dc2b8e832624036947b14.
Remplacer silencieusement un contrat v1 par v2 fait échouer cette suite.

Le harnais de mutations exclut ce fichier : une mutation du v1 doit être
attrapée par un test de comportement, pas par une empreinte."""
import hashlib
import unittest

import aide

FIGES = (
    ("protocol/revue-v1.md", "90fd0576512f6d18353143765acfe45b0ee99c988c06f524151f0e33e6cd30d5"),
    ("schemas/ancres-v1.schema.json", "f33f8d64fb807c376cee7fda62e21d03e2d03d3a326599c83b4379cb1e42fdab"),
    ("schemas/attestation-revue-v1.schema.json", "c39ade0adae44c70ff2847d95d7756ab67535715e015fd07278b600e6a628d88"),
    ("schemas/demande-v1.schema.json", "ab2636579e87f57eafacf03a9a380d0a9ca3e5295cc62dc7cf1b5257195baf2f"),
    ("schemas/politique-v1.schema.json", "4bd94080734e13d5d063d87892c2d3a3440fe188490cc3938a9d1119eea55343"),
    ("schemas/sortie-relecteur-v1.schema.json", "4aefc7ae58647a10f6f096a3c3cc70a7deccb873a7a583990b1059dd7dda7e8e"),
    ("schemas/sujet-revue-v1.schema.json", "a7e28a72e4b11f4bfe7ac20a9032998018fd062b45e0eb095ff71f0bd7810d49"),
    ("policy/confiance-v1.json", "c004a7e5a074b5d0374d1906e19b645f9456e646c32f8c73e26487d6178ea284"),
    ("policy/ancres-v1.json", "90f14c963a4141465c1c006c51e6fa387fc1073cd3239c2689042f1121db428d"),
    ("policy/rulesets/etiquettes-immuables.json", "357dd8da8be9b39b69a47baca4753d130646edcbf42c27b728dde38903014948"),
    ("policy/rulesets/main-protege.json", "3c65c787e26c5f2db6e2a07a233d3633d230bf25e5d2f7ccdea83eda95470f46"),
    ("outils/revue.py", "22d1ea349ce97ea9718bac390f195a3d61ea370b0bea865c39764ee0183a6a9e"),
    ("outils/verifier.py", "89bc97c03ad95f2784dc0b73bf113dbcfa21a1de7d0b0872fe7b70a66aa6397e"),
    ("outils/schema_strict.py", "3a280dd9fe7def6f47fde604ceb4ec2c51257893e3ee3183d8e5ad635dd8cabe"),
    ("outils/snappy_bloc.py", "e48c18d1ec77d8419d977c650cd81a6d2fd07ca26d8715ca8a8d3492e9ce58a4"),
    ("outils/pont_p1.py", "20bbec7e982dec25557b74f0356c1213742287a6d380ae67d77b91f953eb700c"),
    ("outils/registre.py", "f9937cbd90e0bc19ffbbd086ef690d7e23a5e44965c8cb5294df144b0659f32c"),
)


class TestV1Fige(unittest.TestCase):
    def test_artefacts_v1_identiques_octet_pour_octet(self):
        for chemin, attendu in FIGES:
            with self.subTest(chemin=chemin):
                self.assertEqual(hashlib.sha256((aide.RACINE / chemin).read_bytes()).hexdigest(), attendu)

    def test_inventaire_v1_complet(self):
        v1 = {p.relative_to(aide.RACINE).as_posix() for p in (aide.RACINE / "schemas").glob("*-v1.schema.json")}
        self.assertTrue(v1 <= {c for c, _ in FIGES})


if __name__ == "__main__":
    unittest.main()

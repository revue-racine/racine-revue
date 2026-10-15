"""Empreintes du socle antérieur au Lot 3A.1, calculées sur abf3fed069f2.

Toute variation d'un artefact v1/v2, d'une primitive partagée, du pont P1 ou du
workflow de revue fait échouer cette suite.
"""
import hashlib
import unittest

import aide


FIGES = (
    ("protocol/revue-v1.md", "90fd0576512f6d18353143765acfe45b0ee99c988c06f524151f0e33e6cd30d5"),
    ("protocol/revue-v2.md", "f2af216ef893be89dab5722136bae79a5ad409fe71aec3d50d8504ed51f8e914"),
    ("policy/confiance-v1.json", "c004a7e5a074b5d0374d1906e19b645f9456e646c32f8c73e26487d6178ea284"),
    ("policy/confiance-v2.json", "bd23e75d439d34568dc4a6838329e8e8653f8ff0401620cabda50609632bd834"),
    ("policy/ancres-v1.json", "90f14c963a4141465c1c006c51e6fa387fc1073cd3239c2689042f1121db428d"),
    ("schemas/ancres-v1.schema.json", "f33f8d64fb807c376cee7fda62e21d03e2d03d3a326599c83b4379cb1e42fdab"),
    ("schemas/attestation-revue-v1.schema.json", "c39ade0adae44c70ff2847d95d7756ab67535715e015fd07278b600e6a628d88"),
    ("schemas/demande-v1.schema.json", "ab2636579e87f57eafacf03a9a380d0a9ca3e5295cc62dc7cf1b5257195baf2f"),
    ("schemas/politique-v1.schema.json", "4bd94080734e13d5d063d87892c2d3a3440fe188490cc3938a9d1119eea55343"),
    ("schemas/sortie-relecteur-v1.schema.json", "4aefc7ae58647a10f6f096a3c3cc70a7deccb873a7a583990b1059dd7dda7e8e"),
    ("schemas/sujet-revue-v1.schema.json", "a7e28a72e4b11f4bfe7ac20a9032998018fd062b45e0eb095ff71f0bd7810d49"),
    ("schemas/attestation-revue-v2.schema.json", "291937193084df9cc08b019f675994a2448667d306aa59d32c2cdd4916dcd589"),
    ("schemas/politique-v2.schema.json", "80e72e25dff056d9dbe761a83aea1e2bc350bccdc74384c0e8930d40a6ec89de"),
    ("schemas/sujet-revue-v2.schema.json", "67d4929be8d4132ae9c3f571765d70fd5960bc787da00a65ac7f6321f5cc11d3"),
    ("outils/consigne-relecteur-v2.txt", "19e164ae8e8d25523aea17e140820177c01512a6adcf1d0561106d797a8282b2"),
    ("outils/relecteur_openai.py", "c2ce3e1844dda978f461b2aad98bf47af5bc7c260d7b48199740af86d4b4a0e2"),
    ("outils/revue.py", "22d1ea349ce97ea9718bac390f195a3d61ea370b0bea865c39764ee0183a6a9e"),
    ("outils/revue2.py", "10b665d2d145f655a2b13d0a2b0b877a52e80195ad642beff4f25c822c899b94"),
    ("outils/verifier.py", "89bc97c03ad95f2784dc0b73bf113dbcfa21a1de7d0b0872fe7b70a66aa6397e"),
    ("outils/verifier2.py", "89400a75a2e360f11de4e06a90883eb710b37808280e7432ce3b305ea0cbd160"),
    ("outils/schema_strict.py", "3a280dd9fe7def6f47fde604ceb4ec2c51257893e3ee3183d8e5ad635dd8cabe"),
    ("outils/snappy_bloc.py", "e48c18d1ec77d8419d977c650cd81a6d2fd07ca26d8715ca8a8d3492e9ce58a4"),
    ("outils/registre.py", "f9937cbd90e0bc19ffbbd086ef690d7e23a5e44965c8cb5294df144b0659f32c"),
    ("outils/pont_p1.py", "20bbec7e982dec25557b74f0356c1213742287a6d380ae67d77b91f953eb700c"),
    (".github/workflows/revue.yml", "f749d99b1ccd7950b802b7bfc8678266394220c13dff97a8682724db21e27f98"),
)


class TestIntangibiliteV3(unittest.TestCase):
    def test_octets_du_socle_anterieur_inchanges(self):
        for chemin, attendu in FIGES:
            with self.subTest(chemin=chemin):
                obtenu = hashlib.sha256((aide.RACINE / chemin).read_bytes()).hexdigest()
                self.assertEqual(obtenu, attendu)

    def test_workflow_ne_reference_pas_revue3(self):
        workflow = (aide.RACINE / ".github/workflows/revue.yml").read_text("utf-8")
        self.assertNotIn("revue3", workflow)
        self.assertNotIn("revue/3", workflow)


if __name__ == "__main__":
    unittest.main()

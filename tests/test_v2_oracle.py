"""Vecteurs critiques confrontés à un oracle indépendant (tests/oracle_v2.py)
et à des empreintes calculées hors de Python (`printf | sha256sum`)."""
import os
import unittest

import aide
from aide import revue
import aide_v2
import oracle_v2
import revue2

# Calculées par `printf '%s' '<octets>' | sha256sum`, hors de tout code du dépôt.
VECTEURS_CANONIQUES = (
    ({"b": 1, "a": [True, None, "é\n\"\\\u0001"], "é": {}},
     b'{"a":[true,null,"\xc3\xa9\\n\\"\\\\\\u0001"],"b":1,"\xc3\xa9":{}}',
     "2f9488f63f3e1f2ecc78b46bf7c8145718ce2ab0110eca05a0e0213ee8184ed9"),
    ({"ü": "\t", "z": -7, "format": "olistic.confiance.sujet-revue/2"},
     b'{"format":"olistic.confiance.sujet-revue/2","z":-7,"\xc3\xbc":"\\t"}',
     "5dba57007175994e11576e65d945cdb8559d77c4850cba0d1a9eb5329bfcc35c"),
)


class TestOracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cand = aide.DepotCandidat()
        c = cls.cand
        # Cas difficiles : suppression, changement de mode, binaire, nom non ASCII, lien symbolique.
        (c.chemin / "a.txt").unlink()
        (c.chemin / "bin.dat").write_bytes(bytes(range(256)) * 4)
        (c.chemin / "é è.txt").write_text("unicode\n")
        (c.chemin / "lien").symlink_to("b/danger.sh")
        os.chmod(c.chemin / "b" / "danger.sh", 0o755)
        aide.git(c.chemin, "add", "-A")
        aide.git(c.chemin, "commit", "-q", "-m", "c4")
        cls.c4 = aide.git(c.chemin, "rev-parse", "HEAD")
        (c.chemin / "lien").unlink()
        (c.chemin / "lien").write_text("devenu fichier\n")
        aide.git(c.chemin, "add", "-A")
        aide.git(c.chemin, "commit", "-q", "-m", "c5")
        cls.c5 = aide.git(c.chemin, "rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls):
        cls.cand.nettoyer()

    def test_canonique_contre_sha256sum(self):
        for obj, octets, empreinte in VECTEURS_CANONIQUES:
            self.assertEqual(oracle_v2.canonique(obj), octets)
            self.assertEqual(revue.canonique(obj), octets)
            self.assertEqual(oracle_v2.digest(obj), empreinte)
            self.assertEqual(revue.sha256_hex(revue.canonique(obj)), empreinte)

    def test_canonique_concorde_sur_des_valeurs_variees(self):
        valeurs = [{}, [], {"": ""}, {"a": {"b": {"c": [1, -1, 0, 10 ** 18]}}}, {" ": "\u0000\u001f\u007f"},
                   {"Z": 1, "a": 2, "É": 3, "e": 4}, ["퟿", "\U0001f600"]]
        for v in valeurs:
            self.assertEqual(oracle_v2.canonique(v), revue.canonique(v), v)

    def test_sujet_v2_identique_a_l_oracle(self):
        c = self.cand
        for pointe in (c.c2, c.c3, self.c4, self.c5):
            with self.subTest(pointe=pointe):
                produit = aide_v2.sujet_v2_pour(c, pointe)
                attendu = oracle_v2.sujet(c.chemin, c.c1, pointe, "candidat", aide.CANDIDAT_ID)
                self.assertEqual(produit, attendu)
                self.assertEqual(revue.sha256_hex(revue.canonique(produit)), oracle_v2.digest(attendu))
                self.assertEqual(revue2.nom_sujet(produit, aide.RID), oracle_v2.nom(attendu, aide.RID))

    def test_format_du_sujet_v2_distinct_du_v1(self):
        """Le sujet produit porte le format v2 du protocole, que l'oracle écrit en
        dur : un sujet au format v1 aurait le digest d'une attestation v1."""
        c = self.cand
        produit = aide_v2.sujet_v2_pour(c, c.c3)
        self.assertEqual(produit["format"], "olistic.confiance.sujet-revue/2")
        self.assertEqual(oracle_v2.digest(produit),
                         oracle_v2.digest(oracle_v2.sujet(c.chemin, c.c1, c.c3, "candidat", aide.CANDIDAT_ID)))

    def test_sujet_v1_identique_a_l_oracle_et_digest_distinct(self):
        c = self.cand
        v1 = aide.sujet_pour(c, c.c3)
        o1 = oracle_v2.sujet(c.chemin, c.c1, c.c3, "candidat", aide.CANDIDAT_ID, "olistic.confiance.sujet-revue/1")
        self.assertEqual(v1, o1)
        self.assertNotEqual(oracle_v2.digest(o1), oracle_v2.digest(aide_v2.sujet_v2_pour(c, c.c3)))

    def test_perimetre_avec_changement_de_type_et_de_mode(self):
        """c4..c5 : lien symbolique devenu fichier (statut T) ; c3..c4 :
        suppression, ajout binaire, nom non ASCII, changement de mode."""
        import tempfile
        from pathlib import Path
        c = self.cand
        with tempfile.TemporaryDirectory() as tmp:
            git = revue.Git(Path(tmp) / "g", ("file",))
            git("fetch", "--quiet", "--no-tags", str(c.chemin), c.c3, self.c4, self.c5)
            for base, pointe in ((self.c4, self.c5), (c.c3, self.c4), (c.c3, self.c5)):
                self.assertEqual(revue.empreinte_perimetre(git, base, pointe),
                                 oracle_v2.perimetre_sha256(c.chemin, base, pointe), (base, pointe))
            statuts = git("diff-tree", "-r", "--no-renames", "--name-status", self.c4, self.c5).stdout
            self.assertIn(b"T\tlien", statuts)

    def test_l_oracle_detecte_une_erreur_de_perimetre(self):
        c = self.cand
        produit = aide_v2.sujet_v2_pour(c, self.c4)
        self.assertNotEqual(produit["perimetre_sha256"], oracle_v2.perimetre_sha256(c.chemin, c.c1, c.c3))


if __name__ == "__main__":
    unittest.main()

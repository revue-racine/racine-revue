"""Contenu du bundle public : inventaire fermé, aucun secret, aucune adresse,
aucun oracle de nom interne (liste de contrôle tenue hors du dépôt)."""
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import aide

AUTORISES = {
    "README.md", "BOOTSTRAP.md", "SECURITY.md",
    ".github/workflows/revue.yml", ".github/workflows/controles.yml",
    "protocol/revue-v1.md",
    "policy/confiance-v1.json", "policy/ancres-v1.json", "policy/parametres-depot.md",
    "policy/rulesets/main-protege.json", "policy/rulesets/etiquettes-immuables.json",
    "schemas/demande-v1.schema.json", "schemas/sujet-revue-v1.schema.json",
    "schemas/sortie-relecteur-v1.schema.json", "schemas/attestation-revue-v1.schema.json",
    "schemas/politique-v1.schema.json", "schemas/ancres-v1.schema.json",
    "outils/schema_strict.py", "outils/revue.py", "outils/verifier.py", "outils/pont_p1.py",
    "outils/registre.py", "outils/snappy_bloc.py", "tests/mutations.py",
    "tests/requirements.txt", "tests/installer-actionlint.sh", "tests/controle_noms.py",
}
MOTIFS_SECRETS = [
    r"ghp_[A-Za-z0-9]{20,}", r"github_pat_[A-Za-z0-9_]{20,}", r"gh[osu]_[A-Za-z0-9]{20,}",
    r"sk-[A-Za-z0-9_-]{20,}", r"ntn_[A-Za-z0-9]{20,}", r"secret_[A-Za-z0-9]{30,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"xox[abp]-[A-Za-z0-9-]{10,}", r"AKIA[0-9A-Z]{16}",
    r"\b\d{9,10}:[A-Za-z0-9_-]{35}\b", r"AAAA[A-Za-z0-9+/]{60,}",
]


def fichiers():
    for p in aide.RACINE.rglob("*"):
        rel = p.relative_to(aide.RACINE).as_posix()
        if rel == ".git" or rel.startswith(".git/"):
            continue  # métadonnées du checkout (CI comprise), pas le contenu publié
        if p.is_file() and "__pycache__" not in rel:
            yield rel, p


class TestBundle(unittest.TestCase):
    def test_inventaire_ferme(self):
        rel = {r for r, _ in fichiers()}
        hors = {r for r in rel if not (r in AUTORISES or re.fullmatch(r"tests/(aide|test_[a-z0-9_]+)\.py", r))}
        self.assertEqual(hors, set())
        self.assertEqual(AUTORISES - rel, set())

    def test_aucun_secret_ni_cle(self):
        for rel, p in fichiers():
            texte = p.read_text("utf-8", errors="replace")
            for m in MOTIFS_SECRETS:
                self.assertIsNone(re.search(m, texte), f"{rel}: {m}")

    def test_aucune_adresse_mail(self):
        for rel, p in fichiers():
            self.assertIsNone(re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", p.read_text("utf-8", errors="replace")), rel)

    def test_aucune_empreinte_de_nom(self):
        """Aucune liste d'empreintes sha256 ne figure dans les tests : une
        empreinte non salée d'un nom court est un oracle de confirmation."""
        for rel, p in fichiers():
            if rel.startswith("tests/"):
                self.assertNotRegex(p.read_text("utf-8"), r'"[0-9a-f]{64}",\n', rel)

    def test_git_racine_ignore_contenu_toujours_controle(self):
        mail = "runner" + "@" + "exemple.org\n"
        jeton = "ghp_" + "A" * 24 + "\n"
        with tempfile.TemporaryDirectory() as tmp:
            racine = Path(tmp)
            for rel in AUTORISES | {"tests/aide.py"}:
                (racine / rel).parent.mkdir(parents=True, exist_ok=True)
                (racine / rel).write_text("rien\n")
            (racine / ".git/logs").mkdir(parents=True)
            (racine / ".git/logs/HEAD").write_text(mail + jeton)
            controles = (self.test_inventaire_ferme, self.test_aucune_adresse_mail, self.test_aucun_secret_ni_cle)
            with mock.patch.object(aide, "RACINE", racine):
                for controle in controles:
                    controle()  # le même motif sous .git/ est ignoré
                (racine / "README.md").write_text(mail + jeton)
                for controle in controles[1:]:
                    with self.subTest(controle=controle.__name__), self.assertRaises(self.failureException):
                        controle()
                (racine / "sous/.git").mkdir(parents=True)
                (racine / "sous/.git/HEAD").write_text("rien\n")
                with self.assertRaises(self.failureException):
                    self.test_inventaire_ferme()  # seul le .git/ de la racine est exclu

    def test_controle_noms_detecte_et_ne_publie_rien(self):
        with tempfile.TemporaryDirectory() as tmp:
            racine = Path(tmp) / "b"
            racine.mkdir()
            (racine / "x.md").write_text("Le dépôt NomInterne-Secret est cité ici.\n")
            liste = Path(tmp) / "liste"
            liste.write_text("nominterne-secret\n")
            r = subprocess.run([sys.executable, str(aide.RACINE / "tests/controle_noms.py"), str(liste), str(racine)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertNotIn("nominterne", r.stdout.lower())
            (racine / "x.md").write_text("rien\n")
            r = subprocess.run([sys.executable, str(aide.RACINE / "tests/controle_noms.py"), str(liste), str(racine)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()

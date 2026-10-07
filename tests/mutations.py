#!/usr/bin/env python3
"""Harnais de mutations des contrôles de sécurité essentiels.

Chaque mutation est appliquée à une copie jetable du dépôt ; la suite complète
doit alors échouer. Sortie 0 si toutes les mutations sont détectées, 1 si une
survit ou si un motif n'est plus trouvé (le harnais refuse de se taire).

    python3 tests/mutations.py
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent

MUTATIONS = [
    # Régressions trouvées par Codex (contre-relecture finale)
    ("login réintroduit dans le dédoublonnage", "outils/revue.py",
     'and user.get("type") == "User" and user.get("id") in autorises)',
     'and user.get("type") == "User" and user.get("login") == "operateur")'),
    ("filtre `creator` réintroduit dans l'appel d'historique", "outils/revue.py",
     '{"state": "all", "sort": "created"', '{"state": "all", "creator": "operateur", "sort": "created"'),
    ("API de signature acceptant une Decision forgée", "outils/pont_p1.py",
     "def _clore_en_echec(registre, request_id, liaison, motif):",
     "def signer_decision(decision, config):\n    return decision\n\n\ndef _clore_en_echec(registre, request_id, liaison, motif):"),
    # Consommation et atomicité
    ("réservation sautée", "outils/pont_p1.py", "    registre.reserver(request_id, liaison)  # point de non-retour",
     "    pass  # point de non-retour"),
    ("registre facultatif", "outils/pont_p1.py",
     "if not isinstance(registre, registre_mod.RegistreConsommation):", "if registre is None:"),
    ("contrôle de substitution sauté", "outils/pont_p1.py",
     "        registre.controler_reservation(request_id, liaison)", "        pass"),
    ("réservation non exclusive", "outils/registre.py",
     'if not self._t.creer_ref(_ref(rid, "reserve"), contenu):',
     'self._t.creer_ref(_ref(rid, "reserve"), contenu)\n        if False:'),
    ("signature sans décision acceptée", "outils/pont_p1.py",
     'if not decision.acceptee or decision["verdicts"].count("FAVORABLE") != 1 or "DEFAVORABLE" in decision["verdicts"]:',
     'if not decision.get("verdicts"):'),
    # bundle_url
    ("repli sur un bundle en ligne", "outils/verifier.py",
     'u = a.get("bundle_url") if isinstance(a, dict) else None',
     'u = (a.get("bundle_url") or "https://api.github.com/en-ligne") if isinstance(a, dict) else None'),
    ("hôte de bundle non contrôlé", "outils/verifier.py",
     "and any(hote.endswith(s) for s in SUFFIXES_HOTES_BUNDLE))", ")"),
    # Contrôles antérieurs, toujours essentiels
    ("base reprise de la demande", "outils/revue.py", 'base, pointe = ancre["commit"], demande["pointe"]',
     'base, pointe = demande.get("base", ancre["commit"]), demande["pointe"]'),
    ("gitlink accepté dans l'arbre", "outils/revue.py",
     'if typ == b"commit" or mode == b"160000":\n            raise Refus("gitlink_refuse")',
     'if False:\n            raise Refus("gitlink_refuse")'),
    ("relecteur non acceptable accepté", "outils/verifier.py", 'if not rel["acceptable"]:', "if False:"),
    ("coupure ignorée", "outils/verifier.py", 'if t < revue.instant_utc(f["coupure"]):', "if False:"),
    ("_type in-toto ignoré", "outils/verifier.py", "if enonce.get(\"_type\") != TYPE_INTOTO:", "if False:"),
]


def lancer(dossier):
    r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"], cwd=dossier,
                       capture_output=True, text=True, timeout=900)
    return r.returncode


def main():
    if lancer(RACINE) != 0:
        print("la suite non mutée échoue : harnais inutilisable")
        return 1
    survivantes = 0
    for nom, fichier, avant, apres in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="mutation-") as tmp:
            copie = Path(tmp) / "b"
            shutil.copytree(RACINE, copie, ignore=shutil.ignore_patterns("__pycache__"))
            cible = copie / fichier
            texte = cible.read_text("utf-8")
            if texte.count(avant) != 1:
                print(f"MOTIF INTROUVABLE  {nom}")
                survivantes += 1
                continue
            cible.write_text(texte.replace(avant, apres), "utf-8")
            detectee = lancer(copie) != 0
        survivantes += not detectee
        print(f"{'détectée ' if detectee else 'SURVIVANTE'}  {nom}")
    print(f"{len(MUTATIONS) - survivantes}/{len(MUTATIONS)} mutations détectées")
    return 1 if survivantes else 0


if __name__ == "__main__":
    sys.exit(main())

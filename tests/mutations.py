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
    # revue/2 — relecteur openai-responses : transport
    ("v2 : minuterie murale supprimée", "outils/relecteur_openai.py",
     "                signal.setitimer(signal.ITIMER_REAL, delai_total)", "                pass"),
    ("v2 : format de clé non vérifié", "outils/relecteur_openai.py",
     "    if FORMAT_CLE.fullmatch(cle) is None:", "    if False:"),
    ("v2 : échec de la minuterie non codé", "outils/relecteur_openai.py",
     '                raise revue.Refus("relecteur_minuterie")', "                raise"),
    ("v2 : plafond de taille supprimé", "outils/relecteur_openai.py",
     "                if total > taille_max:", "                if False:"),
    ("v2 : redirection traitée comme un succès", "outils/relecteur_openai.py",
     "            if statut != 200:", "            if statut >= 400:"),
    ("v2 : Content-Encoding ignoré", "outils/relecteur_openai.py",
     '            if (rep.getheader("Content-Encoding") or "identity").strip().lower() != "identity":',
     "            if False:"),
    ("v2 : clé reprise dans une erreur", "outils/relecteur_openai.py",
     '            raise revue.Refus("relecteur_connexion")', '            raise revue.Refus("relecteur_connexion", cle)'),
    ("v2 : TLS non vérifié", "outils/relecteur_openai.py",
     "    ctx = ssl.create_default_context()", "    ctx = ssl._create_unverified_context()"),
    # revue/2 : enveloppe
    ("v2 : contrôle du modèle supprimé", "outils/relecteur_openai.py",
     '    if env.get("model") != modele:', "    if False:"),
    ("v2 : statut incomplet accepté", "outils/relecteur_openai.py",
     '    if env.get("status") != "completed":', '    if env.get("status") not in ("completed", "incomplete"):'),
    ("v2 : appel d'outil accepté", "outils/relecteur_openai.py",
     '        if t not in ("message", "reasoning"):', '        if t not in ("message", "reasoning", "function_call"):'),
    ("v2 : refus du modèle accepté", "outils/relecteur_openai.py",
     '            if tp == "refusal":', "            if False:"),
    ("v2 : plusieurs textes acceptés", "outils/relecteur_openai.py",
     "    if len(textes) != 1:", "    if not textes:"),
    ("v2 : erreur d'enveloppe convertie en INDETERMINE", "outils/relecteur_openai.py",
     "    return analyser_enveloppe(appeler(cle, corps, connexion), modele)",
     "    try:\n        return analyser_enveloppe(appeler(cle, corps, connexion), modele)\n"
     "    except revue.Refus:\n        return b\"\""),
    # revue/2 : requête et projection
    ("v2 : stockage fournisseur activé", "outils/relecteur_openai.py",
     '        "store": False,', '        "store": True,'),
    ("v2 : outil déclaré dans la requête", "outils/relecteur_openai.py",
     '        "store": False,', '        "store": False, "tools": [{"type": "web_search"}],'),
    ("v2 : borne d'encadrement constante", "outils/relecteur_openai.py",
     '    borne = "DIFF-" + revue.sha256_hex(diff)', '    borne = "DIFF"'),
    ("v2 : minLength conservé dans la projection", "outils/relecteur_openai.py",
     'SUPPRIMES = frozenset({"$schema", "$id", "title", "description", "minLength", "maxLength"})',
     'SUPPRIMES = frozenset({"$schema", "$id", "title", "description", "maxLength"})\n'
     'CONSERVES = CONSERVES | {"minLength"}'),
    # revue/2 : producteur
    ("v2 : sujet au format v1", "outils/revue2.py",
     'FORMAT_SUJET = "olistic.confiance.sujet-revue/2"', 'FORMAT_SUJET = "olistic.confiance.sujet-revue/1"'),
    ("v2 : clé non exigée avant tout calcul", "outils/revue2.py", "            if not cle:", "            if False:"),
    ("v2 : clé laissée dans l'environnement", "outils/revue2.py",
     "        cle = os.environ.pop(VARIABLE_CLE, \"\")", "        cle = os.environ.get(VARIABLE_CLE, \"\")"),
    ("v2 : acceptable forcé dans le prédicat", "outils/revue2.py",
     '"acceptable": rel["acceptable"]}', '"acceptable": True}'),
    ("v2 : invariant acceptable du producteur supprimé", "outils/revue2.py",
     '    if predicat["relecteur"]["acceptable"] is not r["acceptable"]:', "    if False:"),
    ("v2 : portée consultative retirée de la réponse", "outils/revue2.py",
     '    if not rel["acceptable"]:', "    if False:"),
    # revue/2 : vérificateur candidat
    ("v2 : relecteur non acceptable accepté", "outils/verifier2.py", '    if not rel["acceptable"]:', "    if False:"),
    ("v2 : acceptable lu dans le prédicat", "outils/verifier2.py",
     '    if predicat["relecteur"]["acceptable"] is not rel["acceptable"]:', "    if False:"),
    # revue/2 : workflow
    ("v2 : secret exposé au job de signature", ".github/workflows/revue.yml",
     "          PREDICAT: ${{ needs.revue.outputs.predicat }}",
     "          PREDICAT: ${{ needs.revue.outputs.predicat }}\n          CLE_RELECTEUR: ${{ secrets.CLE_RELECTEUR_OPENAI }}"),
    ("v2 : producteur v1 rappelé par le workflow", ".github/workflows/revue.yml",
     "run: python3 -I outils/revue2.py preparer", "run: python3 -I outils/revue.py preparer"),
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
            # L'épinglage des octets v1 (test_v1_fige) attraperait toute mutation du v1 :
            # il est exclu ici pour que chaque mutation soit attrapée par un test de comportement.
            shutil.copytree(RACINE, copie, ignore=shutil.ignore_patterns("__pycache__", ".git", "test_v1_fige.py"))
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

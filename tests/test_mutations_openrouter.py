#!/usr/bin/env python3
"""Harnais de mutations causales des protections ajoutées par le Lot 3A.2."""
import re
import tempfile
from pathlib import Path

import mutations as commun


RACINE = Path(__file__).resolve().parent.parent
MUTATIONS = (
    (
        "ZDR désactivé",
        "outils/relecteur_openrouter.py",
        '"zdr": True,',
        '"zdr": False,',
        "test_v3_openrouter_contrat.TestContratOpenRouter.test_zdr_collecte_fallback_et_epinglage_sont_explicites",
    ),
    (
        "refus du fallback désactivé",
        "outils/relecteur_openrouter.py",
        '"allow_fallbacks": False,',
        '"allow_fallbacks": True,',
        "test_v3_openrouter_contrat.TestContratOpenRouter.test_zdr_collecte_fallback_et_epinglage_sont_explicites",
    ),
    (
        "épinglage fournisseur neutralisé",
        "outils/relecteur_openrouter.py",
        '"only": [configuration.endpoint_fournisseur],',
        '"only": [],',
        "test_v3_openrouter_contrat.TestContratOpenRouter.test_zdr_collecte_fallback_et_epinglage_sont_explicites",
    ),
    (
        "exigence des paramètres neutralisée",
        "outils/relecteur_openrouter.py",
        '"require_parameters": True,',
        '"require_parameters": False,',
        "test_v3_openrouter_contrat.TestContratOpenRouter.test_zdr_collecte_fallback_et_epinglage_sont_explicites",
    ),
    (
        "collecte autorisée",
        "outils/relecteur_openrouter.py",
        '"data_collection": "deny",',
        '"data_collection": "allow",',
        "test_v3_openrouter_contrat.TestContratOpenRouter.test_zdr_collecte_fallback_et_epinglage_sont_explicites",
    ),
    (
        "précontrôle budgétaire sauté",
        "outils/relecteur_openrouter.py",
        "        controler_budget(budget.corps, config)",
        "        pass  # précontrôle neutralisé",
        "test_v3_openrouter_budget.TestBudgetOpenRouter.test_echec_du_precontrole_interdit_l_inference",
    ),
    (
        "transport réel admis",
        "outils/relecteur_openrouter.py",
        "    if isinstance(transport, transport_http.TransportHTTPS):",
        "    if False:",
        "test_v3_openrouter_contrat.TestContratOpenRouter.test_transport_reel_refuse_avant_tout_appel",
    ),
    (
        "gestionnaire de contexte arbitraire admis comme verrou",
        "outils/relecteur_openrouter.py",
        "    if type(serialiseur) is not SerialiseurFichier:",
        "    if False:",
        "test_v3_openrouter_securite.TestSecuriteOpenRouter.test_nullcontext_et_gestionnaire_fictif_sont_refuses_sans_appel",
    ),
    (
        "preuve d'acquisition du verrou neutralisée",
        "outils/relecteur_openrouter.py",
        "    if not serialiseur.verrou_acquis():",
        "    if False:",
        "test_v3_openrouter_securite.TestSecuriteOpenRouter.test_verrou_non_acquis_est_refuse_sans_appel",
    ),
    (
        "résultat rendu acceptable",
        "outils/relecteur_openrouter.py",
        "    acceptable_future: bool = False",
        "    acceptable_future: bool = True",
        "test_v3_openrouter_contrat.TestContratOpenRouter.test_nominal_reste_simule_non_acceptable_et_non_autorisant",
    ),
    (
        "résultat rendu autorisant",
        "outils/relecteur_openrouter.py",
        "    autorisante: bool = False",
        "    autorisante: bool = True",
        "test_v3_openrouter_contrat.TestContratOpenRouter.test_nominal_reste_simule_non_acceptable_et_non_autorisant",
    ),
)


def remplacer(chemin, avant, apres):
    texte = chemin.read_text("utf-8")
    if texte.count(avant) != 1:
        raise RuntimeError("motif de mutation absent ou ambigu")
    chemin.write_text(texte.replace(avant, apres), "utf-8")


def main():
    causaux = sorted({m[4] for m in MUTATIONS})
    with tempfile.TemporaryDirectory(prefix="mutation-openrouter-") as tmp:
        copie = Path(tmp) / "base"
        commun.copier(copie)
        rc, sortie = commun.lancer(copie, causaux)
    if rc != 0 or not re.search(r"^Ran %d tests?" % len(causaux), sortie, re.M):
        print("tests causaux en échec ou absents sans mutation")
        print(sortie[-2000:])
        return 1
    print(f"contrôle préalable : {len(causaux)} tests causaux verts sans mutation")
    mauvaises = 0
    for nom, fichier, avant, apres, causal in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="mutation-openrouter-") as tmp:
            copie = Path(tmp) / "base"
            commun.copier(copie)
            remplacer(copie / fichier, avant, apres)
            rc, sortie = commun.lancer(copie, [causal])
        etat, detail = commun.classer(rc, sortie, causal, None)
        print(f"{etat} {nom}: {detail}")
        mauvaises += etat.strip() != "détectée"
    print(f"mutations détectées : {len(MUTATIONS) - mauvaises}/{len(MUTATIONS)}")
    return 1 if mauvaises else 0


if __name__ == "__main__":
    raise SystemExit(main())

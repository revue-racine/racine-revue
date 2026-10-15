"""Objets synthétiques revue/3 pour les tests hors ligne."""
import copy
import datetime
import json
import tempfile
from pathlib import Path

import aide
from aide import revue
import revue3


def politique_v3_ancree():
    """Copie de la politique effectivement livrée, sans substitution de test."""
    return json.loads((aide.RACINE / "policy/confiance-v3.json").read_text("utf-8"))


def admis_v3(request_id=aide.RID, issue=7, classe="B", auteur="codex"):
    return {
        "demande": aide.demande(
            "c" * 40,
            alias="auto-test",
            request_id=request_id,
            classe=classe,
            auteur=auteur,
        ),
        "issue": issue,
        "demandeur_id": 241122414,
    }


def sujet_v3_pour(candidat, pointe, politique=None):
    politique = politique or politique_v3_ancree()
    demande = aide.demande(pointe, alias="auto-test", classe="B", auteur="codex")
    ancres = {
        "auto-test": {
            "alias": "auto-test",
            "commit": candidat.c1,
            "objet_sha256": aide.objet_sha256(candidat.chemin, candidat.c1),
        }
    }
    with tempfile.TemporaryDirectory() as tmp:
        sujet, _ = revue3.calculer_sujet(
            demande,
            politique,
            ancres,
            str(candidat.chemin),
            Path(tmp) / "git",
            protocoles=("file",),
        )
    return sujet


def predicat_v3(sujet, politique=None, verdict="FAVORABLE", motif=None,
                 rapport_sha256="0" * 64, auteur="codex"):
    politique = politique or politique_v3_ancree()
    if verdict == "INDETERMINE" and motif is None:
        motif = "synthetique"
    instant = revue.format_instant(aide.MAINTENANT - datetime.timedelta(minutes=5))
    return revue3.construire_predicat_synthetique(
        copy.deepcopy(sujet),
        admis_v3(auteur=auteur),
        politique,
        verdict,
        motif,
        rapport_sha256,
        instant=instant,
    )

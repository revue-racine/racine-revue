"""Fixtures exclusivement simulées pour l'adaptateur OpenRouter 3A.2."""
import copy
import json
from pathlib import Path
import sys
import tempfile

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "outils"))

import relecteur_openrouter as ro  # noqa: E402
import revue  # noqa: E402
import transport_openrouter as th  # noqa: E402

CLE = "cle-test-opaque-sans-valeur-reelle"
MODELE = "anthropic/claude-sonnet-4-20250514"


def configuration(**changements):
    base = {
        "format": ro.FORMAT_CONFIGURATION,
        "profil": "simulation-claude-family-3a2",
        "etat": "dormant",
        "actif": False,
        "acceptable": False,
        "famille_relecture": "claude-family",
        "modele": MODELE,
        "modele_verifie": False,
        "fournisseur": "anthropic",
        "fournisseur_reponse": "Anthropic",
        "endpoint_fournisseur": "anthropic",
        "endpoint_exige": True,
        "temperature": 0,
        "max_tokens": 4096,
        "diff_octets": 500000,
        "requete_octets": 1000000,
        "budget_max_vie": "100",
        "controles_administratifs": copy.deepcopy(ro.ADMIN_NON_VERIFIE),
    }
    base.update(changements)
    return base


def budget(**changements):
    data = {
        "byok_usage": 0,
        "include_byok_in_limit": False,
        "is_management_key": False,
        "is_provisioning_key": False,
        "limit": 100,
        "limit_remaining": 75,
        "limit_reset": None,
        "usage": 25,
    }
    data.update(changements)
    return th.Reponse(json.dumps({"data": data}, separators=(",", ":")).encode(), {})


def sortie(verdict="FAVORABLE", constats=None, **extra):
    objet = {"verdict": verdict, "constats": [] if constats is None else constats}
    objet.update(extra)
    return json.dumps(objet, ensure_ascii=False, separators=(",", ":"))


def inference(
    contenu=None,
    modele=MODELE,
    fournisseur="Anthropic",
    tentative=1,
    total_endpoints=1,
    is_byok=False,
    strategy="direct",
    entetes=None,
    **extra,
):
    env = {
        "id": "gen-test",
        "model": modele,
        "object": "chat.completion",
        "created": 1792022400,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": contenu or sortie()},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
            "is_byok": is_byok,
        },
        "openrouter_metadata": {
            "attempt": tentative,
            "endpoints": {
                "available": [
                    {"model": modele, "provider": fournisseur, "selected": True}
                ],
                "total": total_endpoints,
            },
            "is_byok": is_byok,
            "requested": modele,
            "strategy": strategy,
        },
    }
    env.update(extra)
    return th.Reponse(
        json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode(),
        {} if entetes is None else entetes,
    )


class TransportSimule:
    simule = True

    def __init__(self, reponses=None):
        self.reponses = list(reponses or (budget(), inference()))
        self.appels = 0
        self.requetes = []

    def envoyer(self, cle, requete):
        self.appels += 1
        self.requetes.append((cle, requete))
        if not self.reponses:
            raise AssertionError("appel supplémentaire")
        reponse = self.reponses.pop(0)
        if isinstance(reponse, BaseException):
            raise reponse
        return reponse


class SerialiseurSimule:
    def __init__(self):
        self.entrees = 0
        self.sorties = 0
        self.actif = False

    def __enter__(self):
        if self.actif:
            raise AssertionError("verrou réentrant")
        self.actif = True
        self.entrees += 1
        return self

    def __exit__(self, *_exc):
        self.actif = False
        self.sorties += 1

    def verrou_acquis(self):
        return self.actif


def executer(transport=None, config=None, auteur="codex", diff=b"+changement\n", serialiseur=None):
    def lancer(verrou):
        return ro.executer(
            config or configuration(),
            auteur,
            diff,
            revue.schema("sortie-relecteur"),
            CLE,
            transport or TransportSimule(),
            verrou,
        )

    if serialiseur is not None:
        return lancer(serialiseur)
    with tempfile.TemporaryDirectory(prefix="openrouter-verrou-test-") as tmp:
        return lancer(ro.SerialiseurFichier(Path(tmp) / "adaptateur.lock"))

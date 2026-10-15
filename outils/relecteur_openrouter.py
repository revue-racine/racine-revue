"""Adaptateur OpenRouter dormant et non autorisant pour ``revue/3``.

Point d'entrée unique : :func:`executer`. Il exige un transport explicitement
simulé, sérialise le précontrôle budgétaire et l'inférence sous un même verrou,
et rend un résultat qui ne peut jamais autoriser, signer ou attester quoi que
ce soit. Aucune configuration de modèle n'est fournie par défaut.

Le contrôle de requête (ZDR, refus de collecte, absence de fallback, fournisseur
et endpoint épinglés) est technique. L'absence de Broadcast ou de BYOK au niveau
du compte et l'identité cryptographique du modèle ne sont pas démontrables par
la réponse d'inférence : ils restent explicitement non vérifiés dans ce lot.
"""
from contextlib import AbstractContextManager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import errno
import fcntl
import json
import os
import re
import stat
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import relecteur_openai as commun_v2  # noqa: E402
import revue  # noqa: E402
import revue3  # noqa: E402
import schema_strict  # noqa: E402
import transport_openrouter as transport_http  # noqa: E402

FORMAT_CONFIGURATION = "olistic.confiance.openrouter-adaptateur/1"
NOM_FORMAT = "sortie_relecteur_v1"
ETAT = "dormant"
MAX_APPELS = 2
PROFILS_DORMANTS = {
    "simulation-claude-family-3a2": {
        "famille_relecture": "claude-family",
        "modele": "anthropic/claude-sonnet-4-20250514",
        "fournisseur": "anthropic",
        "fournisseur_reponse": "Anthropic",
        "endpoint_fournisseur": "anthropic",
    }
}
ALIASES_FLOTTANTS = frozenset(
    {"auto", "automatic", "latest", "preview", "beta", "router"}
)
CHAMPS_CONFIGURATION = frozenset(
    {
        "format",
        "profil",
        "etat",
        "actif",
        "acceptable",
        "famille_relecture",
        "modele",
        "modele_verifie",
        "fournisseur",
        "fournisseur_reponse",
        "endpoint_fournisseur",
        "endpoint_exige",
        "temperature",
        "max_tokens",
        "diff_octets",
        "requete_octets",
        "budget_max_vie",
        "controles_administratifs",
    }
)
CHAMPS_ADMIN = frozenset(
    {"broadcast", "byok_compte", "zdr_compte", "plugins_compte"}
)
ADMIN_NON_VERIFIE = {
    "broadcast": "non_verifie",
    "byok_compte": "non_verifie",
    "zdr_compte": "non_verifie",
    "plugins_compte": "non_verifie",
}
LIMITES_NON_VERIFIEES = (
    "broadcast_compte_non_verifie",
    "byok_compte_non_verifie",
    "zdr_compte_non_verifie",
    "plugins_compte_non_verifies",
    "endpoint_non_rapporte_par_la_reponse",
    "identite_modele_non_cryptographique",
    "plafond_financier_non_absolu",
    "serialisation_limitee_au_dispositif_local",
    "transport_simule",
)


@dataclass(frozen=True)
class Configuration:
    famille_relecture: str
    modele: str
    fournisseur: str
    fournisseur_reponse: str
    endpoint_fournisseur: str
    temperature: int
    max_tokens: int
    diff_octets: int
    requete_octets: int
    budget_max_vie: Decimal


@dataclass(frozen=True)
class Resultat:
    rapport: bytes
    verdict: str
    motif: str | None
    modele: str
    fournisseur: str
    endpoint_demande: str
    tentatives_inference: int
    controles_techniques: tuple
    limites_non_verifiees: tuple
    acceptable_future: bool = False
    autorisante: bool = False


class SerialiseurFichier(AbstractContextManager):
    """Verrou inter-processus local ; ne couvre aucun autre consommateur de clé."""

    def __init__(self, chemin):
        self.chemin = Path(chemin)
        self.descripteur = None
        self._utilise = False
        self._proprietaire = None

    def __enter__(self):
        if self._utilise or self.descripteur is not None:
            raise revue.Refus("openrouter_serialisation")
        self._utilise = True
        drapeaux = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            drapeaux |= os.O_NOFOLLOW
        fd = None
        try:
            fd = os.open(self.chemin, drapeaux, 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise OSError("cible de verrou invalide")
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise revue.Refus("openrouter_serialisation") from None
        self.descripteur = fd
        self._proprietaire = threading.get_ident()
        return self

    def verrou_acquis(self):
        """Prouve le conflit du verrou via une seconde description du fichier."""
        if (
            self.descripteur is None
            or self._proprietaire != threading.get_ident()
        ):
            return False
        drapeaux = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            drapeaux |= os.O_NOFOLLOW
        verification = None
        try:
            origine = os.fstat(self.descripteur)
            verification = os.open(self.chemin, drapeaux)
            cible = os.fstat(verification)
            if (origine.st_dev, origine.st_ino) != (cible.st_dev, cible.st_ino):
                return False
            try:
                fcntl.flock(verification, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as erreur:
                return erreur.errno in (errno.EACCES, errno.EAGAIN)
            else:
                fcntl.flock(verification, fcntl.LOCK_UN)
                return False
        except OSError:
            return False
        finally:
            if verification is not None:
                try:
                    os.close(verification)
                except OSError:
                    pass

    def __exit__(self, *_exc):
        acquis = self.verrou_acquis()
        fd, self.descripteur = self.descripteur, None
        self._proprietaire = None
        erreur = not acquis
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                erreur = True
            finally:
                try:
                    os.close(fd)
                except OSError:
                    erreur = True
        if erreur:
            raise revue.Refus("openrouter_serialisation") from None
        return False


def _decimal_strict(texte, motif):
    if not isinstance(texte, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?", texte):
        raise revue.Refus(motif)
    try:
        valeur = Decimal(texte)
    except InvalidOperation:
        raise revue.Refus(motif) from None
    if not valeur.is_finite() or valeur <= 0:
        raise revue.Refus(motif)
    return valeur


def _chaine_bornee(valeur, motif, maximum=160):
    if not isinstance(valeur, str) or not valeur or len(valeur) > maximum:
        raise revue.Refus(motif)
    return valeur


def _modele_exact(modele, famille):
    _chaine_bornee(modele, "openrouter_modele_invalide")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*", modele):
        raise revue.Refus("openrouter_modele_invalide")
    morceaux = set(filter(None, re.split(r"[./_-]+", modele.lower())))
    if morceaux & ALIASES_FLOTTANTS or ":" in modele or "@" in modele:
        raise revue.Refus("openrouter_alias_flottant")
    if famille == "claude-family" and not modele.startswith("anthropic/claude-"):
        raise revue.Refus("openrouter_famille_modele_incoherente")


def charger_configuration(brut):
    """Charge une configuration fermée, obligatoirement dormante et explicite."""
    if not isinstance(brut, dict) or set(brut) != CHAMPS_CONFIGURATION:
        raise revue.Refus("openrouter_configuration_invalide")
    if brut["format"] != FORMAT_CONFIGURATION or brut["etat"] != ETAT:
        raise revue.Refus("openrouter_configuration_invalide")
    if brut["actif"] is not False or brut["acceptable"] is not False:
        raise revue.Refus("openrouter_activation_interdite")
    if brut["modele_verifie"] is not False:
        raise revue.Refus("openrouter_modele_non_verifie")
    profil = brut["profil"]
    if profil not in PROFILS_DORMANTS:
        raise revue.Refus("openrouter_profil_inconnu")
    attendu = PROFILS_DORMANTS[profil]
    if any(brut[cle] != valeur for cle, valeur in attendu.items()):
        raise revue.Refus("openrouter_profil_incoherent")
    famille = brut["famille_relecture"]
    if famille not in ("claude-family", "gpt-codex-family"):
        raise revue.Refus("openrouter_famille_invalide")
    _modele_exact(brut["modele"], famille)
    fournisseur = _chaine_bornee(brut["fournisseur"], "openrouter_fournisseur_invalide", 80)
    fournisseur_reponse = _chaine_bornee(
        brut["fournisseur_reponse"], "openrouter_fournisseur_invalide", 80
    )
    endpoint = _chaine_bornee(
        brut["endpoint_fournisseur"], "openrouter_endpoint_invalide", 120
    )
    motif_slug = r"[a-z0-9][a-z0-9-]*(?:/[a-z0-9][a-z0-9-]*)?"
    if re.fullmatch(motif_slug, fournisseur) is None or re.fullmatch(motif_slug, endpoint) is None:
        raise revue.Refus("openrouter_endpoint_invalide")
    if endpoint != fournisseur and not endpoint.startswith(fournisseur + "/"):
        raise revue.Refus("openrouter_endpoint_invalide")
    if brut["endpoint_exige"] is not True:
        raise revue.Refus("openrouter_endpoint_non_epingle")
    if brut["temperature"] != 0:
        raise revue.Refus("openrouter_parametre_invalide")
    for cle, maximum in (("max_tokens", 32000), ("diff_octets", 2000000), ("requete_octets", 4000000)):
        valeur = brut[cle]
        if not isinstance(valeur, int) or isinstance(valeur, bool) or not 1 <= valeur <= maximum:
            raise revue.Refus("openrouter_limite_invalide")
    admin = brut["controles_administratifs"]
    if not isinstance(admin, dict) or set(admin) != CHAMPS_ADMIN or admin != ADMIN_NON_VERIFIE:
        raise revue.Refus("openrouter_controle_administratif_non_supporte")
    return Configuration(
        famille_relecture=famille,
        modele=brut["modele"],
        fournisseur=fournisseur,
        fournisseur_reponse=fournisseur_reponse,
        endpoint_fournisseur=endpoint,
        temperature=0,
        max_tokens=brut["max_tokens"],
        diff_octets=brut["diff_octets"],
        requete_octets=brut["requete_octets"],
        budget_max_vie=_decimal_strict(brut["budget_max_vie"], "openrouter_budget_politique_invalide"),
    )


def construire_requete(configuration, diff, schema_sortie):
    if not isinstance(diff, bytes) or len(diff) > configuration.diff_octets:
        raise revue.Refus("openrouter_diff_invalide")
    corps = {
        "model": configuration.modele,
        "messages": [
            {"role": "system", "content": commun_v2.FICHIER_CONSIGNE.read_text("utf-8")},
            {"role": "user", "content": commun_v2.encadrer(diff)},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": NOM_FORMAT,
                "strict": True,
                "schema": commun_v2.projeter(schema_sortie),
            },
        },
        "temperature": configuration.temperature,
        "max_tokens": configuration.max_tokens,
        "stream": False,
        "provider": {
            "order": [configuration.endpoint_fournisseur],
            "only": [configuration.endpoint_fournisseur],
            "allow_fallbacks": False,
            "require_parameters": True,
            "data_collection": "deny",
            "zdr": True,
        },
    }
    octets = transport_http.serialiser_json(corps)
    if len(octets) > configuration.requete_octets:
        raise revue.Refus("openrouter_requete_trop_grande")
    return corps, octets


def _json_decimal(octets, motif):
    erreur = False
    objet = None
    try:
        objet = json.loads(
            octets.decode("utf-8"),
            object_pairs_hook=revue._refuser_doublons,
            parse_constant=revue._refuser_constante,
            parse_float=Decimal,
        )
    except (ValueError, UnicodeDecodeError, RecursionError, InvalidOperation):
        erreur = True
    if erreur:
        raise revue.Refus(motif)
    return objet


def _nombre(valeur, motif):
    if isinstance(valeur, bool) or not isinstance(valeur, (int, Decimal)):
        raise revue.Refus(motif)
    valeur = Decimal(valeur)
    if not valeur.is_finite():
        raise revue.Refus(motif)
    return valeur


CHAMPS_BUDGET = frozenset(
    {
        "byok_usage",
        "byok_usage_daily",
        "byok_usage_monthly",
        "byok_usage_weekly",
        "creator_user_id",
        "include_byok_in_limit",
        "is_free_tier",
        "is_management_key",
        "is_provisioning_key",
        "label",
        "limit",
        "limit_remaining",
        "limit_reset",
        "usage",
        "usage_daily",
        "usage_monthly",
        "usage_weekly",
        "rate_limit",
        "expires_at",
        "allowed_data_regions",
        "budgets",
        "effective_budget",
        "free_model_daily_requests",
        "organization_id",
        "workspace_id",
    }
)
REQUIS_BUDGET = frozenset(
    {
        "byok_usage",
        "include_byok_in_limit",
        "is_management_key",
        "is_provisioning_key",
        "limit",
        "limit_remaining",
        "limit_reset",
        "usage",
    }
)


def controler_budget(octets, configuration):
    obj = _json_decimal(octets, "openrouter_budget_illisible")
    if not isinstance(obj, dict) or set(obj) != {"data"} or not isinstance(obj["data"], dict):
        raise revue.Refus("openrouter_budget_invalide")
    data = obj["data"]
    if not REQUIS_BUDGET <= set(data) or set(data) - CHAMPS_BUDGET:
        raise revue.Refus("openrouter_budget_invalide")
    if data["is_management_key"] is not False or data["is_provisioning_key"] is not False:
        raise revue.Refus("openrouter_cle_inadaptee")
    if data["include_byok_in_limit"] is not False or _nombre(data["byok_usage"], "openrouter_byok") != 0:
        raise revue.Refus("openrouter_byok")
    if data["limit_reset"] is not None:
        raise revue.Refus("openrouter_budget_reinitialisable")
    limite = _nombre(data["limit"], "openrouter_budget_absent")
    restant = _nombre(data["limit_remaining"], "openrouter_budget_invalide")
    usage = _nombre(data["usage"], "openrouter_budget_invalide")
    if limite != configuration.budget_max_vie:
        raise revue.Refus("openrouter_budget_politique_incompatible")
    if usage < 0 or restant < 0 or restant > limite or usage + restant != limite:
        raise revue.Refus("openrouter_budget_incoherent")
    if restant == 0:
        raise revue.Refus("openrouter_budget_epuise")
    champs_usages = {
        "byok_usage_daily",
        "byok_usage_monthly",
        "byok_usage_weekly",
        "usage_daily",
        "usage_monthly",
        "usage_weekly",
    }
    for cle in champs_usages & set(data):
        if _nombre(data[cle], "openrouter_budget_invalide") < 0:
            raise revue.Refus("openrouter_budget_invalide")
    for cle in ("creator_user_id", "label", "expires_at", "organization_id", "workspace_id"):
        if cle in data and data[cle] is not None:
            _chaine_bornee(data[cle], "openrouter_budget_invalide", 256)
    if "is_free_tier" in data and not isinstance(data["is_free_tier"], bool):
        raise revue.Refus("openrouter_budget_invalide")
    regions = data.get("allowed_data_regions")
    if regions is not None and (
        not isinstance(regions, list)
        or any(not isinstance(r, str) or r not in {"global", "europe", "us"} for r in regions)
        or len(regions) != len(set(regions))
    ):
        raise revue.Refus("openrouter_budget_invalide")
    libre = data.get("free_model_daily_requests")
    if libre is not None:
        if not _cles_exactes(libre, {"limit", "remaining", "used"}):
            raise revue.Refus("openrouter_budget_invalide")
        valeurs = [libre[k] for k in ("limit", "remaining", "used")]
        if not all(_entier_non_negatif(v) for v in valeurs):
            raise revue.Refus("openrouter_budget_invalide")
        if libre["remaining"] + libre["used"] != libre["limit"]:
            raise revue.Refus("openrouter_budget_incoherent")
    debit = data.get("rate_limit")
    if debit is not None:
        if not _cles_exactes(debit, {"interval", "requests"}, {"note"}):
            raise revue.Refus("openrouter_budget_invalide")
        _chaine_bornee(debit["interval"], "openrouter_budget_invalide", 32)
        if not _entier_non_negatif(debit["requests"]):
            raise revue.Refus("openrouter_budget_invalide")
        if "note" in debit:
            _chaine_bornee(debit["note"], "openrouter_budget_invalide", 256)
    budgets = data.get("budgets", [])
    if not isinstance(budgets, list):
        raise revue.Refus("openrouter_budget_invalide")
    for budget in budgets:
        _controler_budget_effectif(budget, configuration)
    if data.get("effective_budget") is not None:
        _controler_budget_effectif(data["effective_budget"], configuration)
    return limite, restant


def _controler_budget_effectif(budget, configuration):
    champs = {
        "budget_id",
        "guardrail_id",
        "include_byok",
        "limit_usd",
        "remaining_usd",
        "reset_interval",
        "resets_at",
        "scope",
        "spend_usd",
    }
    if not _cles_exactes(budget, champs):
        raise revue.Refus("openrouter_budget_invalide")
    if budget["include_byok"] is not False:
        raise revue.Refus("openrouter_byok")
    if budget["reset_interval"] not in (None, "lifetime") or budget["resets_at"] is not None:
        raise revue.Refus("openrouter_budget_reinitialisable")
    for cle in ("budget_id", "guardrail_id"):
        if budget[cle] is not None:
            _chaine_bornee(budget[cle], "openrouter_budget_invalide", 128)
    _chaine_bornee(budget["scope"], "openrouter_budget_invalide", 64)
    limite = _nombre(budget["limit_usd"], "openrouter_budget_invalide")
    restant = _nombre(budget["remaining_usd"], "openrouter_budget_invalide")
    depense = _nombre(budget["spend_usd"], "openrouter_budget_invalide")
    if limite != configuration.budget_max_vie:
        raise revue.Refus("openrouter_budget_politique_incompatible")
    if restant < 0 or depense < 0 or restant + depense != limite:
        raise revue.Refus("openrouter_budget_incoherent")


def _cles_exactes(objet, requises, optionnelles=()):
    return isinstance(objet, dict) and set(requises) <= set(objet) <= set(requises) | set(optionnelles)


def _entier_non_negatif(valeur):
    return isinstance(valeur, int) and not isinstance(valeur, bool) and valeur >= 0


def _controler_usage(usage):
    requis = {"prompt_tokens", "completion_tokens", "total_tokens", "is_byok"}
    optionnels = {
        "cost",
        "cost_details",
        "prompt_tokens_details",
        "completion_tokens_details",
        "server_tool_use_details",
    }
    if not _cles_exactes(usage, requis, optionnels):
        raise revue.Refus("openrouter_enveloppe_invalide")
    if usage["is_byok"] is not False:
        raise revue.Refus("openrouter_byok")
    if not all(_entier_non_negatif(usage[k]) for k in ("prompt_tokens", "completion_tokens", "total_tokens")):
        raise revue.Refus("openrouter_enveloppe_invalide")
    if usage["prompt_tokens"] + usage["completion_tokens"] > usage["total_tokens"]:
        raise revue.Refus("openrouter_enveloppe_invalide")
    if "cost" in usage and (
        _nombre(usage["cost"], "openrouter_enveloppe_invalide") < 0
    ):
        raise revue.Refus("openrouter_enveloppe_invalide")
    couts = usage.get("cost_details")
    if couts is not None:
        champs_couts = {
            "upstream_inference_cost",
            "upstream_inference_prompt_cost",
            "upstream_inference_completions_cost",
        }
        if not isinstance(couts, dict) or not set(couts) <= champs_couts:
            raise revue.Refus("openrouter_enveloppe_invalide")
        for valeur in couts.values():
            if valeur is not None and _nombre(
                valeur, "openrouter_enveloppe_invalide"
            ) < 0:
                raise revue.Refus("openrouter_enveloppe_invalide")
    details_entree = usage.get("prompt_tokens_details")
    if details_entree is not None:
        if not _cles_exactes(
            details_entree, (), {"cached_tokens", "cache_write_tokens"}
        ) or not all(_entier_non_negatif(v) for v in details_entree.values()):
            raise revue.Refus("openrouter_enveloppe_invalide")
    details_sortie = usage.get("completion_tokens_details")
    if details_sortie is not None:
        if not _cles_exactes(
            details_sortie, (), {"reasoning_tokens"}
        ) or not all(_entier_non_negatif(v) for v in details_sortie.values()):
            raise revue.Refus("openrouter_enveloppe_invalide")
    outils = usage.get("server_tool_use_details")
    if outils is not None:
        if not _cles_exactes(outils, {"tool_calls_executed", "tool_calls_requested"}):
            raise revue.Refus("openrouter_enveloppe_invalide")
        if outils != {"tool_calls_executed": 0, "tool_calls_requested": 0}:
            raise revue.Refus("openrouter_outil_inattendu")


def _controler_metadonnees(meta, configuration):
    requis = {"attempt", "endpoints", "is_byok", "requested", "strategy"}
    optionnels = {"generation_time", "region", "summary"}
    if not _cles_exactes(meta, requis, optionnels):
        raise revue.Refus("openrouter_routage_ambigu")
    if meta["attempt"] != 1 or meta["strategy"] != "direct":
        raise revue.Refus("openrouter_routage_inattendu")
    if meta["is_byok"] is not False:
        raise revue.Refus("openrouter_byok")
    if meta["requested"] != configuration.modele:
        raise revue.Refus("openrouter_modele_inattendu")
    endpoints = meta["endpoints"]
    if not _cles_exactes(endpoints, {"available", "total"}):
        raise revue.Refus("openrouter_routage_ambigu")
    disponibles = endpoints["available"]
    if endpoints["total"] != 1 or not isinstance(disponibles, list) or len(disponibles) != 1:
        raise revue.Refus("openrouter_routage_ambigu")
    selection = disponibles[0]
    if not _cles_exactes(selection, {"model", "provider", "selected"}):
        raise revue.Refus("openrouter_routage_ambigu")
    if selection["selected"] is not True:
        raise revue.Refus("openrouter_routage_ambigu")
    if selection["model"] != configuration.modele:
        raise revue.Refus("openrouter_modele_inattendu")
    if selection["provider"] != configuration.fournisseur_reponse:
        raise revue.Refus("openrouter_fournisseur_inattendu")
    if "generation_time" in meta and _nombre(
        meta["generation_time"], "openrouter_routage_ambigu"
    ) < 0:
        raise revue.Refus("openrouter_routage_ambigu")
    for cle in ("region", "summary"):
        if cle in meta:
            _chaine_bornee(meta[cle], "openrouter_routage_ambigu", 512)


def analyser_reponse(reponse, configuration, schema_sortie):
    if (
        not isinstance(reponse, transport_http.Reponse)
        or not isinstance(reponse.corps, bytes)
        or not isinstance(reponse.entetes, dict)
        or any(not isinstance(k, str) or not isinstance(v, str) for k, v in reponse.entetes.items())
    ):
        raise revue.Refus("openrouter_enveloppe_invalide")
    cache = reponse.entetes.get("x-openrouter-cache-status")
    if cache is not None:
        raise revue.Refus("openrouter_cache_inattendu")
    env = _json_decimal(reponse.corps, "openrouter_enveloppe_illisible")
    requis = {"id", "model", "object", "created", "choices", "usage", "openrouter_metadata"}
    optionnels = {"system_fingerprint", "service_tier"}
    if not _cles_exactes(env, requis, optionnels):
        raise revue.Refus("openrouter_enveloppe_invalide")
    if env["object"] != "chat.completion" or env["model"] != configuration.modele:
        raise revue.Refus("openrouter_modele_inattendu")
    if not isinstance(env["id"], str) or not _entier_non_negatif(env["created"]):
        raise revue.Refus("openrouter_enveloppe_invalide")
    for cle in ("system_fingerprint", "service_tier"):
        if cle in env and env[cle] is not None:
            _chaine_bornee(env[cle], "openrouter_enveloppe_invalide", 256)
    if not isinstance(env["choices"], list) or len(env["choices"]) != 1:
        raise revue.Refus("openrouter_sortie_absente")
    choix = env["choices"][0]
    if not _cles_exactes(choix, {"index", "message", "finish_reason"}, {"native_finish_reason", "logprobs"}):
        raise revue.Refus("openrouter_enveloppe_invalide")
    if choix["index"] != 0 or choix["finish_reason"] != "stop":
        raise revue.Refus("openrouter_statut")
    if "native_finish_reason" in choix and choix["native_finish_reason"] != "stop":
        raise revue.Refus("openrouter_statut")
    if "logprobs" in choix and choix["logprobs"] is not None:
        raise revue.Refus("openrouter_element_inattendu")
    message = choix["message"]
    if not _cles_exactes(message, {"role", "content"}, {"refusal"}):
        raise revue.Refus("openrouter_element_inattendu")
    if message["role"] != "assistant" or not isinstance(message["content"], str):
        raise revue.Refus("openrouter_element_inattendu")
    if message.get("refusal") not in (None, ""):
        raise revue.Refus("openrouter_refus_modele")
    _controler_usage(env["usage"])
    _controler_metadonnees(env["openrouter_metadata"], configuration)
    rapport = message["content"].encode("utf-8")
    try:
        sortie = revue.charger_json_strict(rapport)
    except (ValueError, UnicodeDecodeError):
        raise revue.Refus("openrouter_sortie_invalide") from None
    if schema_strict.erreurs(sortie, schema_sortie):
        raise revue.Refus("openrouter_sortie_invalide")
    verdict, motif, _empreinte = revue.normaliser_verdict("openrouter-chat", rapport)
    if motif in ("sortie_invalide", "favorable_incoherent"):
        raise revue.Refus("openrouter_sortie_contradictoire")
    return rapport, verdict, motif


MOTIFS_TRANSPORT = frozenset(
    {
        "openrouter_route_interdite",
        "openrouter_requete_invalide",
        "openrouter_cle_absente",
        "openrouter_cle_invalide",
        "openrouter_configuration",
        "openrouter_serialisation",
        "openrouter_connexion",
        "openrouter_delai",
        "openrouter_redirection",
        "openrouter_http_client",
        "openrouter_quota",
        "openrouter_http_serveur",
        "openrouter_encodage",
        "openrouter_entete_invalide",
        "openrouter_trop_grand",
        "openrouter_reponse_tronquee",
        "openrouter_nettoyage",
        "openrouter_interne",
    }
)


def _envoyer_opaque(transport, cle, requete):
    motif = None
    reponse = None
    try:
        reponse = transport.envoyer(cle, requete)
    except BaseException as erreur:  # transport simulé hostile compris
        if isinstance(erreur, revue.Refus) and erreur.motif in MOTIFS_TRANSPORT:
            motif = erreur.motif
        else:
            motif = "openrouter_transport"
    if motif is not None:
        raise revue.Refus(motif)
    if not isinstance(reponse, transport_http.Reponse):
        raise revue.Refus("openrouter_transport")
    if not isinstance(reponse.corps, bytes) or len(reponse.corps) > transport_http._taille_max(requete):
        raise revue.Refus("openrouter_trop_grand")
    return reponse


def _exiger_verrou(serialiseur):
    if not serialiseur.verrou_acquis():
        raise revue.Refus("openrouter_serialisation")


def executer(configuration, auteur, diff, schema_sortie, cle, transport, serialiseur):
    """Exécute le scénario simulé borné : budget puis une seule inférence.

    La classe de transport HTTPS du lot et ses sous-classes sont refusées, puis
    le marqueur de simulation est exigé. Cette barrière de dormance ne prétend
    pas constituer une frontière contre du code Python arbitraire déjà exécuté.
    Aucune attestation n'est construite et le résultat reste non autorisant.
    """
    config = charger_configuration(configuration)
    politique = revue3.charger_politique()
    famille_attendue = revue3.selectionner_famille(auteur, politique)
    if config.famille_relecture != famille_attendue:
        raise revue.Refus("openrouter_famille_non_independante")
    if isinstance(transport, transport_http.TransportHTTPS):
        raise revue.Refus("openrouter_adaptateur_dormant")
    if getattr(transport, "simule", None) is not True:
        raise revue.Refus("openrouter_adaptateur_dormant")
    if type(serialiseur) is not SerialiseurFichier:
        raise revue.Refus("openrouter_serialisation")
    appels_avant = getattr(transport, "appels", None)
    if (
        not isinstance(appels_avant, int)
        or isinstance(appels_avant, bool)
        or appels_avant < 0
    ):
        raise revue.Refus("openrouter_compteur_appels")
    _objet_requete, octets_requete = construire_requete(config, diff, schema_sortie)
    with serialiseur:
        _exiger_verrou(serialiseur)
        budget = _envoyer_opaque(transport, cle, transport_http.requete_budget())
        _exiger_verrou(serialiseur)
        controler_budget(budget.corps, config)
        _exiger_verrou(serialiseur)
        reponse = _envoyer_opaque(
            transport,
            cle,
            transport_http.requete_inference(octets_requete),
        )
        _exiger_verrou(serialiseur)
    appels_apres = getattr(transport, "appels", None)
    if (
        not isinstance(appels_apres, int)
        or isinstance(appels_apres, bool)
        or appels_apres - appels_avant != MAX_APPELS
    ):
        raise revue.Refus("openrouter_nombre_appels_inattendu")
    rapport, verdict, motif = analyser_reponse(reponse, config, schema_sortie)
    return Resultat(
        rapport=rapport,
        verdict=verdict,
        motif=motif,
        modele=config.modele,
        fournisseur=config.fournisseur_reponse,
        endpoint_demande=config.endpoint_fournisseur,
        tentatives_inference=1,
        controles_techniques=(
            "zdr_requete",
            "collecte_refusee",
            "fallback_refuse",
            "fournisseur_epingle",
            "endpoint_demande_epingle",
            "parametres_exiges",
            "byok_non_utilise_pour_la_generation",
            "cache_reponse_desactive",
            "budget_vie_precontrole",
            "appels_serialises_localement",
        ),
        limites_non_verifiees=LIMITES_NON_VERIFIEES,
    )

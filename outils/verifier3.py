#!/usr/bin/env python3
"""Vérificateur hors ligne d'attestations synthétiques revue/3.

Une réussite ne constitue jamais une vérification cryptographique ni une
autorisation. L'interface cryptographique échoue explicitement dans 3A.1.
"""
import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import revue  # noqa: E402
import revue3  # noqa: E402


@dataclass(frozen=True)
class DecisionSynthetique:
    verifiee: bool
    autorisante: bool
    nature: str
    motif: str
    verdict: str | None
    sujet_digest: str | None


def _rejet(motif):
    return DecisionSynthetique(
        verifiee=False,
        autorisante=False,
        nature=revue3.NATURE_SYNTHETIQUE,
        motif=motif,
        verdict=None,
        sujet_digest=None,
    )


def controler_synthetique(predicat, sujet, politique):
    revue3.controler_politique(politique)
    revue3.controler_invariants(predicat, politique)
    octets_sujet = revue.canonique(sujet)
    if revue.canonique(predicat["sujet"]) != octets_sujet:
        raise revue.Refus("sujet_divergent")
    empreintes = revue3.empreintes_locales()
    presentes = (
        predicat["protocole"]["sha256"],
        predicat["politique"]["sha256"],
        predicat["ancres_sha256"],
    )
    attendues = (empreintes["protocole"], empreintes["politique"], empreintes["ancres"])
    if presentes != attendues:
        raise revue.Refus("empreintes_divergentes")
    if predicat["protocole"]["version"] != revue3.VERSION_PROTOCOLE:
        raise revue.Refus("protocole_divergent")
    return predicat, revue.sha256_hex(octets_sujet)


def verifier_synthetique(predicat, sujet, politique=None):
    """Vérifie le contrat local ; la décision reste toujours non autorisante."""
    try:
        if politique is None:
            politique = revue3.charger_politique()
        revue3.controler_politique(politique)
        predicat, digest = controler_synthetique(predicat, sujet, politique)
    except (revue.Refus, KeyError, TypeError) as e:
        motif = e.motif if isinstance(e, revue.Refus) else "attestation_illisible"
        return _rejet(motif)
    return DecisionSynthetique(
        verifiee=True,
        autorisante=False,
        nature=revue3.NATURE_SYNTHETIQUE,
        motif="politique_dormante",
        verdict=predicat["verdict"],
        sujet_digest=digest,
    )


def verifier_cryptographique(*_args, **_kwargs):
    raise revue.Refus("verification_cryptographique_non_implementee")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--predicat", required=True)
    parser.add_argument("--sujet", required=True)
    parser.add_argument("--politique", default=str(revue3.RACINE / revue3.FICHIER_POLITIQUE))
    args = parser.parse_args(argv)
    try:
        predicat = revue.charger_json_strict(Path(args.predicat).read_bytes())
        sujet = revue.charger_json_strict(Path(args.sujet).read_bytes())
        politique = revue3.charger_politique(args.politique)
        decision = verifier_synthetique(predicat, sujet, politique)
    except (ValueError, revue.Refus) as e:
        motif = e.motif if isinstance(e, revue.Refus) else "json_invalide"
        decision = _rejet(motif)
    print(json.dumps(asdict(decision), ensure_ascii=False, sort_keys=True))
    return 0 if decision.verifiee else 1


if __name__ == "__main__":
    sys.exit(main())

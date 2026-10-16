"""Fixtures cryptographiques v3, exclusivement hors ligne et non productives.

La frontière ``gh attestation verify`` est simulée : seuls les bundles dont
l'empreinte a été enregistrée par ``FauxGitHubV3.publier(..., signe=True)``
sont rendus comme vérifiés. Tous les contrôles applicatifs qui suivent cette
frontière utilisent le code de production. Les tests du pont emploient en
revanche une vraie signature SSH avec une clé éphémère.
"""
import copy
import datetime
import hashlib
import json
import os
import subprocess
import tempfile
import threading
from pathlib import Path
from unittest import mock

import aide
from aide import revue
import aide_v3
import pont_p1_v3
import registre
import revue3
import verifier
import verifier3

MAINTENANT = datetime.datetime(2026, 10, 16, 12, 0, 0, tzinfo=datetime.timezone.utc)
COMMIT_WORKFLOW = "a" * 40
MODELE = "anthropic/claude-sonnet-test-20261015"
FOURNISSEUR = "Anthropic-Test"
ENDPOINT = "anthropic-test"


def confiance_v3(revocations=None, **surcharges):
    politique = aide_v3.politique_v3_ancree()
    racine = politique["racine"]
    empreintes = revue3.empreintes_locales()
    conf = {
        **racine,
        "type_predicat": revue3.TYPE_PREDICAT,
        "commits_racine": [COMMIT_WORKFLOW],
        "politique_sha256": empreintes["politique"],
        "protocole_sha256": empreintes["protocole"],
        "generation": 3,
        "identite_relecteur": {
            "famille": "claude-family",
            "modele": MODELE,
            "fournisseur": FOURNISSEUR,
            "endpoint": ENDPOINT,
        },
        "revocations": list(revocations or []),
    }
    conf.update(surcharges)
    return conf


def predicat_crypto(sujet, request_id=aide.RID, verdict="FAVORABLE", motif=None,
                    instant=None, auteur="codex"):
    predicat = aide_v3.predicat_v3(
        sujet, verdict=verdict, motif=motif, auteur=auteur
    )
    predicat["demande"]["request_id"] = request_id
    predicat["relecteur"] = {
        "famille": "claude-family",
        "modele": MODELE,
        "fournisseur": FOURNISSEUR,
        "endpoint": ENDPOINT,
        "acceptable": False,
    }
    predicat["verification"] = copy.deepcopy(verifier3.VERIFICATION_CRYPTOGRAPHIQUE)
    predicat["instant"] = instant or revue.format_instant(
        MAINTENANT - datetime.timedelta(minutes=5)
    )
    return predicat


def certificat_v3(commit=COMMIT_WORKFLOW):
    racine = aide_v3.politique_v3_ancree()["racine"]
    proprietaire, depot = racine["proprietaire"], racine["depot"]
    base = f"https://github.com/{proprietaire}/{depot}"
    signataire = f"{base}/{racine['workflow']}@{racine['ref']}"
    return {
        "issuer": "https://token.actions.githubusercontent.com",
        "sourceRepositoryURI": base,
        "sourceRepositoryOwnerURI": f"https://github.com/{proprietaire}",
        "sourceRepositoryRef": racine["ref"],
        "sourceRepositoryIdentifier": str(racine["depot_id"]),
        "sourceRepositoryOwnerIdentifier": str(racine["proprietaire_id"]),
        "sourceRepositoryVisibilityAtSigning": "public",
        "buildSignerURI": signataire,
        "buildConfigURI": signataire,
        "buildSignerDigest": commit,
        "buildConfigDigest": commit,
        "githubWorkflowSHA": commit,
        "sourceRepositoryDigest": commit,
        "runnerEnvironment": "github-hosted",
        "buildTrigger": "issues",
        "githubWorkflowTrigger": "issues",
        "githubWorkflowRepository": f"{proprietaire}/{depot}",
        "githubWorkflowRef": racine["ref"],
        "githubWorkflowName": racine["nom_workflow"],
        "runInvocationURI": f"{base}/actions/runs/1/attempts/1",
    }


def resultat_v3(predicat, sujet=None, certificat=None, type_predicat=None,
                nom=None, instant_verifie=None):
    sujet = sujet if sujet is not None else predicat["sujet"]
    request_id = predicat["demande"]["request_id"]
    instant_verifie = instant_verifie or (
        revue.instant_utc(predicat["instant"]) + datetime.timedelta(seconds=30)
    )
    return {
        "verificationResult": {
            "signature": {"certificate": certificat or certificat_v3()},
            "verifiedTimestamps": [{
                "type": "Tlog",
                "uri": "https://rekor.sigstore.dev",
                "timestamp": revue.format_instant(instant_verifie),
            }],
            "statement": {
                "_type": verifier.TYPE_INTOTO,
                "subject": [{
                    "name": nom if nom is not None else revue3.nom_sujet(sujet, request_id),
                    "digest": {"sha256": revue.sha256_hex(revue.canonique(sujet))},
                }],
                "predicateType": type_predicat or revue3.TYPE_PREDICAT,
                "predicate": predicat,
            },
        }
    }


def empreinte_enonce(resultat):
    return revue.sha256_hex(revue.canonique(resultat["verificationResult"]["statement"]))


class FauxGitHubV3:
    """Liste/téléchargement GitHub et décision cryptographique simulées."""

    HOTE = "https://tmp-attestations.githubusercontent.com"

    def __init__(self):
        self.par_digest = {}
        self.bundles = {}
        self.signes = set()

    def publier(self, resultat, signe=True):
        enonce = resultat["verificationResult"]["statement"]
        digest = enonce["subject"][0]["digest"]["sha256"]
        corps = json.dumps({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "resultat": resultat,
        }).encode("utf-8")
        empreinte = hashlib.sha256(corps).hexdigest()
        self.bundles[empreinte] = aide.snappy_litteral(corps)
        if signe:
            self.signes.add(empreinte)
        self.par_digest.setdefault(digest, []).append({
            "bundle_url": f"{self.HOTE}/b/{empreinte}"
        })
        return empreinte

    def http(self, url, entetes):
        if url.startswith(self.HOTE + "/b/"):
            empreinte = url.rsplit("/", 1)[1]
            if empreinte not in self.bundles:
                return 404, {}, b"", url
            return 200, {}, self.bundles[empreinte], url
        racine = aide_v3.politique_v3_ancree()["racine"]
        prefixe = (
            f"https://api.github.com/repos/{racine['proprietaire']}/"
            f"{racine['depot']}/attestations/sha256:"
        )
        if url.startswith(prefixe):
            digest = url[len(prefixe):].split("?", 1)[0]
            if digest not in self.par_digest:
                return 404, {}, b"", url
            corps = json.dumps({"attestations": self.par_digest[digest]}).encode("utf-8")
            return 200, {}, corps, url
        return 404, {}, b"", url

    def verifier_crypto(self, conf, chemin_sujet, chemin_bundle):
        corps = Path(chemin_bundle).read_bytes()
        if hashlib.sha256(corps).hexdigest() not in self.signes:
            raise revue.Refus("verification_cryptographique")
        resultat = json.loads(corps)["resultat"]
        digest = hashlib.sha256(Path(chemin_sujet).read_bytes()).hexdigest()
        obtenu = resultat["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"]
        if obtenu != digest:
            raise revue.Refus("verification_cryptographique")
        return resultat


class TransportFichierAtomique:
    """Transport local multiprocessus : création unique par lien dur atomique."""

    def __init__(self, racine):
        self.racine = Path(racine)

    def _chemin(self, nom):
        return self.racine.joinpath(*nom.split("/"))

    def creer_ref(self, nom, contenu):
        cible = self._chemin(nom)
        cible.parent.mkdir(parents=True, exist_ok=True)
        temporaire = cible.parent / f".{cible.name}.{os.getpid()}.{threading.get_ident()}"
        fd = os.open(temporaire, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as flux:
                flux.write(contenu)
                flux.flush()
                os.fsync(flux.fileno())
            try:
                os.link(temporaire, cible)
                return True
            except FileExistsError:
                return False
        finally:
            temporaire.unlink(missing_ok=True)

    def lire_ref(self, nom):
        try:
            return self._chemin(nom).read_bytes()
        except FileNotFoundError:
            return None


class BancV3:
    """Sujet v3, épinglages, fausse frontière Sigstore et clé SSH de test."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        dossier = Path(self.tmp.name)
        self.candidat = aide.DepotCandidat()
        self.politique = aide_v3.politique_v3_ancree()
        self.sujet = aide_v3.sujet_v3_pour(
            self.candidat, self.candidat.c3, self.politique
        )
        self.politique_path = aide.RACINE / "policy/confiance-v3.json"
        self.confiance_path = dossier / "confiance-v3-test.json"
        self.ancres_path = dossier / "ancres-v3-test.json"
        self.cle = dossier / "cle-p1-test"
        self.gh = FauxGitHubV3()
        self.transport = aide.TransportMemoire()
        self.registre = registre.RegistreConsommation(self.transport)
        self.ecrire_confiance(confiance_v3())
        self.ancres_path.write_text(json.dumps({
            "format": "olistic.confiance.ancres/1",
            "ancres": [{
                "alias": "auto-test",
                "commit": self.candidat.c1,
                "objet_sha256": aide.objet_sha256(
                    self.candidat.chemin, self.candidat.c1
                ),
            }],
        }), encoding="utf-8")
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test-v3",
             "-f", str(self.cle)],
            check=True,
        )
        self.config = pont_p1_v3.ConfigPontV3Test(
            confiance=str(self.confiance_path),
            politique=str(self.politique_path),
            ancres=str(self.ancres_path),
            cle_test=str(self.cle),
            principal_test="test-relecteur-v3",
            depot_p1_test="test.invalid/paquet-p1",
            url_candidat=str(self.candidat.chemin),
        )
        self.patchs = [
            mock.patch.object(verifier, "_verifier_crypto", self.gh.verifier_crypto),
            mock.patch.object(verifier, "_http_get", self.gh.http),
            mock.patch.object(pont_p1_v3, "_horloge", lambda: MAINTENANT),
        ]
        for patch in self.patchs:
            patch.start()

    def ecrire_confiance(self, valeur):
        self.confiance_path.write_text(json.dumps(valeur), encoding="utf-8")

    def publier(self, signe=True, predicat=None, **kwargs):
        predicat = predicat or predicat_crypto(self.sujet, **kwargs)
        resultat = resultat_v3(predicat)
        self.gh.publier(resultat, signe=signe)
        return resultat

    def reinitialiser_attestations(self):
        """Vide la source simulée sans modifier le sujet ni les épinglages."""
        self.patchs[0].stop()
        self.patchs[1].stop()
        self.gh = FauxGitHubV3()
        self.patchs[0] = mock.patch.object(
            verifier, "_verifier_crypto", self.gh.verifier_crypto
        )
        self.patchs[1] = mock.patch.object(verifier, "_http_get", self.gh.http)
        self.patchs[0].start()
        self.patchs[1].start()

    def verifier(self, request_id=aide.RID):
        with tempfile.TemporaryDirectory() as tmp:
            return verifier3.verifier_cryptographique(
                self.confiance_path,
                self.politique_path,
                self.sujet,
                request_id,
                Path(tmp) / "travail",
                maintenant=MAINTENANT,
            )

    def operer(self, config=None, request_id=aide.RID, pointe=None, registre_test=None):
        return pont_p1_v3.verifier_consommer_et_signer_test_non_autorisant(
            config or self.config,
            request_id,
            "auto-test",
            pointe or self.candidat.c3,
            registre_test or self.registre,
        )

    def fermer(self):
        for patch in reversed(self.patchs):
            patch.stop()
        self.candidat.nettoyer()
        self.tmp.cleanup()

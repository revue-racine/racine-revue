"""Pont P1 v3 dormant : consommation atomique et sortie de test seulement."""
import ast
import base64
import datetime
import inspect
import json
import multiprocessing
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import aide
from aide import revue
import aide_v3
import aide_v3_crypto as crypto
import pont_p1_v3
import registre as R

CLES_P1 = {
    "format", "role", "depot", "pointe", "arbre", "classe", "auteur",
    "relecteur", "reference_revue", "reference_approbation", "instant",
}
PARAMETRES_INTERDITS = {
    "decision", "document", "doc", "octets", "donnees", "predicat",
    "verdict", "resultat", "resultats", "acceptee", "signature", "valeur",
}


def _reserver_dans_processus(racine, barriere, queue):
    registre = R.RegistreConsommation(crypto.TransportFichierAtomique(racine))
    barriere.wait()
    try:
        registre.reserver(aide.RID, {"sujet_sha256": "a" * 64})
        queue.put("reserve")
    except revue.Refus as e:
        queue.put(e.motif)


class TestPontP1V3(unittest.TestCase):
    def setUp(self):
        self.b = crypto.BancV3()
        self.addCleanup(self.b.fermer)

    def motif(self, fonction, *args, **kwargs):
        with self.assertRaises(revue.Refus) as cm:
            fonction(*args, **kwargs)
        return cm.exception.motif

    def refuser_sans_signature_ni_consommation(self):
        appels_signature = []
        executer = subprocess.run

        def surveiller(arguments, *args, **kwargs):
            if arguments and arguments[0] == "/usr/bin/ssh-keygen" \
                    and "sign" in arguments:
                appels_signature.append(arguments)
            return executer(arguments, *args, **kwargs)

        motif = None
        resultat = None
        with mock.patch.object(pont_p1_v3.subprocess, "run", surveiller):
            try:
                resultat = self.b.operer()
            except revue.Refus as e:
                motif = e.motif
        self.assertEqual(appels_signature, [])
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.DISPONIBLE)
        self.assertIsNone(resultat)
        self.assertIsNotNone(motif, "le pont a accepté une décision contradictoire")
        return motif

    def verifier_signature_p1(self, valeur, modifier_document=None,
                              espace=pont_p1_v3.ESPACE_REVUE_P1):
        porteur = json.loads(base64.b64decode(valeur, validate=True).decode("utf-8"))
        self.assertEqual(set(porteur), {"document", "signature", "principal"})
        document = dict(porteur["document"])
        if modifier_document:
            modifier_document(document)
        with tempfile.TemporaryDirectory() as tmp:
            dossier = Path(tmp)
            autorises = dossier / "allowed_signers"
            type_cle, cle = self.b.cle.with_suffix(".pub").read_text("utf-8").split()[:2]
            autorises.write_text(
                f'{porteur["principal"]} namespaces="{espace}" {type_cle} {cle}\n',
                encoding="utf-8",
            )
            signature = dossier / "observation.sig"
            signature.write_text(porteur["signature"], encoding="utf-8")
            resultat = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-f", str(autorises),
                 "-I", porteur["principal"], "-n", espace, "-s", str(signature)],
                input=revue.canonique(document),
                capture_output=True,
            )
        return porteur, resultat.returncode == 0

    def test_surface_publique_fermee_sans_decision_injectable(self):
        publiques = {
            nom for nom, valeur in vars(pont_p1_v3).items()
            if callable(valeur) and not nom.startswith("_")
            and getattr(valeur, "__module__", None) == "pont_p1_v3"
        }
        self.assertEqual(publiques, {
            "ConfigPontV3Test", "ResultatPontV3Test",
            "verifier_consommer_et_signer_test_non_autorisant",
        })
        self.assertEqual(
            list(inspect.signature(
                pont_p1_v3.verifier_consommer_et_signer_test_non_autorisant
            ).parameters),
            ["config", "request_id", "alias", "pointe", "registre"],
        )
        arbre = ast.parse(Path(pont_p1_v3.__file__).read_text("utf-8"))
        for noeud in arbre.body:
            if isinstance(noeud, (ast.FunctionDef, ast.AsyncFunctionDef)):
                noms = {a.arg for a in noeud.args.args + noeud.args.kwonlyargs}
                self.assertFalse(noms & PARAMETRES_INTERDITS, (noeud.name, noms))

    def test_document_p1_exact_signature_ssh_reelle_mais_non_autorisante(self):
        self.b.publier()
        resultat = self.b.operer()
        self.assertEqual(
            (resultat.cryptographiquement_valide,
             resultat.conforme_au_contrat,
             resultat.acceptable_p1),
            (True, True, False),
        )
        self.assertEqual(resultat.nature, "simulation-hors-ligne-non-autorisante")
        self.assertNotIn("Approval-Attestation", resultat.trailers)
        porteur, valide = self.verifier_signature_p1(
            resultat.trailers["Review-Attestation"]
        )
        self.assertTrue(valide)
        document = porteur["document"]
        self.assertEqual(set(document), CLES_P1)
        self.assertEqual(document["format"], "olistic.gouvernance.attestation/1")
        self.assertEqual(document["role"], "revue")
        self.assertEqual(document["classe"], "B")
        self.assertEqual(document["auteur"], "codex")
        self.assertEqual(document["relecteur"], "claude-family")
        self.assertEqual(document["depot"], "test.invalid/paquet-p1")
        self.assertTrue(document["reference_revue"].startswith(
            pont_p1_v3.PREFIXE_REFERENCE_TEST
        ))
        self.assertIsNone(document["reference_approbation"])
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.SIGNE)

    def test_synthetique_meme_signee_refusee_avant_consommation(self):
        predicat = aide_v3.predicat_v3(self.b.sujet)
        self.b.publier(predicat=predicat)
        self.assertEqual(
            self.motif(self.b.operer), "attestation_synthetique_refusee"
        )
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.DISPONIBLE)

    def test_rejeu_apres_signature_refuse(self):
        self.b.publier()
        self.b.operer()
        self.assertEqual(self.motif(self.b.operer), "request_id_deja_consomme")
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.SIGNE)

    def test_cas_a_defavorable_autre_demande_refuse_sans_effet_dans_tout_ordre(self):
        favorable = crypto.resultat_v3(crypto.predicat_crypto(self.b.sujet))
        predicat_defavorable = crypto.predicat_crypto(
            self.b.sujet, request_id="f" * 32, verdict="DEFAVORABLE"
        )
        predicat_defavorable["demande"]["issue"] = 8
        defavorable = crypto.resultat_v3(predicat_defavorable)
        for ordre in ((favorable, defavorable), (defavorable, favorable)):
            self.b.reinitialiser_attestations()
            for resultat in ordre:
                self.b.gh.publier(resultat)
            self.assertEqual(
                self.refuser_sans_signature_ni_consommation(),
                "decision_v3_incoherente",
            )

    def test_cas_b_defavorable_ulterieure_meme_demande_refuse_sans_effet(self):
        favorable = crypto.resultat_v3(crypto.predicat_crypto(self.b.sujet))
        instant_ulterieur = revue.format_instant(
            crypto.MAINTENANT - datetime.timedelta(minutes=4, seconds=30)
        )
        defavorable = crypto.resultat_v3(crypto.predicat_crypto(
            self.b.sujet, verdict="DEFAVORABLE", instant=instant_ulterieur
        ))
        for ordre in ((favorable, defavorable), (defavorable, favorable)):
            self.b.reinitialiser_attestations()
            for resultat in ordre:
                self.b.gh.publier(resultat)
            self.assertEqual(
                self.refuser_sans_signature_ni_consommation(),
                "decision_v3_incoherente",
            )

    def test_double_consommation_concurrente_une_seule_signature(self):
        self.b.publier()
        resultats = []
        barriere = threading.Barrier(4)

        def tenter():
            barriere.wait()
            try:
                self.b.operer()
                resultats.append("signe")
            except revue.Refus as e:
                resultats.append(e.motif)

        fils = [threading.Thread(target=tenter) for _ in range(4)]
        for fil in fils:
            fil.start()
        for fil in fils:
            fil.join()
        self.assertEqual(resultats.count("signe"), 1, resultats)
        self.assertTrue(
            set(resultats) - {"signe"}
            <= {"request_id_deja_reserve", "request_id_deja_consomme"},
            resultats,
        )

    def test_echec_apres_reservation_ne_rouvre_jamais_la_demande(self):
        self.b.publier()
        config = pont_p1_v3.ConfigPontV3Test(
            **{**vars(self.b.config), "cle_test": "/cle/test/inexistante"}
        )
        self.assertEqual(
            self.motif(self.b.operer, config=config), "signature_test_impossible"
        )
        etat, detail = self.b.registre.etat(aide.RID)
        self.assertEqual((etat, detail["motif"]), (R.ECHEC, "signature_test_impossible"))
        self.assertEqual(self.motif(self.b.operer), "request_id_deja_consomme")

    def test_sujet_ou_pointe_substitue_refuse_avant_consommation(self):
        self.b.publier()
        self.assertEqual(
            self.motif(self.b.operer, pointe=self.b.candidat.c2),
            "aucune_attestation_pour_la_demande",
        )
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.DISPONIBLE)

    def test_attestation_revoquee_refusee_avant_consommation(self):
        resultat = self.b.publier()
        self.b.ecrire_confiance(crypto.confiance_v3(
            revocations=[crypto.empreinte_enonce(resultat)]
        ))
        self.assertEqual(self.motif(self.b.operer), "attestation_revoquee")
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.DISPONIBLE)

    def test_approval_fabriquee_ne_peut_etre_injectee_ni_produite(self):
        self.b.publier()
        with self.assertRaises(TypeError):
            pont_p1_v3.verifier_consommer_et_signer_test_non_autorisant(
                self.b.config,
                aide.RID,
                "auto-test",
                self.b.candidat.c3,
                self.b.registre,
                approval_attestation="fabriquee",
            )
        resultat = self.b.operer()
        self.assertNotIn("Approval-Attestation", resultat.trailers)
        self.assertIsNone(resultat.document["reference_approbation"])

    def test_decision_autorisante_fabriquee_est_refusee_par_la_porte_dormante(self):
        forgee = pont_p1_v3.verifier3.DecisionCryptographique(
            cryptographiquement_valide=True,
            conforme_au_contrat=True,
            acceptable_p1=True,
            nature="cryptographique-sigstore",
            motif="politique_dormante",
            verdict="FAVORABLE",
            predicat=crypto.predicat_crypto(self.b.sujet),
        )
        with mock.patch.object(
            pont_p1_v3.verifier3, "verifier_cryptographique", return_value=forgee
        ):
            self.assertEqual(self.motif(self.b.operer), "activation_interdite")
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.DISPONIBLE)

    def test_motif_defavorable_avec_verdict_favorable_est_refuse_par_le_pont(self):
        forgee = pont_p1_v3.verifier3.DecisionCryptographique(
            cryptographiquement_valide=True,
            conforme_au_contrat=True,
            acceptable_p1=False,
            nature="cryptographique-sigstore",
            motif="verdict_defavorable",
            verdict="FAVORABLE",
            predicat=crypto.predicat_crypto(self.b.sujet),
        )
        with mock.patch.object(
            pont_p1_v3.verifier3, "verifier_cryptographique", return_value=forgee
        ):
            self.assertEqual(
                self.refuser_sans_signature_ni_consommation(),
                "decision_v3_incoherente",
            )

    def test_v1_decision_favorable_predicat_defavorable_refuse_sans_effet(self):
        forgee = pont_p1_v3.verifier3.DecisionCryptographique(
            cryptographiquement_valide=True,
            conforme_au_contrat=True,
            acceptable_p1=False,
            nature="cryptographique-sigstore",
            motif="politique_dormante",
            verdict="FAVORABLE",
            predicat=crypto.predicat_crypto(self.b.sujet, verdict="DEFAVORABLE"),
        )
        with mock.patch.object(
            pont_p1_v3.verifier3, "verifier_cryptographique", return_value=forgee
        ):
            self.assertEqual(
                self.refuser_sans_signature_ni_consommation(),
                "decision_v3_incoherente",
            )

    def test_predicat_absent_malforme_ou_sans_verdict_est_refuse_sans_effet(self):
        sans_verdict = crypto.predicat_crypto(self.b.sujet)
        sans_verdict.pop("verdict")
        variantes = {
            "absent": None,
            "malforme": [],
            "verdict_absent": sans_verdict,
            "indetermine": crypto.predicat_crypto(
                self.b.sujet, verdict="INDETERMINE"
            ),
        }
        for nom, predicat in variantes.items():
            with self.subTest(nom=nom):
                forgee = pont_p1_v3.verifier3.DecisionCryptographique(
                    cryptographiquement_valide=True,
                    conforme_au_contrat=True,
                    acceptable_p1=False,
                    nature="cryptographique-sigstore",
                    motif="politique_dormante",
                    verdict="FAVORABLE",
                    predicat=predicat,
                )
                with mock.patch.object(
                    pont_p1_v3.verifier3,
                    "verifier_cryptographique",
                    return_value=forgee,
                ):
                    self.assertEqual(
                        self.refuser_sans_signature_ni_consommation(),
                        "decision_v3_incoherente",
                    )

    def test_substitution_de_reservation_entre_verification_et_signature(self):
        self.b.publier()
        nom = f"{R.PREFIXE}/{aide.RID}/reserve"
        creer_original = self.b.transport.creer_ref

        def creer_puis_substituer(ref, contenu):
            cree = creer_original(ref, contenu)
            if ref == nom and cree:
                self.b.transport.alteration_lecture[ref] = revue.canonique({
                    "etat": R.RESERVE,
                    "liaison": {"sujet_sha256": "f" * 64},
                })
            return cree

        self.b.transport.creer_ref = creer_puis_substituer
        self.assertEqual(self.motif(self.b.operer), "reservation_substituee")

    def test_configuration_ou_registre_operationnels_interdits(self):
        self.b.publier()
        transport_github = R.TransportRefsGitHub(
            "https://api.github.test.invalid", "x/y", "test", http=lambda *a: (404, None)
        )
        registre_github = R.RegistreConsommation(transport_github)
        self.assertEqual(
            self.motif(self.b.operer, registre_test=registre_github),
            "registre_operationnel_interdit",
        )
        for changements in (
            {"principal_test": "relecteur-production"},
            {"depot_p1_test": "github.com/production/depot"},
            {"protocoles": ("https",)},
            {"jeton": "secret-test"},
        ):
            with self.subTest(changements=changements):
                config = pont_p1_v3.ConfigPontV3Test(
                    **{**vars(self.b.config), **changements}
                )
                self.assertEqual(
                    self.motif(self.b.operer, config=config),
                    "configuration_test_invalide",
                )
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.DISPONIBLE)

    def test_signature_ssh_modifiee_ou_namespace_approbation_refusee(self):
        self.b.publier()
        resultat = self.b.operer()
        valeur = resultat.trailers["Review-Attestation"]
        _, valide = self.verifier_signature_p1(
            valeur, modifier_document=lambda d: d.update(pointe="f" * 40)
        )
        self.assertFalse(valide)
        _, valide = self.verifier_signature_p1(
            valeur, espace="olistic-gouvernance-approbation"
        )
        self.assertFalse(valide)

    def test_creation_unique_persiste_entre_processus(self):
        contexte = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as tmp:
            barriere = contexte.Barrier(4)
            queue = contexte.Queue()
            processus = [
                contexte.Process(
                    target=_reserver_dans_processus,
                    args=(tmp, barriere, queue),
                )
                for _ in range(4)
            ]
            for processus_unitaire in processus:
                processus_unitaire.start()
            for processus_unitaire in processus:
                processus_unitaire.join(10)
                self.assertEqual(processus_unitaire.exitcode, 0)
            resultats = [queue.get(timeout=2) for _ in processus]
            registre = R.RegistreConsommation(crypto.TransportFichierAtomique(tmp))
            self.assertEqual(registre.etat(aide.RID)[0], R.RESERVE)
        self.assertEqual(resultats.count("reserve"), 1, resultats)
        self.assertEqual(resultats.count("request_id_deja_reserve"), 3, resultats)


if __name__ == "__main__":
    unittest.main()

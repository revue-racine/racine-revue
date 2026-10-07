"""Consommateur : provenance complète, politique et protocole épinglés,
fraîcheur, révocation, rejeu, agrégation sans seuil de longueur."""
import datetime
import json
import tempfile
import unittest
from pathlib import Path

import aide
from aide import revue
import verifier

T = aide.MAINTENANT
AUTRE_RID = "f" * 32


class TestVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cand = aide.DepotCandidat()
        cls.sujet = aide.sujet_pour(cls.cand, cls.cand.c3)

    @classmethod
    def tearDownClass(cls):
        cls.cand.nettoyer()

    def setUp(self):
        self.conf = aide.confiance()
        self.pol = aide.politique_ancree()

    def evaluer(self, resultats, sujet=None, rid=aide.RID, conf=None, pol=None, maintenant=T):
        return verifier.evaluer(resultats, sujet or self.sujet, rid, conf or self.conf, pol or self.pol, maintenant)

    def bon(self, **kw):
        return aide.resultat(aide.predicat(self.sujet, **kw))

    def motif(self, resultats, **kw):
        d = self.evaluer(resultats, **kw)
        self.assertFalse(d.acceptee, d)
        return d["motif"]

    # --- acceptation

    def test_favorable_accepte(self):
        d = self.evaluer([self.bon()])
        self.assertTrue(d.acceptee, d)
        self.assertEqual(d["request_id"], aide.RID)

    # --- provenance (§7)

    def test_certificat_falsifie_champ_par_champ(self):
        base = f"https://github.com/{aide.PROPRIETAIRE}/{aide.DEPOT}"
        alterations = {
            "issuer": "https://accounts.google.com",
            "sourceRepositoryURI": "https://github.com/intrus/racine",
            "sourceRepositoryOwnerURI": "https://github.com/intrus",
            "sourceRepositoryRef": "refs/heads/proposition",
            "sourceRepositoryIdentifier": "123",
            "sourceRepositoryOwnerIdentifier": "456",
            "sourceRepositoryVisibilityAtSigning": "private",
            "buildSignerURI": f"{base}/.github/workflows/autre.yml@refs/heads/main",
            "buildConfigURI": f"{base}/.github/workflows/revue.yml@refs/heads/autre",
            "runnerEnvironment": "self-hosted",
            "buildTrigger": "workflow_dispatch",
            "githubWorkflowTrigger": "workflow_dispatch",
            "githubWorkflowRepository": "intrus/racine",
            "githubWorkflowRef": "refs/heads/autre",
            "githubWorkflowName": "autre",
            "buildSignerDigest": "b" * 40,
            "buildConfigDigest": "b" * 40,
            "githubWorkflowSHA": "b" * 40,
            "runInvocationURI": "https://github.com/intrus/racine/actions/runs/1",
        }
        for champ, valeur in alterations.items():
            cert = aide.certificat_conforme()
            cert[champ] = valeur
            m = self.motif([aide.resultat(aide.predicat(self.sujet), cert=cert)])
            self.assertTrue(m.startswith("certificat:"), (champ, m))
        cert = aide.certificat_conforme()
        del cert["githubWorkflowName"]
        self.assertTrue(self.motif([aide.resultat(aide.predicat(self.sujet), cert=cert)]).startswith("certificat:"))

    def test_commit_du_workflow_non_epingle(self):
        cert = aide.certificat_conforme(commit="c" * 40)
        self.assertEqual(self.motif([aide.resultat(aide.predicat(self.sujet), cert=cert)]),
                         "certificat:commit_workflow_non_epingle")

    def test_renommage_du_depot_de_confiance(self):
        """Même identifiants numériques, autre nom : rejet jusqu'à réépinglage."""
        cert = aide.certificat_conforme()
        nouveau = f"https://github.com/{aide.PROPRIETAIRE}/racine-renommee"
        cert.update(sourceRepositoryURI=nouveau, githubWorkflowRepository=f"{aide.PROPRIETAIRE}/racine-renommee",
                    buildSignerURI=f"{nouveau}/.github/workflows/revue.yml@refs/heads/main",
                    buildConfigURI=f"{nouveau}/.github/workflows/revue.yml@refs/heads/main",
                    runInvocationURI=f"{nouveau}/actions/runs/1")
        self.assertTrue(self.motif([aide.resultat(aide.predicat(self.sujet), cert=cert)]).startswith("certificat:"))

    def test_transfert_ou_recreation_du_depot(self):
        for champ in ("sourceRepositoryOwnerIdentifier", "sourceRepositoryIdentifier"):
            cert = aide.certificat_conforme()
            cert[champ] = "999"
            self.assertEqual(self.motif([aide.resultat(aide.predicat(self.sujet), cert=cert)]), f"certificat:{champ}")

    def test_type_intoto_invalide(self):
        for t in ("https://in-toto.io/Statement/v0.1", "", None):
            self.assertEqual(self.motif([aide.resultat(aide.predicat(self.sujet), type_intoto=t)]), "type_intoto")

    def test_type_de_predicat(self):
        r = aide.resultat(aide.predicat(self.sujet), type_predicat="https://slsa.dev/provenance/v1")
        self.assertEqual(self.motif([r]), "type_predicat")

    def test_mauvais_nom_de_sujet(self):
        for nom in (f"olistic-revue:candidat@{self.cand.c3}", f"olistic-revue:candidat@{self.cand.c3}#{AUTRE_RID}",
                    f"olistic-revue:auto-test@{self.cand.c3}#{aide.RID}", "x"):
            self.assertEqual(self.motif([aide.resultat(aide.predicat(self.sujet), nom=nom)]), "nom_sujet", nom)

    def test_modele_non_autorise(self):
        p = aide.predicat(self.sujet)
        p["relecteur"]["modele"] = "autre-modele"
        self.assertEqual(self.motif([aide.resultat(p)]), "modele_non_autorise")

    # --- sujet et base

    def test_attestation_d_un_autre_commit(self):
        autre = aide.sujet_pour(self.cand, self.cand.c2)
        self.assertEqual(self.motif([aide.resultat(aide.predicat(autre))]), "digest_sujet")

    def test_meme_pointe_base_differente(self):
        """Attestation calculée sur une autre base (ancre c2, qui exclut le
        changement dangereux) : le consommateur recalcule avec SON ancre (c1)."""
        sur_c2 = aide.sujet_pour(self.cand, self.cand.c3, ancre=self.cand.c2)
        self.assertEqual(self.motif([aide.resultat(aide.predicat(sur_c2))]), "digest_sujet")

    def test_predicat_altere_sous_un_digest_valide(self):
        p = aide.predicat(self.sujet)
        p["sujet"]["pointe"]["arbre"] = "0" * 40
        self.assertEqual(self.motif([aide.resultat(p, sujet=self.sujet)]), "sujet_divergent")

    def test_predicat_hors_schema(self):
        for v in ("APPROUVE", "FAVORABLE_AVEC_CORRECTIONS"):
            p = aide.predicat(self.sujet)
            p["verdict"] = v
            self.assertEqual(self.motif([aide.resultat(p)]), "predicat_invalide", v)

    # --- politique, protocole, relecteur (§2)

    def test_politique_attestee_differente(self):
        p = aide.predicat(self.sujet)
        p["politique"]["sha256"] = "1" * 64
        self.assertEqual(self.motif([aide.resultat(p)]), "politique_differente")
        self.assertEqual(self.motif([self.bon()], conf=aide.confiance(politique_sha256="2" * 64)), "politique_differente")

    def test_protocole_atteste_different(self):
        p = aide.predicat(self.sujet)
        p["protocole"]["sha256"] = "1" * 64
        self.assertEqual(self.motif([aide.resultat(p)]), "protocole_different")
        self.assertEqual(self.motif([self.bon()], conf=aide.confiance(protocole_sha256="2" * 64)), "protocole_different")

    def test_relecteur_acceptable_false(self):
        self.assertEqual(self.motif([self.bon()], pol=aide.politique_ancree(acceptable=False)),
                         "relecteur_non_acceptable")

    def test_relecteur_inactif(self):
        self.assertEqual(self.motif([self.bon()], pol=aide.politique_ancree(actif=False, acceptable=False)),
                         "relecteur_inactif")

    def test_factice_favorable_rejete_meme_signe(self):
        p = aide.predicat(self.sujet)
        p["relecteur"] = {"famille": "factice", "modele": None}
        self.assertIn(self.motif([aide.resultat(p)]), ("relecteur_inactif", "relecteur_non_acceptable"))

    def test_relecteur_revoque(self):
        """Révocation = PR : relecteur inactif, génération + 1, nouvelle coupure.
        Le consommateur réépingle ; les attestations antérieures tombent."""
        pol2 = aide.politique_ancree(actif=False, acceptable=False, generation=2,
                                     fraicheur=dict(self.pol["fraicheur"], coupure="2026-10-08T11:00:00Z"))
        conf2 = aide.confiance(generation=2, politique_sha256="9" * 64)
        self.assertEqual(self.motif([self.bon()], conf=conf2, pol=pol2), "politique_differente")

    # --- fraîcheur (§3)

    def test_attestation_anterieure_a_la_coupure(self):
        pol = aide.politique_ancree(fraicheur=dict(self.pol["fraicheur"], coupure="2026-10-08T11:59:00Z"))
        self.assertEqual(self.motif([self.bon()], pol=pol), "anterieure_a_la_coupure")

    def test_attestation_perimee(self):
        self.assertEqual(self.motif([self.bon()], maintenant=T + datetime.timedelta(days=8)), "attestation_perimee")

    def test_horodatage_absent_illisible_futur(self):
        p = aide.predicat(self.sujet)
        for h, m in (([], "horodatage_absent"), (None, "horodatage_absent"),
                     ([{"type": "Tlog", "timestamp": "hier"}], "horodatage_illisible"),
                     ([{"type": "Tlog"}], "horodatage_illisible"),
                     ([{"type": "Tlog", "timestamp": "2026-10-09T12:00:00Z"}], "horodatage_futur")):
            r = aide.resultat(p)
            if h is None:
                del r["verificationResult"]["verifiedTimestamps"]
            else:
                r["verificationResult"]["verifiedTimestamps"] = h
            self.assertEqual(self.motif([r]), m, h)

    def test_instant_du_predicat_incoherent_avec_l_horodatage(self):
        for decalage in (datetime.timedelta(hours=2), datetime.timedelta(minutes=-10)):
            p = aide.predicat(self.sujet, instant=revue.format_instant(T - datetime.timedelta(minutes=5) - decalage))
            r = aide.resultat(p, horodatages=[{"type": "Tlog", "timestamp": revue.format_instant(T - datetime.timedelta(minutes=5))}])
            self.assertEqual(self.motif([r]), "instant_incoherent", decalage)

    # --- rejeu, idempotence, agrégation (§6)

    def test_verification_pure_ne_consomme_rien(self):
        """evaluer n'a plus de registre facultatif : le rejeu relève du registre
        obligatoire du pont (test_pont_p1, test_registre)."""
        import inspect
        self.assertNotIn("deja_consommes", inspect.signature(verifier.evaluer).parameters)
        self.assertTrue(self.evaluer([self.bon()]).acceptee)
        self.assertTrue(self.evaluer([self.bon()]).acceptee)

    def test_attestation_d_une_autre_demande(self):
        self.assertEqual(self.motif([self.bon()], rid=AUTRE_RID), "aucune_attestation_pour_la_demande")

    def test_nombreuses_demandes_indeterminees_ne_bloquent_pas(self):
        autres = [aide.resultat(aide.predicat(self.sujet, verdict="INDETERMINE", request_id=f"{n:032x}"))
                  for n in range(1, 301)]
        self.assertTrue(self.evaluer(autres + [self.bon()] + autres).acceptee)

    def test_aucun_refus_par_longueur(self):
        self.assertTrue(self.evaluer([self.bon()] * 250).acceptee)

    def test_indetermine_seul_rejete(self):
        self.assertEqual(self.motif([self.bon(verdict="INDETERMINE")]), "aucun_verdict_acceptant")

    def test_reexecutions_concurrentes_deterministes(self):
        fav, defav = self.bon(), self.bon(verdict="DEFAVORABLE")
        for ordre in ([fav, defav], [defav, fav]):
            self.assertEqual(self.motif(ordre), "verdict_defavorable")
        a = self.evaluer([fav, self.bon(issue=8)])
        b = self.evaluer([self.bon(issue=8), fav])
        self.assertEqual((a.acceptee, a["predicat"]), (b.acceptee, b["predicat"]))

    def test_redemande_ne_lave_pas_un_defavorable(self):
        r = [aide.resultat(aide.predicat(self.sujet, verdict="DEFAVORABLE", request_id=AUTRE_RID)), self.bon()]
        self.assertEqual(self.motif(r), "defavorable_sur_le_meme_sujet")

    def test_defavorable_invalide_d_une_autre_demande_ignore(self):
        cert = aide.certificat_conforme()
        cert["sourceRepositoryIdentifier"] = "1"
        r = [aide.resultat(aide.predicat(self.sujet, verdict="DEFAVORABLE", request_id=AUTRE_RID), cert=cert), self.bon()]
        self.assertTrue(self.evaluer(r).acceptee)

    def test_vide_ou_illisible(self):
        self.assertEqual(self.motif([]), "aucune_attestation_pour_la_demande")
        self.assertEqual(self.motif([{"x": 1}]), "aucune_attestation_pour_la_demande")
        self.assertEqual(self.motif("x"), "resultats_illisibles")

    # --- configuration et commandes

    def test_commandes_gh_epinglees_et_sans_limite(self):
        cmd = verifier.commande_gh(self.conf, "/tmp/s.json", "/tmp/b.json")
        for opt, val in {"--repo": f"{aide.PROPRIETAIRE}/{aide.DEPOT}",
                         "--signer-workflow": f"{aide.PROPRIETAIRE}/{aide.DEPOT}/.github/workflows/revue.yml",
                         "--source-ref": "refs/heads/main",
                         "--cert-oidc-issuer": "https://token.actions.githubusercontent.com",
                         "--predicate-type": "urn:olistic:confiance:attestation-revue:1",
                         "--bundle": "/tmp/b.json", "--format": "json"}.items():
            self.assertEqual(cmd[cmd.index(opt) + 1], val, opt)
        self.assertIn("--deny-self-hosted-runners", cmd)
        self.assertNotIn("--limit", cmd)

    def test_charger_confiance_politique_epinglee(self):
        with tempfile.TemporaryDirectory() as tmp:
            pol = Path(tmp) / "pol.json"
            pol.write_text(json.dumps(aide.politique_ancree()))
            conf = Path(tmp) / "conf.json"
            conf.write_text(json.dumps(aide.confiance(politique_sha256=revue.sha256_hex(pol.read_bytes()))))
            verifier.charger_confiance(conf, pol)
            pol.write_text(pol.read_text() + " ")
            with self.assertRaises(revue.Refus) as cm:
                verifier.charger_confiance(conf, pol)
            self.assertEqual(cm.exception.motif, "politique_non_epinglee")


if __name__ == "__main__":
    unittest.main()

"""Analyse statique des workflows : déclencheurs, permissions, injection,
épinglage, secrets. Complète actionlint et zizmor, qui tournent en CI."""
import re
import unittest

import yaml

import aide

WF = aide.RACINE / ".github" / "workflows"
EPINGLES = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/attest": "1e69f48acb82d1966a394da916b4c1698aa569d6",
}
INTERDITS = {"workflow_dispatch", "pull_request_target", "repository_dispatch", "workflow_run",
             "workflow_call", "issue_comment", "schedule"}


def charger(nom):
    texte = (WF / nom).read_text("utf-8")
    doc = yaml.load(texte, Loader=yaml.BaseLoader)  # BaseLoader : `on` reste une chaîne
    return texte, doc


class TestWorkflows(unittest.TestCase):
    def setUp(self):
        self.wfs = {p.name: charger(p.name) for p in WF.glob("*.yml")}

    def test_inventaire_ferme(self):
        self.assertEqual(set(self.wfs), {"revue.yml", "controles.yml"})

    def test_declencheurs(self):
        self.assertEqual(self.wfs["revue.yml"][1]["on"], {"issues": {"types": ["opened"]}})
        self.assertEqual(set(self.wfs["controles.yml"][1]["on"]), {"pull_request", "push"})
        for nom, (_, doc) in self.wfs.items():
            self.assertFalse(INTERDITS & set(doc["on"]), nom)

    def test_permissions_vides_puis_minimales(self):
        for nom, (_, doc) in self.wfs.items():
            self.assertEqual(doc["permissions"], {}, nom)
            for job, d in doc["jobs"].items():
                self.assertIn("permissions", d, f"{nom}:{job}")
                self.assertIn("timeout-minutes", d, f"{nom}:{job}")
                self.assertEqual(d["runs-on"], "ubuntu-24.04", f"{nom}:{job}")
        jobs = self.wfs["revue.yml"][1]["jobs"]
        attendu = {
            "admission": {"contents": "read", "issues": "read"},
            "revue": {"contents": "read"},
            "attestation": {"contents": "read", "id-token": "write", "attestations": "write"},
            "reponse": {"contents": "read", "issues": "write"},
        }
        self.assertEqual({j: d["permissions"] for j, d in jobs.items()}, attendu)
        self.assertEqual(self.wfs["controles.yml"][1]["jobs"]["controles"]["permissions"], {"contents": "read"})

    def test_aucune_expression_dans_un_bloc_run(self):
        for nom, (_, doc) in self.wfs.items():
            for job, d in doc["jobs"].items():
                for etape in d["steps"]:
                    self.assertNotIn("${{", etape.get("run", ""), f"{nom}:{job}")

    def test_donnees_d_evenement_libres_jamais_exposees(self):
        for nom, (texte, _) in self.wfs.items():
            for m in re.findall(r"\$\{\{([^}]*)\}\}", texte):
                if "github.event" in m:
                    self.assertIn(m.strip(), {"github.event.issue.number"}, nom)

    def test_jeton_seulement_dans_env(self):
        for nom, (_, doc) in self.wfs.items():
            for d in doc["jobs"].values():
                for etape in d["steps"]:
                    self.assertNotIn("token", etape.get("run", "").lower().replace("gh_token", ""), nom)

    def test_pont_p1_absent_du_lot1(self):
        for nom, (texte, _) in self.wfs.items():
            self.assertNotIn("pont_p1", texte, nom)
            self.assertNotIn("ssh-keygen", texte, nom)

    def test_actions_epinglees_par_sha(self):
        for nom, (_, doc) in self.wfs.items():
            for d in doc["jobs"].values():
                for etape in d["steps"]:
                    if "uses" in etape:
                        action, _, ref = etape["uses"].partition("@")
                        self.assertEqual(EPINGLES.get(action), ref, f"{nom}: {etape['uses']}")

    def test_checkout_sans_identifiants_persistants(self):
        for nom, (_, doc) in self.wfs.items():
            for d in doc["jobs"].values():
                for etape in d["steps"]:
                    if etape.get("uses", "").startswith("actions/checkout@"):
                        self.assertEqual(etape.get("with", {}).get("persist-credentials"), "false", nom)
                        self.assertNotIn("ref", etape.get("with", {}), nom)
                        self.assertNotIn("repository", etape.get("with", {}), nom)

    def test_aucun_artifact_ni_runner_auto_heberge(self):
        for nom, (texte, _) in self.wfs.items():
            self.assertNotIn("upload-artifact", texte, nom)
            self.assertNotIn("self-hosted", texte, nom)

    def test_lot2_secret_unique_dans_le_seul_step_de_relecture(self):
        """Lot 2 : exactement une référence de secret, la clé du relecteur, dans
        le seul step `revue` du job `revue`, attaché à l'environnement dédié.
        Aucun autre job (signature compris) ne voit ni secret ni environnement."""
        self.assertNotIn("secrets.", self.wfs["controles.yml"][0])
        self.assertNotIn("environment:", self.wfs["controles.yml"][0])
        texte, doc = self.wfs["revue.yml"]
        self.assertEqual(texte.count("secrets."), 1)
        self.assertEqual(texte.count("environment:"), 1)
        jobs = doc["jobs"]
        for job, d in jobs.items():
            if job != "revue":
                self.assertNotIn("environment", d, job)
                self.assertNotIn("secrets.", repr(d), job)
        self.assertEqual(jobs["revue"]["environment"], "relecteur-openai")
        avec_secret = [e for e in jobs["revue"]["steps"] if "secrets." in repr(e)]
        self.assertEqual(len(avec_secret), 1)
        self.assertEqual(avec_secret[0]["id"], "revue")
        self.assertEqual(avec_secret[0]["env"]["CLE_RELECTEUR"], "${{ secrets.CLE_RELECTEUR_OPENAI }}")
        self.assertNotIn("secrets.", avec_secret[0]["run"])

    def test_lot2_relecture_serialisee(self):
        self.assertEqual(self.wfs["revue.yml"][1]["jobs"]["revue"]["concurrency"],
                         {"group": "revue-relecteur", "cancel-in-progress": "false"})

    def test_lot2_producteur_v2_seulement(self):
        """Après le Lot 2, le workflow ne produit que des attestations revue/2 :
        aucune sous-commande du producteur v1 n'est appelée."""
        texte = self.wfs["revue.yml"][0]
        self.assertNotIn("outils/revue.py", texte)
        for cmd in ("admission", "revue", "preparer", "reponse"):
            self.assertIn(f"python3 -I outils/revue2.py {cmd} ", texte)

    def test_seul_le_job_attestation_signe(self):
        jobs = self.wfs["revue.yml"][1]["jobs"]
        for job, d in jobs.items():
            utilise_attest = any(e.get("uses", "").startswith("actions/attest@") for e in d["steps"])
            self.assertEqual(utilise_attest, job == "attestation", job)
        attest = [e for e in jobs["attestation"]["steps"] if "uses" in e and "attest@" in e["uses"]][0]["with"]
        self.assertEqual(attest["predicate-type"], "urn:olistic:confiance:attestation-revue:2")
        self.assertEqual(attest["create-storage-record"], "false")
        self.assertNotIn("subject-path", attest)
        self.assertIn("steps.preparer.outputs", attest["subject-digest"])

    def test_signature_conditionnee_au_recalcul(self):
        jobs = self.wfs["revue.yml"][1]["jobs"]
        ids = [e.get("id") for e in jobs["attestation"]["steps"]]
        self.assertLess(ids.index("preparer"), ids.index("attest"))
        self.assertEqual(jobs["attestation"]["needs"], ["admission", "revue"])
        self.assertEqual(jobs["revue"]["if"], "needs.admission.outputs.admis == 'oui'")

    def test_garde_de_branche(self):
        etapes = self.wfs["revue.yml"][1]["jobs"]["admission"]["steps"]
        self.assertIn("refs/heads/main", etapes[0]["if"])
        self.assertEqual(etapes[0]["run"].strip(), "exit 1")

    def test_python_isole(self):
        for nom, (_, doc) in self.wfs.items():
            for d in doc["jobs"].values():
                for etape in d["steps"]:
                    for ligne in etape.get("run", "").splitlines():
                        if "outils/" in ligne:
                            self.assertIn("python3 -I outils/", ligne, nom)


if __name__ == "__main__":
    unittest.main()

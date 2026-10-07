"""Pont P2 → P1 : une seule opération `verifier_consommer_et_signer`, qui part
des références, récupère et vérifie elle-même les attestations, consomme le
request_id de façon atomique, puis construit et signe le document P1.

Doublures : API GitHub (`bundle_url`) et vérification cryptographique simulée
qui n'accepte que les bundles publiés par la racine. Clés SSH de test
éphémères, détruites en fin de test."""
import ast
import base64
import inspect
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import aide
from aide import revue
import pont_p1
import registre as R
import verifier

# Contrat P1 (paquet 4G.3.1, figé) recopié pour comparaison.
CLES_P1 = {"format", "role", "depot", "pointe", "arbre", "classe", "auteur", "relecteur", "reference_revue",
           "reference_approbation", "instant"}
PARAMETRES_INTERDITS = {"decision", "document", "doc", "octets", "donnees", "predicat", "verdict", "resultat",
                        "resultats", "acceptee", "signature", "valeur"}


def octets_observation_p1(document):
    return json.dumps(document, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class Banc:
    """Racine simulée + candidat + configuration du pont, dans un dossier jetable."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.cand = aide.DepotCandidat()
        self.sujet = aide.sujet_pour(self.cand, self.cand.c3)
        pol = d / "politique.json"
        pol.write_text(json.dumps(aide.politique_ancree()))
        self.pol_sha = revue.sha256_hex(pol.read_bytes())
        conf = d / "confiance.json"
        conf.write_text(json.dumps(aide.confiance(politique_sha256=self.pol_sha)))
        anc = d / "ancres.json"
        anc.write_text(json.dumps({"format": "olistic.confiance.ancres/1",
                                   "ancres": list(self.cand.ancres().values())}))
        self.cle = d / "cle_test"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", str(self.cle)], check=True)
        self.config = pont_p1.ConfigPont(confiance=str(conf), politique=str(pol), ancres=str(anc), cle=str(self.cle),
                                         principal="relecteur-p2", depot_p1="github.com/exemple/depot",
                                         url_candidat=str(self.cand.chemin), protocoles=("file",))
        self.gh = aide.FauxGitHub()
        self.transport = aide.TransportMemoire()
        self.registre = R.RegistreConsommation(self.transport)
        self._patchs = [mock.patch.object(verifier, "_verifier_crypto", self.gh.verifier_crypto),
                        mock.patch.object(verifier, "_http_get", self.gh.http),
                        mock.patch.object(pont_p1, "_horloge", lambda: aide.MAINTENANT)]
        for p in self._patchs:
            p.start()

    def publier(self, signe=True, **kw):
        p = aide.predicat(self.sujet, **kw)
        p["politique"]["sha256"] = self.pol_sha
        return self.gh.publier(aide.resultat(p), signe=signe)

    def operer(self, rid=aide.RID, config=None, registre="defaut"):
        return pont_p1.verifier_consommer_et_signer(config or self.config, rid, "candidat", self.cand.c3,
                                                    self.registre if registre == "defaut" else registre)

    def fermer(self):
        for p in self._patchs:
            p.stop()
        self.cand.nettoyer()
        self.tmp.cleanup()


class TestPontP1(unittest.TestCase):
    def setUp(self):
        self.b = Banc()
        self.addCleanup(self.b.fermer)

    def motif(self, f, *a, **k):
        with self.assertRaises(revue.Refus) as cm:
            f(*a, **k)
        return cm.exception.motif

    def verifier_comme_p1(self, valeur, espace="olistic-gouvernance-revue"):
        o = json.loads(base64.b64decode(valeur, validate=True).decode("utf-8"))
        self.assertEqual(set(o), {"document", "signature", "principal"})
        with tempfile.TemporaryDirectory() as tmp:
            autorises = Path(tmp) / "allowed_signers"
            cle = self.b.cle.with_suffix(".pub").read_text().split()[:2]
            autorises.write_text(f'{o["principal"]} namespaces="{espace}" {" ".join(cle)}\n')
            sig = Path(tmp) / "observation.sig"
            sig.write_text(o["signature"])
            r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(autorises), "-I", o["principal"], "-n", espace,
                                "-s", str(sig)], input=octets_observation_p1(o["document"]), capture_output=True)
        return o, r.returncode == 0

    # --- surface : aucune injection possible

    def test_surface_publique_fermee(self):
        publiques = {n for n, v in vars(pont_p1).items() if callable(v) and not n.startswith("_")
                     and getattr(v, "__module__", None) == "pont_p1"}
        self.assertEqual(publiques, {"ConfigPont", "verifier_consommer_et_signer"})
        self.assertEqual(list(inspect.signature(pont_p1.verifier_consommer_et_signer).parameters),
                         ["config", "request_id", "alias", "pointe", "registre"])

    def test_aucune_fonction_du_module_ne_recoit_decision_document_ou_octets(self):
        arbre = ast.parse(Path(pont_p1.__file__).read_text("utf-8"))
        for noeud in arbre.body:
            if isinstance(noeud, (ast.FunctionDef, ast.AsyncFunctionDef)):
                noms = {a.arg for a in noeud.args.args + noeud.args.kwonlyargs}
                self.assertFalse(noms & PARAMETRES_INTERDITS, (noeud.name, noms & PARAMETRES_INTERDITS))
            if isinstance(noeud, ast.ClassDef) and noeud.name != "ConfigPont":
                self.fail(f"classe inattendue : {noeud.name}")
        self.assertNotIn("ssh-keygen", "".join(ast.get_source_segment(Path(pont_p1.__file__).read_text(), n) or ""
                                               for n in arbre.body if isinstance(n, ast.FunctionDef)
                                               and n.name != "verifier_consommer_et_signer"))

    def test_decision_forgee_impossible_a_injecter(self):
        self.b.publier()
        forgee = verifier.Decision(acceptee=True, verdicts=["FAVORABLE"], predicat={}, instant_verifie="x")
        with self.assertRaises(TypeError):
            pont_p1.verifier_consommer_et_signer(self.b.config, aide.RID, "candidat", self.b.cand.c3, self.b.registre,
                                                 decision=forgee)
        for faux in (forgee, {"acceptee": True}, True):
            self.assertEqual(self.motif(self.b.operer, registre=faux), "registre_absent")
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.DISPONIBLE)

    def test_verdict_favorable_forge_refuse(self):
        self.b.publier(signe=False)  # bundle FAVORABLE fabriqué hors de la racine
        self.assertEqual(self.motif(self.b.operer), "verification_cryptographique")
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.DISPONIBLE)

    def test_aucune_attestation_echec_avant_consommation_puis_reussite(self):
        self.assertEqual(self.motif(self.b.operer), "non_acceptee")
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.DISPONIBLE)
        self.b.publier()
        self.assertIn("Review-Attestation", self.b.operer())

    def test_indetermine_ou_defavorable_refuses(self):
        self.b.publier(verdict="INDETERMINE")
        self.assertEqual(self.motif(self.b.operer), "non_acceptee")
        self.b.publier(verdict="DEFAVORABLE", issue=8)
        self.assertEqual(self.motif(self.b.operer), "non_acceptee")

    # --- chemin nominal

    def test_vraie_attestation_document_p1_exact_et_signature_verifiable(self):
        self.b.publier()
        t = self.b.operer()
        o, ok = self.verifier_comme_p1(t["Review-Attestation"])
        self.assertTrue(ok)
        doc = o["document"]
        self.assertEqual(set(doc), CLES_P1)
        self.assertEqual((doc["format"], doc["role"], doc["relecteur"]),
                         ("olistic.gouvernance.attestation/1", "revue", "gpt-codex-family"))
        self.assertEqual(doc["pointe"], self.b.cand.c3)
        self.assertEqual(doc["arbre"], aide.git(self.b.cand.chemin, "rev-parse", self.b.cand.c3 + "^{tree}"))
        self.assertEqual((doc["classe"], doc["auteur"]), ("A", "claude"))
        self.assertIsNone(doc["reference_approbation"])
        self.assertEqual((t["Reviewed-commit"], t["Review-Reference"], t["Agent"]),
                         (doc["pointe"], doc["reference_revue"], doc["auteur"]))
        etat, detail = self.b.registre.etat(aide.RID)
        self.assertEqual(etat, R.SIGNE)
        self.assertEqual(detail["document_sha256"], revue.sha256_hex(octets_observation_p1(doc)))
        self.assertFalse(self.verifier_comme_p1(t["Review-Attestation"], espace="olistic-gouvernance-approbation")[1])

    # --- rejeu, concurrence, atomicité

    def test_signer_deux_fois_refuse(self):
        self.b.publier()
        self.b.operer()
        self.assertEqual(self.motif(self.b.operer), "request_id_deja_consomme")
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.SIGNE)

    def test_deux_consommateurs_simultanes_une_seule_signature(self):
        self.b.publier()
        issues, barriere = [], threading.Barrier(4)

        def tenter():
            barriere.wait()
            try:
                self.b.operer()
                issues.append("signe")
            except revue.Refus as e:
                issues.append(e.motif)
        fils = [threading.Thread(target=tenter) for _ in range(4)]
        [f.start() for f in fils]
        [f.join() for f in fils]
        self.assertEqual(issues.count("signe"), 1, issues)
        self.assertTrue(set(issues) - {"signe"} <= {"request_id_deja_reserve", "request_id_deja_consomme"}, issues)

    def test_echec_apres_reservation_avant_signature(self):
        self.b.publier()
        mauvaise = pont_p1.ConfigPont(**{**vars(self.b.config), "cle": "/inexistante"})
        self.assertEqual(self.motif(self.b.operer, config=mauvaise), "signature_impossible")
        etat, detail = self.b.registre.etat(aide.RID)
        self.assertEqual((etat, detail["motif"]), (R.ECHEC, "signature_impossible"))
        self.assertEqual(self.motif(self.b.operer), "request_id_deja_consomme")  # jamais rouvert

    def test_substitution_entre_verification_et_signature(self):
        self.b.publier()
        nom = f"{R.PREFIXE}/{aide.RID}/reserve"
        original = self.b.transport.creer_ref

        def creer_puis_alterer(n, contenu):
            ok = original(n, contenu)
            if n == nom:
                autre = json.loads(contenu)
                autre["liaison"]["sujet_sha256"] = "0" * 64
                self.b.transport.alteration_lecture[n] = revue.canonique(autre)
            return ok
        self.b.transport.creer_ref = creer_puis_alterer
        self.assertEqual(self.motif(self.b.operer), "reservation_substituee")
        self.assertIn(f"{R.PREFIXE}/{aide.RID}/fin", self.b.transport.refs)  # clos, non signé
        self.assertNotIn(b"SIGNE", self.b.transport.refs[f"{R.PREFIXE}/{aide.RID}/fin"])

    def test_interruption_puis_etat_terminal_explicite(self):
        self.b.publier()
        self.b.transport.panne_creation = {"fin"}  # ni SIGNE ni ECHEC ne peuvent s'écrire
        self.assertEqual(self.motif(self.b.operer), "registre_injoignable")
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.RESERVE)  # diagnostic : réservé, jamais signé
        self.b.transport.panne_creation = set()
        self.b.registre.clore_en_echec(aide.RID, "interruption")
        self.assertEqual(self.b.registre.etat(aide.RID)[0], R.ECHEC)
        self.assertEqual(self.motif(self.b.operer), "request_id_deja_consomme")

    def test_ancien_request_id_refuse(self):
        self.b.publier()
        self.b.operer()
        self.b.publier(issue=9)
        self.assertEqual(self.motif(self.b.operer), "request_id_deja_consomme")


if __name__ == "__main__":
    unittest.main()

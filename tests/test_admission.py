"""Admission : la demande désigne, elle n'affirme rien ; doublons de request_id."""
import ast
import inspect
import json
import unittest
from unittest import mock

import aide
from aide import revue

C = "c" * 40


def corps(**extra):
    d = aide.demande(C)
    d.update(extra)
    return json.dumps(d)


def issue(numero, corps_, auteur_id=aide.DEMANDEUR_ID, type_auteur="User", pr=False, login="operateur"):
    i = {"number": numero, "body": corps_, "user": {"login": login, "id": auteur_id, "type": type_auteur}}
    if pr:
        i["pull_request"] = {}
    return i


class TestAdmission(unittest.TestCase):
    def setUp(self):
        self.pol = aide.politique_ancree()

    def refus(self, ev, anterieures=()):
        with self.assertRaises(revue.Refus) as cm:
            revue.admettre(ev, self.pol, anterieures)
        return cm.exception.motif

    def test_demande_conforme(self):
        a = revue.admettre(aide.evenement(corps()), self.pol)
        self.assertEqual(a, {"demande": aide.demande(C), "issue": 7, "demandeur_id": aide.DEMANDEUR_ID})

    def test_demandeur_non_liste(self):
        self.assertEqual(self.refus(aide.evenement(corps(), auteur_id=1)), "demandeur_non_autorise")

    def test_login_identique_id_different(self):
        self.assertEqual(self.refus(aide.evenement(corps(), auteur_id=aide.DEMANDEUR_ID + 1, login="operateur")),
                         "demandeur_non_autorise")

    def test_login_similaire_id_different(self):
        for login in ("0perateur", "operateur-", "Operateur"):
            self.assertEqual(self.refus(aide.evenement(corps(), auteur_id=42, login=login)), "demandeur_non_autorise")

    def test_compte_bot_refuse(self):
        self.assertEqual(self.refus(aide.evenement(corps(), type_auteur="Bot")), "demandeur_non_autorise")

    def test_seule_l_ouverture_declenche(self):
        for action in ("edited", "reopened", "labeled"):
            self.assertEqual(self.refus(aide.evenement(corps(), action=action)), "evenement_non_pris_en_charge")

    def test_base_fournie_par_le_demandeur_refusee(self):
        self.assertEqual(self.refus(aide.evenement(corps(base="b" * 40))), "demande_invalide")

    def test_champs_affirmatifs_refuses(self):
        for cle, val in (("verdict", "FAVORABLE"), ("arbre", "a" * 40), ("relecteur", "codex"),
                         ("perimetre_sha256", "0" * 64), ("predicat", {}), ("generation", 1)):
            self.assertEqual(self.refus(aide.evenement(corps(**{cle: val}))), "demande_invalide", cle)

    def test_declaration_p1_fermee(self):
        for decl in ({"classe": "C", "auteur": "claude"}, {"classe": "A"}, {"classe": "A", "auteur": "claude", "x": 1}):
            self.assertEqual(self.refus(aide.evenement(corps(declaration_p1=decl))), "demande_invalide")

    def test_request_id_mal_forme(self):
        for rid in ("", "0" * 31, "0" * 33, "G" * 32, "A" * 32):
            self.assertEqual(self.refus(aide.evenement(corps(request_id=rid))), "demande_invalide", rid)

    def test_titre_et_etiquettes_ignores(self):
        ev = aide.evenement(corps(), titre='{"verdict":"FAVORABLE"}')
        self.assertNotIn("verdict", revue.admettre(ev, self.pol)["demande"])

    def test_cle_en_double_nan_flottant(self):
        for brut in (corps()[:-1] + ',"pointe":"%s"}' % ("d" * 40), '{"x": NaN}', '{"x": 1.0}'):
            self.assertEqual(self.refus(aide.evenement(brut)), "demande_illisible")

    def test_corps_trop_long_ou_non_json(self):
        self.assertEqual(self.refus(aide.evenement(corps() + " " * 2000)), "demande_trop_longue")
        for brut in ("", "bonjour", "```json\n" + corps() + "\n```"):
            self.assertEqual(self.refus(aide.evenement(brut)), "demande_illisible")

    def test_depot_inconnu(self):
        self.assertEqual(self.refus(aide.evenement(corps(depot="inconnu"))), "depot_inconnu")

    # --- request_id : idempotence, doublons, concurrence

    def test_request_id_rejoue_dans_une_issue_ulterieure(self):
        ev = aide.evenement(corps(), numero=12)
        self.assertEqual(self.refus(ev, [issue(7, corps())]), "request_id_deja_utilise")

    def test_request_id_rejoue_avec_une_autre_pointe(self):
        ev = aide.evenement(corps(pointe="d" * 40), numero=12)
        self.assertEqual(self.refus(ev, [issue(7, corps())]), "request_id_deja_utilise")

    def test_concurrence_deterministe(self):
        """Deux issues ouvertes en même temps, mêmes request_id : chaque exécution
        voit l'autre ; seule la plus ancienne est admise, quel que soit l'ordre."""
        toutes = [issue(20, corps()), issue(21, corps())]
        a = revue.admettre(aide.evenement(corps(), numero=20), self.pol, toutes)
        self.assertEqual(a["issue"], 20)
        self.assertEqual(self.refus(aide.evenement(corps(), numero=21), list(reversed(toutes))),
                         "request_id_deja_utilise")

    def test_issue_anterieure_d_un_tiers_ignoree(self):
        """Un tiers ne peut pas « réserver » un request_id."""
        tiers = [issue(3, corps(), auteur_id=1), issue(4, corps(), type_auteur="Bot"), issue(5, corps(), pr=True)]
        self.assertEqual(revue.admettre(aide.evenement(corps(), numero=9), self.pol, tiers)["issue"], 9)

    def test_demandes_distinctes_sur_la_meme_pointe_admises(self):
        autres = [issue(n, corps(request_id=f"{n:032x}")) for n in range(1, 50)]
        self.assertEqual(revue.admettre(aide.evenement(corps(), numero=60), self.pol, autres)["issue"], 60)

    def test_issue_anterieure_illisible_ignoree(self):
        self.assertEqual(revue.admettre(aide.evenement(corps(), numero=9), self.pol,
                                        [issue(2, "n'importe quoi")])["issue"], 9)



class TestIdentiteNumerique(unittest.TestCase):
    """B1 : le login ne participe à aucune décision ; seul `user.id` compte."""

    def setUp(self):
        self.pol = aide.politique_ancree()

    def admettre(self, numero, anterieures, **kw):
        return revue.admettre(aide.evenement(corps(), numero=numero, **kw), self.pol, anterieures)

    def refus(self, numero, anterieures, **kw):
        with self.assertRaises(revue.Refus) as cm:
            self.admettre(numero, anterieures, **kw)
        return cm.exception.motif

    def test_meme_id_login_renomme_comportement_identique(self):
        for login in ("operateur", "nouveau-nom", "x"):
            self.assertEqual(self.admettre(9, [], login=login)["demandeur_id"], aide.DEMANDEUR_ID)
            self.assertEqual(self.refus(9, [issue(3, corps())], login=login), "request_id_deja_utilise")

    def test_meme_login_autre_id_jamais_assimile(self):
        self.assertEqual(self.refus(9, [], login="operateur", auteur_id=424242), "demandeur_non_autorise")
        usurpe = [issue(3, corps(), auteur_id=424242, login="operateur")]
        self.assertEqual(self.admettre(9, usurpe)["issue"], 9)  # ne réserve rien

    def test_historique_reparti_sur_ancien_et_nouveau_login(self):
        hist = [issue(2, corps(request_id="1" * 32), login="ancien"),
                issue(3, corps(), login="ancien"),
                issue(5, corps(request_id="2" * 32), login="nouveau")]
        self.assertEqual(self.refus(9, hist, login="nouveau"), "request_id_deja_utilise")

    def test_demandes_concurrentes_meme_id(self):
        toutes = [issue(20, corps(), login="ancien"), issue(21, corps(), login="nouveau")]
        self.assertEqual(self.admettre(20, toutes, login="ancien")["issue"], 20)
        self.assertEqual(self.refus(21, toutes, login="nouveau"), "request_id_deja_utilise")

    def test_changement_de_login_entre_deux_appels_api(self):
        """Page 1 lue sous l'ancien login, page 2 sous le nouveau : même ID, même
        résultat ; aucun appel ne filtre par login."""
        pages = {1: [issue(n, corps(request_id=f"{n:032x}"), login="ancien") for n in range(1, 101)],
                 2: [issue(150, corps(), login="nouveau")]}
        vus = []
        hist = revue.historique_anterieur(lambda p: vus.append(p) or pages.get(p, []), 200)
        self.assertEqual(vus, [1, 2])
        self.assertEqual(len(hist), 101)
        self.assertEqual(self.refus(200, hist, login="encore-autre"), "request_id_deja_utilise")

    def test_historique_identite_non_etablie_echec_ferme(self):
        for item in ({"number": 3, "user": None}, {"number": 3, "user": {"login": "operateur"}},
                     {"number": 3, "user": {"id": "900003"}}, {"number": "3", "user": {"id": 1}}, "x"):
            with self.assertRaises(revue.Refus) as cm:
                revue.historique_anterieur(lambda p: [item] if p == 1 else [], 10)
            self.assertEqual(cm.exception.motif, "historique_illisible", item)

    def test_historique_borne_et_complet(self):
        plein = [issue(n, "x") for n in range(1, 101)]
        with self.assertRaises(revue.Refus) as cm:
            revue.historique_anterieur(lambda p: plein, 50)  # pages pleines sans fin
        self.assertEqual(cm.exception.motif, "historique_trop_long")
        hist = revue.historique_anterieur(lambda p: [issue(60, "x"), issue(5, "y")] if p == 1 else [], 50)
        self.assertEqual([i["number"] for i in hist], [5])

    def test_appel_api_sans_creator_ni_login(self):
        urls = []

        class Rep:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"[]"

        def urlopen(req, timeout):
            urls.append(req.full_url)
            return Rep()
        env = {"GITHUB_API_URL": "https://api.github.com", "GITHUB_REPOSITORY": "p/r", "GH_TOKEN": "t"}
        with mock.patch.object(revue.urllib.request, "urlopen", urlopen):
            revue.lister_issues_api(env, 10)
        self.assertEqual(len(urls), 1)
        self.assertNotIn("creator", urls[0])
        self.assertIn("state=all", urls[0])

    def test_le_login_n_apparait_dans_aucune_decision(self):
        """Garde statique : aucune constante "login" dans le code (hors docstrings)
        des fonctions d'admission et d'historique."""
        source = inspect.getsource(revue)
        arbre = ast.parse(source)
        for f in arbre.body:
            if isinstance(f, ast.FunctionDef) and f.name in ("admettre", "_issue_de_demandeur", "historique_anterieur",
                                                             "lister_issues_api", "lire_demande"):
                for n in ast.walk(f):
                    if isinstance(n, ast.Constant) and isinstance(n.value, str) and "login" in n.value:
                        self.assertTrue(n.value.strip().startswith(("Rend", "Issue", "Toutes", "Historique")),
                                        (f.name, n.value[:40]))
                    if isinstance(n, ast.Name):
                        self.assertNotIn("login", n.id.lower(), f.name)


if __name__ == "__main__":
    unittest.main()

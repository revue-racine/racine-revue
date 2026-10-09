"""Transport fail-closed du relecteur, contre un serveur 127.0.0.1 : aucune
redirection, aucune reprise, délai total, plafond de taille, encodage, TLS,
aucun mandataire hérité. Aucun appel externe."""
import http.client
import os
import ssl
import time
import unittest
from unittest import mock

import aide  # noqa: F401
from aide import revue
import aide_v2
from aide_v2 import ServeurLocal
import relecteur_openai as ro


class TestTransport(unittest.TestCase):
    def motif(self, serveur, **kw):
        with self.assertRaises(revue.Refus) as cm:
            ro.appeler(aide_v2.CLE, b"{}", serveur.connexion(), **kw)
        return cm.exception.motif

    def test_succes_rend_le_corps_exact(self):
        with ServeurLocal() as s:
            self.assertEqual(ro.appeler(aide_v2.CLE, b"{}", s.connexion()), aide_v2.enveloppe())
            self.assertEqual(s.connexions, 1)
            chemin, entetes, corps = s.requetes[0]
            self.assertEqual(chemin, "/v1/responses")
            self.assertEqual(entetes["Authorization"], "Bearer " + aide_v2.CLE)
            self.assertEqual(entetes["Accept-Encoding"], "identity")
            self.assertEqual(corps, b"{}")

    def test_redirection_jamais_suivie(self):
        with ServeurLocal("redirection") as s:
            self.assertEqual(self.motif(s), "relecteur_redirection")
            self.assertEqual(s.connexions, 1)

    def test_aucune_reprise(self):
        for mode, motif in (("quota", "relecteur_quota"), ("serveur", "relecteur_http_serveur"),
                            ("client", "relecteur_http_client")):
            with ServeurLocal(mode) as s:
                self.assertEqual(self.motif(s), motif)
                self.assertEqual(s.connexions, 1, mode)

    def test_delai_total_mural_contre_un_serveur_au_compte_gouttes(self):
        """Chaque octet arrive avant le délai de socket : seule la minuterie
        murale borne l'appel."""
        with ServeurLocal("goutte") as s:
            debut = time.monotonic()
            self.assertEqual(self.motif(s, delai_total=1.0), "relecteur_delai")
            self.assertLess(time.monotonic() - debut, 3.0)

    def test_delai_total_contre_un_serveur_muet(self):
        with ServeurLocal("silence") as s:
            debut = time.monotonic()
            with self.assertRaises(revue.Refus) as cm:
                ro.appeler(aide_v2.CLE, b"{}", s.connexion(timeout=20), delai_total=1.0)
            self.assertEqual(cm.exception.motif, "relecteur_delai")
            self.assertLess(time.monotonic() - debut, 3.0)

    def test_minuterie_toujours_desarmee(self):
        with ServeurLocal() as s:
            ro.appeler(aide_v2.CLE, b"{}", s.connexion())
        self.assertEqual(ro.signal.getitimer(ro.signal.ITIMER_REAL), (0.0, 0.0))
        with ServeurLocal("serveur") as s:
            self.motif(s)
        self.assertEqual(ro.signal.getitimer(ro.signal.ITIMER_REAL), (0.0, 0.0))

    def test_taille_plafonnee_en_octets(self):
        with ServeurLocal("gros", taille=1001) as s:
            self.assertEqual(self.motif(s, taille_max=1000), "relecteur_trop_grand")
        with ServeurLocal("gros", taille=1000) as s:
            self.assertEqual(len(ro.appeler(aide_v2.CLE, b"{}", s.connexion(), taille_max=1000)), 1000)

    def test_encodage_compresse_refuse(self):
        with ServeurLocal("gzip") as s:
            self.assertEqual(self.motif(s), "relecteur_encodage")

    def test_connexion_impossible(self):
        def refusee():
            return http.client.HTTPConnection("127.0.0.1", 1, timeout=2)
        with self.assertRaises(revue.Refus) as cm:
            ro.appeler(aide_v2.CLE, b"{}", refusee)
        self.assertEqual(cm.exception.motif, "relecteur_connexion")
        self.assertNotIn(aide_v2.CLE, repr(cm.exception) + str(cm.exception.args))

    def test_cle_absente_aucune_connexion(self):
        with ServeurLocal() as s:
            for cle in ("", None):
                with self.assertRaises(revue.Refus) as cm:
                    ro.appeler(cle, b"{}", s.connexion())
                self.assertEqual(cm.exception.motif, "relecteur_cle_absente")
            self.assertEqual(s.connexions, 0)

    def test_cle_opaque_aucun_alphabet_ni_prefixe_impose(self):
        """La clé est opaque : tout ce qui est sûr dans un en-tête passe, quel que
        soit son alphabet ou son préfixe."""
        refus = []
        with ServeurLocal() as s:
            for cle in ("a", "x" * 4096, "proj_AbC.def+ghi/jkl=mno:pqr~", "!#$%&'*+-.^_`|~0123456789",
                        "Zz9" * 100):
                try:
                    ro.appeler(cle, b"{}", s.connexion())
                except revue.Refus as e:
                    refus.append((cle[:12], e.motif))
            vues = [e["Authorization"] for _, e, _ in s.requetes]
        self.assertEqual(refus, [])
        self.assertEqual(len(vues), 5)
        self.assertEqual(vues[2], "Bearer proj_AbC.def+ghi/jkl=mno:pqr~")

    def test_cle_dangereuse_en_en_tete_refusee_avant_tout_en_tete(self):
        """CR/LF, caractères de contrôle, espaces, caractères hors ASCII, taille
        excessive : refus codé, aucune connexion, aucune exception chaînée."""
        valide = aide_v2.CLE
        with ServeurLocal() as s:
            for cle in (valide + "\n", valide + "\r\nX-Fuite: 1", "\r" + valide, valide + " ", " " + valide,
                        valide + "\t", valide + "\x00", valide + "\x7f", valide + "\x1b", valide + "\u00a0",
                        valide + "\u2028", valide + "é", "x" * 4097):
                with self.assertRaises(revue.Refus) as cm:
                    ro.appeler(cle, b"{}", s.connexion())
                e = cm.exception
                self.assertEqual(e.motif, "relecteur_cle_invalide", repr(cle))
                self.assertIsNone(e.__context__)
                self.assertNotIn(valide, repr(e) + str(e.args))
            self.assertEqual(s.connexions, 0)

    def test_minuterie_indisponible_refus_code_sans_connexion(self):
        """Hors du fil principal, `signal` est indisponible : refus codé
        `relecteur_minuterie`, aucune connexion, gestionnaire inchangé."""
        import threading
        avant = ro.signal.getsignal(ro.signal.SIGALRM)
        resultat = []
        with ServeurLocal() as s:
            def cible():
                try:
                    ro.appeler(aide_v2.CLE, b"{}", s.connexion())
                    resultat.append("aucun refus")
                except revue.Refus as e:
                    resultat.append(e.motif)
                except BaseException as e:  # noqa: BLE001
                    resultat.append(type(e).__name__)
            fil = threading.Thread(target=cible)
            fil.start()
            fil.join(10)
            self.assertEqual(s.connexions, 0)
        self.assertEqual(resultat, ["relecteur_minuterie"])
        self.assertIs(ro.signal.getsignal(ro.signal.SIGALRM), avant)

    def test_minuterie_en_echec_au_premier_armement(self):
        avant = ro.signal.getsignal(ro.signal.SIGALRM)
        with ServeurLocal() as s, mock.patch.object(ro.signal, "setitimer",
                                                    side_effect=ro.signal.ItimerError("indisponible")):
            with self.assertRaises(revue.Refus) as cm:
                ro.appeler(aide_v2.CLE, b"{}", s.connexion())
            self.assertEqual(s.connexions, 0)
        self.assertEqual(cm.exception.motif, "relecteur_minuterie")
        self.assertIs(ro.signal.getsignal(ro.signal.SIGALRM), avant)

    def test_gestionnaire_precedent_restaure(self):
        avant = ro.signal.getsignal(ro.signal.SIGALRM)
        for mode in ("ok", "serveur"):
            with ServeurLocal(mode) as s:
                try:
                    ro.appeler(aide_v2.CLE, b"{}", s.connexion())
                except revue.Refus:
                    pass
            self.assertIs(ro.signal.getsignal(ro.signal.SIGALRM), avant, mode)

    # --- nettoyage : alarme déclenchée de façon déterministe aux points sensibles

    def sonner(self):
        """Simule l'alarme à cet instant précis : appelle le gestionnaire installé."""
        ro.signal.getsignal(ro.signal.SIGALRM)(ro.signal.SIGALRM, None)

    def etat_propre(self, avant, conn):
        self.assertEqual(ro.signal.getitimer(ro.signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(ro.signal.getsignal(ro.signal.SIGALRM), avant)
        self.assertEqual(conn.fermetures, 1)

    def appel_simule(self, conn, **kw):
        """Rend le refus ; toute autre issue (succès, exception brute comme une
        `_Echeance` échappée) est un échec d'assertion, jamais une erreur de test."""
        avant = ro.signal.getsignal(ro.signal.SIGALRM)
        issue = None
        try:
            ro.appeler(aide_v2.CLE, b"{}", lambda: conn, delai_total=60, **kw)
        except revue.Refus as e:
            issue = e
        except BaseException as e:  # noqa: BLE001
            self.fail(f"exception brute échappée : {type(e).__name__}")
        if issue is None:
            self.fail("aucun refus")
        self.etat_propre(avant, conn)
        return issue

    def test_alarme_pendant_l_attente_de_la_reponse(self):
        conn = FausseConnexion(self, sur_reponse=self.sonner)
        e = self.appel_simule(conn)
        self.assertEqual(e.motif, "relecteur_delai")
        self.assertIsNone(e.__cause__)

    def test_alarme_pendant_la_lecture(self):
        conn = FausseConnexion(self, sur_lecture=self.sonner)
        self.assertEqual(self.appel_simule(conn).motif, "relecteur_delai")

    def test_alarme_au_debut_du_nettoyage_apres_succes(self):
        """La fenêtre corrigée : alarme entre la fin de l'échange et le
        désarmement. Le nettoyage interrompu est repris ; refus codé."""
        conn = FausseConnexion(self)
        reel = ro._nettoyer
        def interrompu(m, etat):
            self.sonner()
            return reel(m, etat)
        with mock.patch.object(ro, "_nettoyer", interrompu):
            self.assertEqual(self.appel_simule(conn).motif, "relecteur_delai")

    def test_alarme_au_debut_du_nettoyage_pendant_un_refus(self):
        conn = FausseConnexion(self, statut=503)
        reel = ro._nettoyer
        def interrompu(m, etat):
            self.sonner()
            return reel(m, etat)
        with mock.patch.object(ro, "_nettoyer", interrompu):
            self.assertEqual(self.appel_simule(conn).motif, "relecteur_delai")

    def test_alarme_pendant_le_desarmement_muette(self):
        """Après la première instruction du nettoyage, l'alarme ne lève plus rien."""
        conn = FausseConnexion(self)
        reel_setitimer = ro.signal.setitimer
        def setitimer(quel, delai, *a):
            if delai == 0:
                self.sonner()
            return reel_setitimer(quel, delai, *a)
        avant = ro.signal.getsignal(ro.signal.SIGALRM)
        with mock.patch.object(ro.signal, "setitimer", setitimer):
            self.assertEqual(self.motif_sans_exception_brute(conn), "aucun refus")
        self.etat_propre(avant, conn)

    def test_alarme_pendant_la_fermeture_muette(self):
        conn = FausseConnexion(self, sur_fermeture=self.sonner)
        avant = ro.signal.getsignal(ro.signal.SIGALRM)
        self.assertEqual(ro.appeler(aide_v2.CLE, b"{}", lambda: conn, delai_total=60), aide_v2.enveloppe())
        self.etat_propre(avant, conn)

    def test_alarme_avalee_par_une_bibliotheque_reste_une_echeance(self):
        def avaler():
            try:
                self.sonner()
            except BaseException:  # noqa: BLE001 — bibliothèque fautive simulée
                pass
        conn = FausseConnexion(self, sur_lecture=avaler)
        self.assertEqual(self.appel_simule(conn).motif, "relecteur_delai")

    def test_alarme_avalee_pendant_l_attente_prime_sur_le_statut(self):
        """Échéance avalée pendant `getresponse` puis statut 503 : l'échéance est
        constatée aussitôt (`relecteur_delai`), avant tout traitement du statut."""
        def avaler():
            try:
                self.sonner()
            except BaseException:  # noqa: BLE001
                pass
        conn = FausseConnexion(self, statut=503, sur_reponse=avaler)
        self.assertEqual(self.appel_simule(conn).motif, "relecteur_delai")

    def test_alarme_avalee_pendant_la_lecture_arrete_la_lecture(self):
        def avaler():
            try:
                self.sonner()
            except BaseException:  # noqa: BLE001
                pass
        conn = FausseConnexion(self, sur_lecture=avaler)
        conn.restant = b"x" * (ro.LECTURE * 5)
        self.assertEqual(self.appel_simule(conn).motif, "relecteur_delai")
        self.assertEqual(conn.lectures, 1)

    def test_deux_alarmes_une_seule_echeance(self):
        def deux():
            self.sonner()
        conn = FausseConnexion(self, sur_reponse=deux, sur_fermeture=self.sonner)
        self.assertEqual(self.appel_simule(conn).motif, "relecteur_delai")

    # --- échecs du nettoyage lui-même (B2)

    def motif_sans_exception_brute(self, conn):
        """Motif du refus, ou nom de toute autre exception : une régression donne
        un échec d'assertion (FAIL), jamais une erreur de test."""
        try:
            ro.appeler(aide_v2.CLE, b"{}", lambda: conn, delai_total=60)
            return "aucun refus"
        except revue.Refus as e:
            return e.motif
        except BaseException as e:  # noqa: BLE001
            return type(e).__name__

    def proteger_le_processus(self, avant):
        """Un désarmement simulé en échec laisse une vraie alarme programmée :
        on la défait ici, avec les vraies fonctions, pour ne pas tuer la suite."""
        reel_setitimer, reel_signal = ro.signal.setitimer, ro.signal.signal
        self.addCleanup(lambda: reel_signal(ro.signal.SIGALRM, avant))
        self.addCleanup(lambda: reel_setitimer(ro.signal.ITIMER_REAL, 0))

    def desarmement_en_echec(self):
        reel = ro.signal.setitimer
        def setitimer(quel, delai, *a):
            if delai == 0:
                raise ro.signal.ItimerError("désarmement impossible")
            return reel(quel, delai, *a)
        return mock.patch.object(ro.signal, "setitimer", setitimer)

    def restauration_en_echec(self, avant):
        reel = ro.signal.signal
        def fausse(signum, gestionnaire):
            if gestionnaire is avant:
                raise ValueError("restauration impossible")
            return reel(signum, gestionnaire)
        return mock.patch.object(ro.signal, "signal", fausse)

    def test_desarmement_en_echec_jamais_un_succes(self):
        """setitimer(…, 0) en échec : refus `relecteur_nettoyage`, et les autres
        opérations (restauration du gestionnaire, fermeture) ont lieu quand même."""
        avant = ro.signal.getsignal(ro.signal.SIGALRM)
        self.proteger_le_processus(avant)
        for statut in (200, 503):
            conn = FausseConnexion(self, statut=statut)
            with self.desarmement_en_echec():
                motif = self.motif_sans_exception_brute(conn)
            self.assertEqual(motif, "relecteur_nettoyage", statut)
            self.assertEqual(conn.fermetures, 1, statut)
            self.assertIs(ro.signal.getsignal(ro.signal.SIGALRM), avant, statut)
            ro.signal.setitimer(ro.signal.ITIMER_REAL, 0)

    def test_restauration_en_echec_refus_code_et_connexion_fermee(self):
        """signal.signal en échec à la restauration : aucune exception brute,
        refus `relecteur_nettoyage`, minuterie désarmée, connexion fermée."""
        avant = ro.signal.getsignal(ro.signal.SIGALRM)
        self.proteger_le_processus(avant)
        for statut in (200, 503):
            conn = FausseConnexion(self, statut=statut)
            with self.restauration_en_echec(avant):
                motif = self.motif_sans_exception_brute(conn)
            self.assertEqual(motif, "relecteur_nettoyage", statut)
            self.assertEqual(conn.fermetures, 1, statut)
            self.assertEqual(ro.signal.getitimer(ro.signal.ITIMER_REAL), (0.0, 0.0), statut)
            ro.signal.signal(ro.signal.SIGALRM, avant)

    def test_double_echec_du_nettoyage_connexion_quand_meme_fermee(self):
        avant = ro.signal.getsignal(ro.signal.SIGALRM)
        self.proteger_le_processus(avant)
        conn = FausseConnexion(self)
        with self.desarmement_en_echec(), self.restauration_en_echec(avant):
            motif = self.motif_sans_exception_brute(conn)
        self.assertEqual(motif, "relecteur_nettoyage")
        self.assertEqual(conn.fermetures, 1)

    def test_alarme_pendant_le_nettoyage_puis_desarmement_en_echec(self):
        """Alarme au début du nettoyage, puis nettoyage repris dont le désarmement
        échoue : l'échec du nettoyage prime sur l'échéance (`relecteur_nettoyage`)."""
        avant = ro.signal.getsignal(ro.signal.SIGALRM)
        self.proteger_le_processus(avant)
        conn = FausseConnexion(self)
        reel = ro._nettoyer
        appels = []
        def interrompu(m, etat):
            appels.append(1)
            if len(appels) == 1:
                self.sonner()
            return reel(m, etat)
        with mock.patch.object(ro, "_nettoyer", interrompu), self.desarmement_en_echec():
            motif = self.motif_sans_exception_brute(conn)
        self.assertEqual(motif, "relecteur_nettoyage")
        self.assertEqual(conn.fermetures, 1)
        self.assertIs(ro.signal.getsignal(ro.signal.SIGALRM), avant)

    def test_erreur_inattendue_fermee(self):
        def cassee():
            raise RuntimeError("détail interne " + aide_v2.CLE)
        with self.assertRaises(revue.Refus) as cm:
            ro.appeler(aide_v2.CLE, b"{}", cassee)
        self.assertEqual(cm.exception.motif, "relecteur_interne")
        self.assertNotIn(aide_v2.CLE, str(cm.exception))

    def test_connexion_par_defaut_directe_tls_verifie_sans_mandataire(self):
        """Sans réseau : on capture la construction de la connexion par défaut."""
        vues = []

        class Capture:
            def __init__(self, hote, port, timeout, context):
                vues.append((hote, port, timeout, context))

            def set_tunnel(self, *a, **k):
                raise AssertionError("aucun tunnel de mandataire")

        env = dict(os.environ, HTTPS_PROXY="http://127.0.0.1:9", https_proxy="http://127.0.0.1:9",
                   ALL_PROXY="http://127.0.0.1:9")
        with mock.patch.dict(os.environ, env), mock.patch.object(ro.http.client, "HTTPSConnection", Capture):
            try:
                ro.connexion_defaut()
            except revue.Refus as e:
                self.fail(f"contexte TLS refusé : {e.motif}")
        (hote, port, timeout, ctx), = vues
        self.assertEqual((hote, port, timeout), ("api.openai.com", 443, ro.DELAI_SOCKET_S))
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_aucun_module_de_mandataire_ni_de_redirection(self):
        texte = (aide.RACINE / "outils/relecteur_openai.py").read_text("utf-8")
        for interdit in ("urllib", "requests", "getproxies", "_PROXY", "set_tunnel", "HTTPRedirectHandler"):
            self.assertNotIn(interdit, texte, interdit)
        self.assertEqual(ro.HOTE, "api.openai.com")
        self.assertEqual(ro.CHEMIN, "/v1/responses")


if __name__ == "__main__":
    unittest.main()


class FausseConnexion:
    """Connexion simulée, sans réseau, avec des points d'accroche pour déclencher
    l'alarme à un instant précis."""

    def __init__(self, test, statut=200, sur_reponse=None, sur_lecture=None, sur_fermeture=None):
        self.test, self.statut, self.fermetures, self.lectures = test, statut, 0, 0
        self.sur_reponse, self.sur_lecture, self.sur_fermeture = sur_reponse, sur_lecture, sur_fermeture
        self.restant = aide_v2.enveloppe()

    def request(self, *a, **k):
        pass

    def getresponse(self):
        if self.sur_reponse:
            self.sur_reponse()
        return self

    @property
    def status(self):
        return self.statut

    def getheader(self, nom):
        return None

    def read(self, n):
        self.lectures += 1
        if self.sur_lecture:
            accroche, self.sur_lecture = self.sur_lecture, None
            accroche()
        bloc, self.restant = self.restant[:n], self.restant[n:]
        return bloc

    def close(self):
        self.fermetures += 1
        if self.sur_fermeture:
            accroche, self.sur_fermeture = self.sur_fermeture, None
            accroche()

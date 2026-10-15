"""Échec fermé, sérialisation et absence de fuite de l'adaptateur 3A.2."""
from contextlib import nullcontext
import os
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path

import aide  # noqa: F401
from aide import revue
import aide_openrouter as ao
import relecteur_openrouter as ro
import transport_openrouter as th


class TestSecuriteOpenRouter(unittest.TestCase):
    def test_exception_hostile_ne_divulgue_ni_cle_ni_diff(self):
        secret = ao.CLE
        contenu = "DIFF-TRES-SENSIBLE"

        class Hostile:
            simule = True
            appels = 0

            def envoyer(self, _cle, _requete):
                self.appels += 1
                raise RuntimeError(secret + contenu)

        with self.assertRaises(revue.Refus) as cm:
            ao.executer(transport=Hostile(), diff=contenu.encode())
        rendu = str(cm.exception) + repr(cm.exception.args)
        self.assertEqual(cm.exception.motif, "openrouter_transport")
        self.assertNotIn(secret, rendu)
        self.assertNotIn(contenu, rendu)

    def test_aucune_tentative_apres_echec_de_l_inference(self):
        transport = ao.TransportSimule(
            [ao.budget(), RuntimeError("contenu sensible"), ao.inference()]
        )
        with self.assertRaises(revue.Refus) as cm:
            ao.executer(transport=transport)
        self.assertEqual(cm.exception.motif, "openrouter_transport")
        self.assertEqual(transport.appels, 2)
        self.assertEqual(len(transport.reponses), 1)

    def test_verrou_couvre_budget_et_inference_dans_une_seule_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            serialiseur = ro.SerialiseurFichier(Path(tmp) / "verrou")

            class Observe(ao.TransportSimule):
                def __init__(self):
                    super().__init__()
                    self.observations = []

                def envoyer(self, cle, requete):
                    self.observations.append(serialiseur.verrou_acquis())
                    return super().envoyer(cle, requete)

            transport = Observe()
            resultat = ao.executer(transport=transport, serialiseur=serialiseur)
            self.assertFalse(resultat.autorisante)
            self.assertEqual(transport.observations, [True, True])
            self.assertIsNone(serialiseur.descripteur)

    def test_nullcontext_et_gestionnaire_fictif_sont_refuses_sans_appel(self):
        class SousClasse(ro.SerialiseurFichier):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            serialiseurs = (
                ao.SerialiseurSimule(),
                nullcontext(),
                SousClasse(Path(tmp) / "verrou"),
            )
            for serialiseur in serialiseurs:
                transport = ao.TransportSimule()
                with self.assertRaises(revue.Refus) as cm:
                    ao.executer(transport=transport, serialiseur=serialiseur)
                self.assertEqual(cm.exception.motif, "openrouter_serialisation")
                self.assertEqual(transport.appels, 0)

    def test_verrou_non_acquis_est_refuse_sans_appel(self):
        with tempfile.TemporaryDirectory() as tmp:
            serialiseur = ro.SerialiseurFichier(Path(tmp) / "verrou")
            transport = ao.TransportSimule()
            with mock.patch.object(ro.fcntl, "flock", return_value=None):
                with self.assertRaises(revue.Refus) as cm:
                    ao.executer(transport=transport, serialiseur=serialiseur)
            self.assertEqual(cm.exception.motif, "openrouter_serialisation")
            self.assertEqual(transport.appels, 0)
            self.assertIsNone(serialiseur.descripteur)

    def test_verrou_libere_apres_erreur(self):
        with tempfile.TemporaryDirectory() as tmp:
            chemin = Path(tmp) / "verrou"
            serialiseur = ro.SerialiseurFichier(chemin)
            transport = ao.TransportSimule(
                [ao.budget(), RuntimeError("echec simule")]
            )
            with self.assertRaises(revue.Refus) as cm:
                ao.executer(transport=transport, serialiseur=serialiseur)
            self.assertEqual(cm.exception.motif, "openrouter_transport")
            self.assertIsNone(serialiseur.descripteur)
            with ro.SerialiseurFichier(chemin) as suivant:
                self.assertTrue(suivant.verrou_acquis())

    def test_threads_utilisent_des_instances_distinctes_sur_le_meme_fichier(self):
        with tempfile.TemporaryDirectory() as tmp:
            chemin = Path(tmp) / "verrou"
            premier_dedans = threading.Event()
            liberer_premier = threading.Event()
            erreurs = []

            class Premier(ao.TransportSimule):
                def envoyer(self, cle, requete):
                    if self.appels == 0:
                        premier_dedans.set()
                        if not liberer_premier.wait(2):
                            raise AssertionError("attente de test depassee")
                    return super().envoyer(cle, requete)

            transport_1 = Premier()
            transport_2 = ao.TransportSimule()

            def lancer(transport):
                try:
                    ao.executer(
                        transport=transport,
                        serialiseur=ro.SerialiseurFichier(chemin),
                    )
                except BaseException as erreur:
                    erreurs.append(erreur)

            fil_1 = threading.Thread(target=lancer, args=(transport_1,))
            fil_2 = threading.Thread(target=lancer, args=(transport_2,))
            fil_1.start()
            self.assertTrue(premier_dedans.wait(1))
            fil_2.start()
            time.sleep(0.05)
            self.assertEqual(transport_2.appels, 0)
            liberer_premier.set()
            fil_1.join(2)
            fil_2.join(2)
            self.assertFalse(fil_1.is_alive() or fil_2.is_alive())
            self.assertEqual(erreurs, [])
            self.assertEqual((transport_1.appels, transport_2.appels), (2, 2))

    def test_verrou_fichier_est_prive_et_refuse_un_lien_symbolique(self):
        with tempfile.TemporaryDirectory() as tmp:
            chemin = Path(tmp) / "verrou"
            serialiseur = ro.SerialiseurFichier(chemin)
            with serialiseur:
                self.assertEqual(chemin.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(revue.Refus):
                with serialiseur:
                    pass
            cible = Path(tmp) / "cible"
            cible.write_text("x")
            lien = Path(tmp) / "lien"
            os.symlink(cible, lien)
            with self.assertRaises(revue.Refus) as cm:
                with ro.SerialiseurFichier(lien):
                    pass
            self.assertEqual(cm.exception.motif, "openrouter_serialisation")

    def test_reponse_simulee_trop_grande_ou_mal_formee_refusee(self):
        grosse = th.Reponse(b"x" * (th.TAILLE_BUDGET_MAX + 1), {})
        for reponse, motif in (
            (grosse, "openrouter_trop_grand"),
            (th.Reponse("pas-des-octets", {}), "openrouter_trop_grand"),
        ):
            transport = ao.TransportSimule([reponse])
            with self.assertRaises(revue.Refus) as cm:
                ao.executer(transport=transport)
            self.assertEqual(cm.exception.motif, motif)

    def test_modules_ne_journalisent_aucun_contenu(self):
        for nom in ("outils/relecteur_openrouter.py", "outils/transport_openrouter.py"):
            texte = (ao.RACINE / nom).read_text("utf-8")
            self.assertNotIn("print(", texte, nom)
            self.assertNotIn("logging", texte, nom)


if __name__ == "__main__":
    unittest.main()

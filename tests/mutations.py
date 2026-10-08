#!/usr/bin/env python3
"""Harnais de mutations CAUSAL des contrôles de sécurité essentiels.

Chaque mutation est associée à son test causal. Pour chacune :
  1. le test causal doit réussir sur une copie NON mutée (contrôle préalable,
     une seule exécution pour tous les tests causaux) ;
  2. la mutation est appliquée à une copie jetable du dépôt (son motif doit y
     figurer exactement une fois) ;
  3. le test causal, et lui seul, est exécuté : il doit ÉCHOUER par un échec ou
     une erreur de CE test — une erreur d'import ou de chargement est un
     résultat invalide, pas une détection.
Sortie 0 si toutes les mutations sont détectées causalement ; 1 sinon (survivante,
motif introuvable, test causal absent ou en échec sans mutation, résultat invalide).

L'épinglage des octets v1 (`test_v1_fige.py`) est exclu des copies mutées : chaque
mutation doit être attrapée par un test de comportement, pas par une empreinte.

    python3 tests/mutations.py
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent

# (nom, fichier, avant, après, test causal `module.Classe.methode`)
MUTATIONS = [
    # --- revue/1 : les 15 mutations historiques, inchangées
    ('login réintroduit dans le dédoublonnage', 'outils/revue.py',
     'and user.get("type") == "User" and user.get("id") in autorises)',
     'and user.get("type") == "User" and user.get("login") == "operateur")',
     'test_admission.TestIdentiteNumerique.test_le_login_n_apparait_dans_aucune_decision'),
    ("filtre `creator` réintroduit dans l'appel d'historique", 'outils/revue.py',
     '{"state": "all", "sort": "created"',
     '{"state": "all", "creator": "operateur", "sort": "created"',
     'test_admission.TestIdentiteNumerique.test_appel_api_sans_creator_ni_login'),
    ('API de signature acceptant une Decision forgée', 'outils/pont_p1.py',
     'def _clore_en_echec(registre, request_id, liaison, motif):',
     'def signer_decision(decision, config):\n    return decision\n\n\ndef _clore_en_echec(registre, request_id, liaison, motif):',
     'test_pont_p1.TestPontP1.test_surface_publique_fermee'),
    ('réservation sautée', 'outils/pont_p1.py',
     '    registre.reserver(request_id, liaison)  # point de non-retour',
     '    pass  # point de non-retour',
     'test_pont_p1.TestPontP1.test_signer_deux_fois_refuse'),
    ('registre facultatif', 'outils/pont_p1.py',
     'if not isinstance(registre, registre_mod.RegistreConsommation):',
     'if registre is None:',
     'test_pont_p1.TestPontP1.test_decision_forgee_impossible_a_injecter'),
    ('contrôle de substitution sauté', 'outils/pont_p1.py',
     '        registre.controler_reservation(request_id, liaison)',
     '        pass',
     'test_pont_p1.TestPontP1.test_substitution_entre_verification_et_signature'),
    ('réservation non exclusive', 'outils/registre.py',
     'if not self._t.creer_ref(_ref(rid, "reserve"), contenu):',
     'self._t.creer_ref(_ref(rid, "reserve"), contenu)\n        if False:',
     'test_registre.TestRegistre.test_reserveurs_simultanes_une_seule_reussite'),
    ('signature sans décision acceptée', 'outils/pont_p1.py',
     'if not decision.acceptee or decision["verdicts"].count("FAVORABLE") != 1 or "DEFAVORABLE" in decision["verdicts"]:',
     'if not decision.get("verdicts"):',
     'test_pont_p1.TestPontP1.test_indetermine_ou_defavorable_refuses'),
    ('repli sur un bundle en ligne', 'outils/verifier.py',
     'u = a.get("bundle_url") if isinstance(a, dict) else None',
     'u = (a.get("bundle_url") or "https://api.github.com/en-ligne") if isinstance(a, dict) else None',
     'test_bundle_url.TestListe.test_bundle_url_absente_null_ou_vide'),
    ('hôte de bundle non contrôlé', 'outils/verifier.py',
     'and any(hote.endswith(s) for s in SUFFIXES_HOTES_BUNDLE))',
     ')',
     'test_bundle_url.TestListe.test_bundle_url_inattendue'),
    ('base reprise de la demande', 'outils/revue.py',
     'base, pointe = ancre["commit"], demande["pointe"]',
     'base, pointe = demande.get("base", ancre["commit"]), demande["pointe"]',
     'test_sujet.TestSujet.test_base_glissee_dans_la_demande_ignoree'),
    ("gitlink accepté dans l'arbre", 'outils/revue.py',
     'if typ == b"commit" or mode == b"160000":\n            raise Refus("gitlink_refuse")',
     'if False:\n            raise Refus("gitlink_refuse")',
     'test_sujet.TestSujet.test_gitlink_refuse'),
    ('relecteur non acceptable accepté', 'outils/verifier.py',
     'if not rel["acceptable"]:',
     'if False:',
     'test_verifier.TestVerifier.test_relecteur_acceptable_false'),
    ('coupure ignorée', 'outils/verifier.py',
     'if t < revue.instant_utc(f["coupure"]):',
     'if False:',
     'test_verifier.TestVerifier.test_attestation_anterieure_a_la_coupure'),
    ('_type in-toto ignoré', 'outils/verifier.py',
     'if enonce.get("_type") != TYPE_INTOTO:',
     'if False:',
     'test_verifier.TestVerifier.test_type_intoto_invalide'),
    # --- revue/2
    ('v2 : minuterie murale supprimée', 'outils/relecteur_openai.py',
     '            signal.setitimer(signal.ITIMER_REAL, delai)',
     '            pass',
     'test_v2_transport.TestTransport.test_delai_total_mural_contre_un_serveur_au_compte_gouttes'),
    ('v2 : clé dangereuse acceptée en en-tête', 'outils/relecteur_openai.py',
     '    if not cle_utilisable(cle):',
     '    if False:',
     'test_v2_transport.TestTransport.test_cle_dangereuse_en_en_tete_refusee_avant_tout_en_tete'),
    ('v2 : alphabet de clé imposé', 'outils/relecteur_openai.py',
     '    return 0 < len(cle) <= CLE_TAILLE_MAX and all("\\x21" <= c <= "\\x7e" for c in cle)',
     '    return cle.startswith("sk-") and 0 < len(cle) <= CLE_TAILLE_MAX and all("\\x21" <= c <= "\\x7e" for c in cle)',
     'test_v2_transport.TestTransport.test_cle_opaque_aucun_alphabet_ni_prefixe_impose'),
    ('v2 : échec de la minuterie non codé', 'outils/relecteur_openai.py',
     '            raise revue.Refus("relecteur_minuterie")',
     '            raise',
     'test_v2_transport.TestTransport.test_minuterie_indisponible_refus_code_sans_connexion'),
    ('v2 : alarme non à usage unique', 'outils/relecteur_openai.py',
     '            self.active = False\n            self.echue = True',
     '            self.echue = True',
     'test_v2_transport.TestTransport.test_alarme_au_debut_du_nettoyage_apres_succes'),
    ('v2 : nettoyage interrompu non repris', 'outils/relecteur_openai.py',
     '        _nettoyer(minuterie, etat)  # nettoyage peut-être interrompu',
     '        pass  # nettoyage peut-être interrompu',
     'test_v2_transport.TestTransport.test_alarme_au_debut_du_nettoyage_pendant_un_refus'),
    ("v2 : désarmement ne désactive pas d'abord", 'outils/relecteur_openai.py',
     '        """Idempotent. Désactive d\'abord : une alarme pendant la suite est muette."""\n        self.active = False',
     '        """Idempotent. Désactive d\'abord : une alarme pendant la suite est muette."""',
     'test_v2_transport.TestTransport.test_alarme_pendant_le_desarmement_muette'),
    ('v2 : échéance avalée non constatée après la réponse', 'outils/relecteur_openai.py',
     '        rep = conn.getresponse()\n        minuterie.verifier()',
     '        rep = conn.getresponse()',
     'test_v2_transport.TestTransport.test_alarme_avalee_pendant_l_attente_prime_sur_le_statut'),
    ('v2 : échéance avalée non constatée pendant la lecture', 'outils/relecteur_openai.py',
     '            bloc = rep.read(LECTURE)\n            minuterie.verifier()',
     '            bloc = rep.read(LECTURE)',
     'test_v2_transport.TestTransport.test_alarme_avalee_pendant_la_lecture_arrete_la_lecture'),
    ('v2 : connexion non fermée', 'outils/relecteur_openai.py',
     '            conn.close()\n        except Exception:  # noqa: BLE001\n            pass',
     '            pass\n        except Exception:  # noqa: BLE001\n            pass',
     'test_v2_transport.TestTransport.test_alarme_pendant_l_attente_de_la_reponse'),
    ('v2 : plafond de taille supprimé', 'outils/relecteur_openai.py',
     '            if total > taille_max:',
     '            if False:',
     'test_v2_transport.TestTransport.test_taille_plafonnee_en_octets'),
    ('v2 : redirection traitée comme un succès', 'outils/relecteur_openai.py',
     '        if statut != 200:',
     '        if statut >= 400:',
     'test_v2_transport.TestTransport.test_redirection_jamais_suivie'),
    ('v2 : Content-Encoding ignoré', 'outils/relecteur_openai.py',
     '        if (rep.getheader("Content-Encoding") or "identity").strip().lower() != "identity":',
     '        if False:',
     'test_v2_transport.TestTransport.test_encodage_compresse_refuse'),
    ('v2 : clé reprise dans une erreur', 'outils/relecteur_openai.py',
     '        raise revue.Refus("relecteur_connexion")',
     '        raise revue.Refus("relecteur_connexion", cle)',
     'test_v2_transport.TestTransport.test_connexion_impossible'),
    ('v2 : TLS non vérifié', 'outils/relecteur_openai.py',
     '    ctx = ssl.create_default_context()',
     '    ctx = ssl._create_unverified_context()',
     'test_v2_transport.TestTransport.test_connexion_par_defaut_directe_tls_verifie_sans_mandataire'),
    ('v2 : rôle absent toléré', 'outils/relecteur_openai.py',
     '        if element.get("role") != "assistant" or',
     '        if element.get("role", "assistant") != "assistant" or',
     'test_v2_enveloppe.TestEnveloppe.test_role_absent_refuse'),
    ('v2 : contrôle du modèle supprimé', 'outils/relecteur_openai.py',
     '    if env.get("model") != modele:',
     '    if False:',
     'test_v2_enveloppe.TestEnveloppe.test_modele_exact_octet_pour_octet'),
    ('v2 : statut incomplet accepté', 'outils/relecteur_openai.py',
     '    if env.get("status") != "completed":',
     '    if env.get("status") not in ("completed", "incomplete"):',
     'test_v2_enveloppe.TestEnveloppe.test_statut_non_termine_ou_erreur'),
    ("v2 : appel d'outil accepté", 'outils/relecteur_openai.py',
     '        if t not in ("message", "reasoning"):',
     '        if t not in ("message", "reasoning", "function_call"):',
     'test_v2_enveloppe.TestEnveloppe.test_appel_d_outil_ou_element_inconnu_refuse'),
    ('v2 : refus du modèle accepté', 'outils/relecteur_openai.py',
     '            if tp == "refusal":',
     '            if False:',
     'test_v2_enveloppe.TestEnveloppe.test_refus_du_modele'),
    ('v2 : plusieurs textes acceptés', 'outils/relecteur_openai.py',
     '    if len(textes) != 1:',
     '    if not textes:',
     'test_v2_enveloppe.TestEnveloppe.test_exactement_un_texte'),
    ("v2 : erreur d'enveloppe convertie en INDETERMINE", 'outils/relecteur_openai.py',
     '    return analyser_enveloppe(appeler(cle, corps, connexion), modele)',
     '    try:\n        return analyser_enveloppe(appeler(cle, corps, connexion), modele)\n    except revue.Refus:\n        return b""',
     'test_v2_bout_en_bout.TestBoutEnBoutV2.test_chaque_erreur_d_enveloppe_ne_produit_aucune_attestation'),
    ('v2 : stockage fournisseur activé', 'outils/relecteur_openai.py',
     '        "store": False,',
     '        "store": True,',
     'test_v2_projection.TestProjection.test_requete_porte_la_projection_et_rien_d_autre'),
    ('v2 : outil déclaré dans la requête', 'outils/relecteur_openai.py',
     '        "store": False,',
     '        "store": False, "tools": [{"type": "web_search"}],',
     'test_v2_injection.TestInjection.test_requete_ne_porte_la_cle_que_dans_l_en_tete'),
    ("v2 : borne d'encadrement constante", 'outils/relecteur_openai.py',
     '    borne = "DIFF-" + revue.sha256_hex(diff)',
     '    borne = "DIFF"',
     'test_v2_injection.TestInjection.test_borne_dependante_du_contenu'),
    ('v2 : minLength conservé dans la projection', 'outils/relecteur_openai.py',
     'SUPPRIMES = frozenset({"$schema", "$id", "title", "description", "minLength", "maxLength"})',
     'SUPPRIMES = frozenset({"$schema", "$id", "title", "description", "maxLength"})\nCONSERVES = CONSERVES | {"minLength"}',
     'test_v2_projection.TestProjection.test_projection_de_reference'),
    ('v2 : sujet au format v1', 'outils/revue2.py',
     'FORMAT_SUJET = "olistic.confiance.sujet-revue/2"',
     'FORMAT_SUJET = "olistic.confiance.sujet-revue/1"',
     'test_v2_predicat.TestPredicatV2.test_sujet_et_nom_v2'),
    ('v2 : clé non exigée avant tout calcul', 'outils/revue2.py',
     '            if not cle:',
     '            if False:',
     'test_v2_bout_en_bout.TestBoutEnBoutV2.test_sans_cle_aucune_attestation_meme_sans_appel_necessaire'),
    ("v2 : clé laissée dans l'environnement", 'outils/revue2.py',
     '        cle = os.environ.pop(VARIABLE_CLE, "")',
     '        cle = os.environ.get(VARIABLE_CLE, "")',
     'test_v2_bout_en_bout.TestBoutEnBoutV2.test_cle_retiree_de_l_environnement_avant_la_relecture'),
    ('v2 : acceptable forcé dans le prédicat', 'outils/revue2.py',
     '"acceptable": rel["acceptable"]}',
     '"acceptable": True}',
     'test_v2_predicat.TestPredicatV2.test_produit_sous_acceptable_false_pour_chaque_verdict'),
    ('v2 : invariant acceptable du producteur supprimé', 'outils/revue2.py',
     '    if predicat["relecteur"]["acceptable"] is not r["acceptable"]:',
     '    if False:',
     'test_v2_predicat.TestPredicatV2.test_acceptable_falsifie_refuse'),
    ('v2 : portée consultative retirée de la réponse', 'outils/revue2.py',
     '    if not rel["acceptable"]:',
     '    if False:',
     'test_v2_bout_en_bout.TestReponseV2.test_attestee_signale_la_portee_consultative'),
    ('v2 : relecteur non acceptable accepté', 'outils/verifier2.py',
     '    if not rel["acceptable"]:',
     '    if False:',
     'test_v2_verifier.TestVerifierV2.test_seule_une_attestation_saine_atteint_relecteur_non_acceptable'),
    ('v2 : acceptable lu dans le prédicat', 'outils/verifier2.py',
     '    if predicat["relecteur"]["acceptable"] is not rel["acceptable"]:',
     '    if False:',
     'test_v2_verifier.TestVerifierV2.test_acceptable_ne_vient_jamais_du_predicat'),
    ('v2 : non acceptable appliqué avant le modèle', 'outils/verifier2.py',
     '    if predicat["relecteur"]["modele"] not in rel["modeles"]:',
     '    if not rel["acceptable"]:\n        raise Invalide("relecteur_non_acceptable")\n    if predicat["relecteur"]["modele"] not in rel["modeles"]:',
     'test_v2_verifier.TestVerifierV2.test_canari_revele_un_modele_non_autorise_malgre_acceptable_false'),
    ('v2 : modèle non vérifié par le vérificateur', 'outils/verifier2.py',
     '    if predicat["relecteur"]["modele"] not in rel["modeles"]:',
     '    if False:',
     'test_v2_verifier.TestVerifierV2.test_canari_revele_un_modele_non_autorise_malgre_acceptable_false'),
    ('v2 : fraîcheur non vérifiée par le vérificateur', 'outils/verifier2.py',
     '    t = verifier.instant_verifie(vr, pol, maintenant)',
     '    t = revue.instant_utc(predicat["instant"])',
     'test_v2_verifier.TestVerifierV2.test_canari_revele_les_anomalies_de_fraicheur_malgre_acceptable_false'),
    ('v2 : provenance non vérifiée par le vérificateur', 'outils/verifier2.py',
     '    motif = verifier.controler_certificat(cert, conf)',
     '    motif = None',
     'test_v2_verifier.TestVerifierV2.test_canari_revele_la_provenance_malgre_acceptable_false'),
    ('v2 : secret exposé au job de signature', '.github/workflows/revue.yml',
     '          PREDICAT: ${{ needs.revue.outputs.predicat }}',
     '          PREDICAT: ${{ needs.revue.outputs.predicat }}\n          CLE_RELECTEUR: ${{ secrets.CLE_RELECTEUR_OPENAI }}',
     'test_workflow.TestWorkflows.test_lot2_secret_unique_dans_le_seul_step_de_relecture'),
    ('v2 : producteur v1 rappelé par le workflow', '.github/workflows/revue.yml',
     'run: python3 -I outils/revue2.py preparer',
     'run: python3 -I outils/revue.py preparer',
     'test_workflow.TestWorkflows.test_lot2_producteur_v2_seulement'),
]


def copier(destination):
    shutil.copytree(RACINE, destination, ignore=shutil.ignore_patterns("__pycache__", ".git", "test_v1_fige.py"))


def lancer(dossier, tests):
    r = subprocess.run([sys.executable, "-m", "unittest", *tests], cwd=Path(dossier) / "tests",
                       capture_output=True, text=True, timeout=900)
    return r.returncode, r.stdout + r.stderr


def echecs(sortie):
    """Identifiants `module.Classe.methode` en échec ou en erreur ; et chargements ratés."""
    vus = set(re.findall(r"^(?:FAIL|ERROR): \S+ \((\S+)\)", sortie, re.M))
    rates = {v for v in vus if v.startswith("unittest.loader._FailedTest") or "_FailedTest" in v}
    return vus - rates, rates


def main():
    causaux = sorted({m[4] for m in MUTATIONS})
    with tempfile.TemporaryDirectory(prefix="mutation-") as tmp:
        copier(Path(tmp) / "b")
        rc, sortie = lancer(Path(tmp) / "b", causaux)
    if rc != 0 or "Ran %d test" % len(causaux) not in sortie:
        print("tests causaux en échec, absents ou dupliqués sans mutation : harnais inutilisable")
        print(sortie[-2000:])
        return 1
    print(f"contrôle préalable : {len(causaux)} tests causaux verts sans mutation")
    mauvaises = 0
    for nom, fichier, avant, apres, causal in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="mutation-") as tmp:
            copie = Path(tmp) / "b"
            copier(copie)
            cible = copie / fichier
            texte = cible.read_text("utf-8")
            if texte.count(avant) != 1:
                print(f"MOTIF INTROUVABLE  {nom}")
                mauvaises += 1
                continue
            cible.write_text(texte.replace(avant, apres), "utf-8")
            rc, sortie = lancer(copie, [causal])
        en_echec, rates = echecs(sortie)
        if rates:
            etat = "INVALIDE  "
        elif rc != 0 and causal in en_echec:
            etat = "détectée  "
        elif rc != 0:
            etat = "NON CAUSALE"
        else:
            etat = "SURVIVANTE"
        mauvaises += etat != "détectée  "
        print(f"{etat}  {nom}  <- {causal}")
    print(f"{len(MUTATIONS) - mauvaises}/{len(MUTATIONS)} mutations détectées par leur test causal")
    return 1 if mauvaises else 0


if __name__ == "__main__":
    sys.exit(main())

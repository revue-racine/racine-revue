#!/usr/bin/env python3
"""Contrôle avant publication : aucun nom interne dans le bundle.

La liste des noms interdits n'est PAS dans ce dépôt public (ni en clair, ni en
empreinte, qui servirait d'oracle de confirmation) : l'administrateur la tient
hors du dépôt et la passe en argument, un nom par ligne.

    python3 tests/controle_noms.py <liste-privée> [racine]

Sortie 0 si aucun nom n'apparaît (comparaison insensible à la casse, sur le
texte brut de chaque fichier) ; 1 sinon, en citant seulement le fichier."""
import sys
from pathlib import Path


def fichiers(racine):
    for p in sorted(Path(racine).rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts and ".git" not in p.parts:
            yield p


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__)
        return 2
    noms = [l.strip().lower() for l in Path(argv[1]).read_text("utf-8").splitlines() if l.strip()]
    if not noms:
        print("liste vide : contrôle impossible")
        return 2
    racine = Path(argv[2] if len(argv) == 3 else Path(__file__).resolve().parent.parent)
    fautifs = [p.relative_to(racine).as_posix() for p in fichiers(racine)
               if any(n in p.read_text("utf-8", errors="replace").lower() for n in noms)]
    for f in fautifs:
        print(f"nom interne présent : {f}")
    print(f"{len(noms)} noms contrôlés, {len(fautifs)} fichier(s) fautif(s)")
    return 1 if fautifs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

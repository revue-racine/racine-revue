"""Décompression snappy, format bloc, bibliothèque standard seulement.

GitHub sert les bundles d'attestation à `bundle_url` compressés en snappy bloc
(c'est ce que décode `gh` : `snappy.Decode`). Toute anomalie (longueur, tag,
décalage, débordement, borne) lève ValueError : échec fermé.
"""


def decompresser(donnees, taille_max):
    if not isinstance(donnees, (bytes, bytearray)):
        raise ValueError("octets attendus")
    try:
        i, n, decalage = 0, 0, 0
        while True:
            b = donnees[i]
            i += 1
            n |= (b & 0x7F) << decalage
            if b < 0x80:
                break
            decalage += 7
            if decalage > 28:
                raise ValueError("longueur illisible")
        if n > taille_max:
            raise ValueError("taille annoncée hors borne")
        out = bytearray()
        while i < len(donnees):
            tag = donnees[i]
            i += 1
            genre = tag & 3
            if genre == 0:
                longueur = tag >> 2
                if longueur >= 60:
                    nb = longueur - 59
                    if i + nb > len(donnees):
                        raise ValueError("littéral tronqué")
                    longueur = int.from_bytes(donnees[i:i + nb], "little")
                    i += nb
                longueur += 1
                if i + longueur > len(donnees):
                    raise ValueError("littéral tronqué")
                out += donnees[i:i + longueur]
                i += longueur
            else:
                if genre == 1:
                    longueur = ((tag >> 2) & 7) + 4
                    offset = ((tag >> 5) << 8) | donnees[i]
                    i += 1
                else:
                    nb = 2 if genre == 2 else 4
                    if i + nb > len(donnees):
                        raise ValueError("copie tronquée")
                    longueur = (tag >> 2) + 1
                    offset = int.from_bytes(donnees[i:i + nb], "little")
                    i += nb
                if offset == 0 or offset > len(out):
                    raise ValueError("décalage invalide")
                for _ in range(longueur):
                    out.append(out[-offset])
            if len(out) > n:
                raise ValueError("débordement")
    except IndexError:
        raise ValueError("flux tronqué")
    if len(out) != n:
        raise ValueError("longueur incohérente")
    return bytes(out)

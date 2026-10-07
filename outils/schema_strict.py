"""Validateur JSON Schema minimal, bibliothèque standard seulement.

Couvre exactement le sous-ensemble utilisé par `schemas/` ; un mot-clé hors de
ce sous-ensemble fait échouer la validation (échec fermé) au lieu d'être ignoré.
Les tests croisent ce validateur avec la bibliothèque `jsonschema` de référence.
"""
import re

MOTS_CLES = {
    "$schema", "$id", "$defs", "$ref", "title", "description",
    "type", "properties", "required", "additionalProperties",
    "enum", "const", "pattern", "minLength", "maxLength",
    "minimum", "maximum", "items", "minItems", "maxItems", "uniqueItems",
}


class SchemaInvalide(Exception):
    pass


def _type_ok(valeur, attendu):
    if attendu == "null":
        return valeur is None
    if attendu == "boolean":
        return isinstance(valeur, bool)
    if attendu == "integer":
        return isinstance(valeur, int) and not isinstance(valeur, bool)
    if attendu == "string":
        return isinstance(valeur, str)
    if attendu == "object":
        return isinstance(valeur, dict)
    if attendu == "array":
        return isinstance(valeur, list)
    raise SchemaInvalide(f"type non pris en charge : {attendu}")


def _egal(a, b):
    # JSON : 1 et true sont distincts, contrairement à Python.
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_egal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_egal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def erreurs(valeur, schema, racine=None, chemin="$"):
    """Rend la liste des erreurs ; vide si la valeur est conforme."""
    racine = schema if racine is None else racine
    inconnus = set(schema) - MOTS_CLES
    if inconnus:
        raise SchemaInvalide(f"{chemin} : mots-clés non pris en charge {sorted(inconnus)}")
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise SchemaInvalide(f"référence non locale : {ref}")
        return erreurs(valeur, racine["$defs"][ref[len("#/$defs/"):]], racine, chemin)

    out = []
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(valeur, t) for t in types):
            return [f"{chemin} : type attendu {types}"]
    if "const" in schema and not _egal(valeur, schema["const"]):
        out.append(f"{chemin} : valeur constante attendue")
    if "enum" in schema and not any(_egal(valeur, e) for e in schema["enum"]):
        out.append(f"{chemin} : valeur hors énumération")
    if isinstance(valeur, str):
        if "pattern" in schema and re.search(schema["pattern"], valeur) is None:
            out.append(f"{chemin} : motif non respecté")
        if "minLength" in schema and len(valeur) < schema["minLength"]:
            out.append(f"{chemin} : trop court")
        if "maxLength" in schema and len(valeur) > schema["maxLength"]:
            out.append(f"{chemin} : trop long")
    if isinstance(valeur, int) and not isinstance(valeur, bool):
        if "minimum" in schema and valeur < schema["minimum"]:
            out.append(f"{chemin} : inférieur au minimum")
        if "maximum" in schema and valeur > schema["maximum"]:
            out.append(f"{chemin} : supérieur au maximum")
    if isinstance(valeur, dict):
        props = schema.get("properties", {})
        if "properties" in schema and schema.get("additionalProperties") is not False:
            raise SchemaInvalide(f"{chemin} : objet ouvert interdit (additionalProperties: false exigé)")
        for cle in schema.get("required", []):
            if cle not in valeur:
                out.append(f"{chemin} : clé requise absente « {cle} »")
        for cle, v in valeur.items():
            if cle not in props:
                out.append(f"{chemin} : clé non autorisée « {cle} »")
            else:
                out.extend(erreurs(v, props[cle], racine, f"{chemin}.{cle}"))
    if isinstance(valeur, list):
        if "minItems" in schema and len(valeur) < schema["minItems"]:
            out.append(f"{chemin} : trop peu d'éléments")
        if "maxItems" in schema and len(valeur) > schema["maxItems"]:
            out.append(f"{chemin} : trop d'éléments")
        if schema.get("uniqueItems"):
            for i, x in enumerate(valeur):
                if any(_egal(x, y) for y in valeur[:i]):
                    out.append(f"{chemin} : éléments en double")
                    break
        if "items" in schema:
            for i, x in enumerate(valeur):
                out.extend(erreurs(x, schema["items"], racine, f"{chemin}[{i}]"))
    return out


def valide(valeur, schema):
    return not erreurs(valeur, schema)

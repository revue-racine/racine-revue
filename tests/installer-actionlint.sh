#!/usr/bin/env bash
# Installe actionlint v1.7.12 dans le dossier donné, après contrôle d'empreinte.
# L'empreinte est figée ici : un binaire différent fait échouer les contrôles.
set -euo pipefail
dest="$1"
url="https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz"
attendu="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
tmp="$(mktemp -d)"
curl -sfL -o "$tmp/a.tgz" "$url"
echo "$attendu  $tmp/a.tgz" | sha256sum -c --quiet -
mkdir -p "$dest"
tar -xzf "$tmp/a.tgz" -C "$dest" actionlint

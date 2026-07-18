#!/bin/bash
# Deploy the harness source tree to the (still-online) Nebula CA box.
#
# Set CA_BOX_HOST to your box's ssh target -- either export it, or drop a local
# (git-ignored) deploy.env next to this script:
#     echo 'CA_BOX_HOST=you@your-ca-box.lan' > deploy.env
# Optional in that file: CA_BOX_SRC (default /opt/nebula-ca/src); CA_SSH_KEY (an
# explicit `ssh -i` key path).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SCRIPT_DIR/deploy.env" ] && . "$SCRIPT_DIR/deploy.env"
: "${CA_BOX_HOST:?set CA_BOX_HOST (e.g. you@your-ca-box.lan) via env or deploy.env}"
CA_BOX_SRC="${CA_BOX_SRC:-/opt/nebula-ca/src}"

rsync -a --delete \
    --exclude '.git' --exclude '__pycache__' --exclude '.superpowers' \
    --exclude '.pytest_cache' --exclude 'ca-state' --exclude 'deploy.env' \
    -e "ssh -o IdentitiesOnly=yes${CA_SSH_KEY:+ -i $CA_SSH_KEY}" \
    "$SCRIPT_DIR/" \
    "${CA_BOX_HOST}:${CA_BOX_SRC}/"

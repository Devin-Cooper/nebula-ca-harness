#!/bin/bash
# Deploy the harness to the box, then run the stdlib unittest suite on it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SCRIPT_DIR/deploy.env" ] && . "$SCRIPT_DIR/deploy.env"
: "${CA_BOX_HOST:?set CA_BOX_HOST (e.g. you@your-ca-box.lan) via env or deploy.env}"
CA_BOX_SRC="${CA_BOX_SRC:-/opt/nebula-ca/src}"

"$SCRIPT_DIR/deploy.sh"

ssh -o IdentitiesOnly=yes${CA_SSH_KEY:+ -i $CA_SSH_KEY} "$CA_BOX_HOST" \
    "cd $CA_BOX_SRC && PYTHONPATH=box/lib python3 -m unittest discover -s tests/unit -v"

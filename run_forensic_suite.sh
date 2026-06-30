#!/usr/bin/env bash
# Bootstrap a local Python virtualenv, install requirements, then run the forensic suite.
set -Eeuo pipefail
IFS=$'\n\t'

PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:$PATH"
export PATH

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
VENV_DIR="$REPO_ROOT/.venv"
PYTHON_BIN="${PYTHON:-python3}"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -r "$REPO_ROOT/requirements.txt"

exec "$REPO_ROOT/scripts/master_detector.sh" --python "$VENV_DIR/bin/python" "$@"

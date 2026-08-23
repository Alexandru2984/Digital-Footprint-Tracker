#!/bin/sh
set -eu

# Run the reviewed source tree directly. Avoid installing VoidAccess package
# metadata because its all-features dependency declaration would pull the LLM,
# API, TUI and export stacks that this worker deliberately excludes.
release_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
export PYTHONPATH="${release_root}/source"
exec "${release_root}/venv/bin/python" -c \
    'import sys; sys.argv[0] = "voidaccess"; from voidaccess_cli.main import run; run()' \
    "$@"

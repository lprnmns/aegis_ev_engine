#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../engine"
PYTHONPATH=src python -m unittest discover -s tests

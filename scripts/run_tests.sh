#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../engine"
PYTHONPATH=src python3 -m unittest discover -s tests

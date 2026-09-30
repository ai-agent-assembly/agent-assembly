#!/bin/sh
# AAASM-6162 dogfood fixture: builds out/artifact.txt from src/lib.txt, so
# there is a real ordering dependency on the agent's own edit landing first.
set -e
mkdir -p out
cat src/lib.txt > out/artifact.txt

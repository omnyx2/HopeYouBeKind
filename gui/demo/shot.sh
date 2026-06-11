#!/usr/bin/env bash
# shot.sh <name>  — capture the Lattice window rect to shots/NN-<name>.png
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
shot "${1:?usage: shot.sh <name>}"

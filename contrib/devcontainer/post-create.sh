#!/usr/bin/env bash
# Post-create setup for Tetragon devcontainer.
# Compiles BPF programs, builds Go binaries, and prepares the environment.

set -euo pipefail

# The workspace belongs to the host user, not root.
git config --global --add safe.directory "$PWD"

# Build BPF from scratch so bear records every compile for clangd.
make -C bpf clean
make gen-compile-commands

make -j"$(nproc)" tetragon tetra tester-progs

cp -f bpf/objs/*.o /var/lib/tetragon/ 2>/dev/null || true

echo "Setup complete. Run 'make help' for the available targets."

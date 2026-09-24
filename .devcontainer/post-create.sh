#!/usr/bin/env bash
# Post-create setup for Tetragon devcontainer.
# Compiles BPF programs, builds Go binaries, and prepares the environment.

set -euo pipefail

echo "=============================================="
echo " Tetragon Development Container Setup"
echo "=============================================="

JOBS=$(nproc)

# ── Compile BPF programs (using local Clang) ────────────────────────────────
echo ""
echo "[1/4] Compiling BPF programs (LOCAL_CLANG=1) ..."
make tetragon-bpf LOCAL_CLANG=1 -j"${JOBS}"

# ── Build Go binaries ───────────────────────────────────────────────────────
echo ""
echo "[2/4] Building tetragon and tetra ..."
make tetragon tetra -j"${JOBS}"

# ── Compile tester programs ─────────────────────────────────────────────────
echo ""
echo "[3/4] Compiling test helper programs ..."
make tester-progs -j"${JOBS}"

# ── Copy BPF objects to runtime directory ───────────────────────────────────
echo ""
echo "[4/4] Installing BPF objects to /var/lib/tetragon/ ..."
cp -f bpf/objs/*.o /var/lib/tetragon/ 2>/dev/null || true

# ── Generate compile_commands.json for C/BPF IDE support ────────────────────
if command -v bear &>/dev/null; then
  echo ""
  echo "[bonus] Generating compile_commands.json for IDE support ..."
  make -C ./bpf clean
  bear -- make tetragon-bpf LOCAL_CLANG=1 -j"${JOBS}" || true
fi

echo ""
echo "=============================================="
echo " Setup complete!"
echo "=============================================="
echo ""
echo " Common targets:"
echo "   make tetragon            Build the agent"
echo "   make tetra               Build the CLI client"
echo "   make tetragon-bpf        Compile BPF programs (uses local Clang)"
echo "   make test                Run unit tests (requires sudo)"
echo "   make check               Run linters"
echo "   make format              Format Go + BPF code"
echo "   make kind-setup          Create Kind cluster + install Tetragon"
echo ""
echo " BPF compilation uses LOCAL_CLANG=1 by default in this container."
echo " For debug builds: make tetragon-bpf DEBUG=1"
echo ""

#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

# This script checks that bpf/errmetrics/fileids.h and pkg/errmetrics/files.go
# are kept in sync. Both files maintain a mapping of BPF source file names to
# numeric IDs used for error metrics.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

FILEIDS_H="${ROOT_DIR}/bpf/errmetrics/fileids.h"
FILES_GO="${ROOT_DIR}/pkg/errmetrics/files.go"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

if [[ ! -f "${FILEIDS_H}" ]]; then
    echo -e "${RED}error${NC}: ${FILEIDS_H} not found"
    exit 1
fi

if [[ ! -f "${FILES_GO}" ]]; then
    echo -e "${RED}error${NC}: ${FILES_GO} not found"
    exit 1
fi

# Extract mappings from fileids.h: fileid__("filename", id)
# Output format: id:filename
extract_from_h() {
    grep -E 'fileid__\(' "${FILEIDS_H}" | \
        sed -E 's/.*fileid__\("([^"]+)",\s*([0-9]+)\).*/\2:\1/' | \
        sort -t: -k1 -n
}

# Extract mappings from files.go: id: "filename",
# Output format: id:filename
extract_from_go() {
    grep -E '^\s+[0-9]+:\s+"[^"]+"' "${FILES_GO}" | \
        sed -E 's/^\s+([0-9]+):\s+"([^"]+)".*/\1:\2/' | \
        sort -t: -k1 -n
}

h_mappings=$(extract_from_h)
go_mappings=$(extract_from_go)

if [[ -z "${h_mappings}" ]]; then
    echo -e "${RED}error${NC}: no mappings found in ${FILEIDS_H}"
    exit 1
fi

if [[ -z "${go_mappings}" ]]; then
    echo -e "${RED}error${NC}: no mappings found in ${FILES_GO}"
    exit 1
fi

# Compare the mappings
if [[ "${h_mappings}" == "${go_mappings}" ]]; then
    echo -e "${GREEN}success${NC}: bpf/errmetrics/fileids.h and pkg/errmetrics/files.go are in sync"
    exit 0
fi

echo -e "${RED}error${NC}: bpf/errmetrics/fileids.h and pkg/errmetrics/files.go are out of sync"
echo ""
echo "Entries in fileids.h:"
echo "${h_mappings}" | sed 's/^/  /'
echo ""
echo "Entries in files.go:"
echo "${go_mappings}" | sed 's/^/  /'
echo ""
echo "Diff (fileids.h vs files.go):"
diff <(echo "${h_mappings}") <(echo "${go_mappings}") || true
echo ""
echo "Please ensure both files have identical mappings."
exit 1

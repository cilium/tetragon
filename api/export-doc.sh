#!/bin/bash

set -e -o pipefail

if [ -z "$1" ]; then
    echo "Usage: $0 export/to/path.md"
    exit 1
fi

TMP_FILE=$(mktemp)
trap "rm $TMP_FILE" EXIT

# use the generated proto documentation as source
cp v1/README.md $TMP_FILE

# cleanup the generated documentation for the website
# remove the link to the top of the page
sed -i'' -e '/<p align="right"><a href="#top">Top<\/a><\/p>/d' $TMP_FILE
sed -i'' -e '/<a name="top"><\/a>/d' $TMP_FILE
# remove title
sed -i'' -e '/^# Protocol Documentation/d' $TMP_FILE
# remove table of content
sed -i'' -e '/## Table of Contents/,/##/{//!d;}' $TMP_FILE
sed -i'' -e '/^## Table of Contents/d' $TMP_FILE
# cleanup unecessary consecutive whitelines
sed -i'' -e '/^[[:space:]]*$/N;/^[[:space:]]*\n[[:space:]]*$/D' $TMP_FILE
# remove empty line at the end of the file (required for macOS, doesn't harm on Linux)
sed -i'' -e '${/^$/d;}' $TMP_FILE

# Cleanup backup file that might be created by macOS sed:
rm ${TMP_FILE}-e 2>/dev/null || true

# add a frontmatter and a small introduction
echo '---
title: "gRPC API"
description: >
  This reference is generated from the protocol buffer specification and
  documents the gRPC API of Tetragon.
weight: 3
---

{{< comment >}}
This page was generated with github.io/cilium/tetragon/api/export-doc.sh,
please do not edit directly.
{{< /comment >}}

The Tetragon API is an independant Go module that can be found in the Tetragon
repository under [api](https://github.com/cilium/tetragon/tree/main/api). The
version 1 of this API is defined in
[github.com/cilium/tetragon/api/v1/tetragon](https://github.com/cilium/tetragon/tree/main/api/v1/tetragon).' | cat - $TMP_FILE > $1

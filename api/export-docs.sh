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
sed -i '/<p align="right"><a href="#top">Top<\/a><\/p>/d' $TMP_FILE
sed -i '/<a name="top"><\/a>/d' $TMP_FILE
# remove title
sed -i '/^# Protocol Documentation/d' $TMP_FILE
# remove table of content
sed -i -e '/## Table of Contents/,/##/{//!d}' $TMP_FILE
sed -i '/^## Table of Contents/d' $TMP_FILE
# cleanup unecessary consecutive whitelines
sed -i '/^[[:space:]]*$/N;/^[[:space:]]*\n[[:space:]]*$/D' $TMP_FILE

# add a frontmatter and a small introduction
echo '---
title: "gRPC API"
description: >
  This reference is generated from the protocol buffer specification and
  documents the gRPC API of Tetragon.
---

The Tetragon API is an independant Go module that can be found in the Tetragon
repository under [api](https://github.com/cilium/tetragon/tree/main/api). The
version 1 of this API is defined in
[api/v1/tetragon](https://github.com/cilium/tetragon/tree/main/api/v1/tetragon).' | cat - $TMP_FILE > $1


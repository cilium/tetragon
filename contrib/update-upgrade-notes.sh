#!/usr/bin/env bash

set -ex

if [ -z "$1" ] || [[ ! $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
  echo "USAGE: ./contrib/update-upgrade-notes.sh vX.Y.Z"
  exit 1
fi

NOTES_DIR="${NOTES_DIR:-contrib/upgrade-notes}"
version=$1

# Copy the latest upgrade notes to a version-specific file and create new latest from the template.
# Skip for pre-releases.
if [[ ! "$version" == *"-"* ]]; then
  cp "$NOTES_DIR/latest.md" "$NOTES_DIR/$version.md"
  cp "$NOTES_DIR/template.md" "$NOTES_DIR/latest.md"
fi

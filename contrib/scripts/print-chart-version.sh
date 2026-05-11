#!/usr/bin/env bash

set -euo pipefail

version="$(git describe --tags --always --exclude '*/*')"
printf '%s\n' "${version#v}"

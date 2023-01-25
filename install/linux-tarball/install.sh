#!/usr/bin/env bash

set -eu

SRC_DIR=$(dirname -- "$(readlink -f -- "$0")")

cp -vRf ${SRC_DIR}/usr/local/* /usr/local/

cp -vf /usr/local/lib/tetragon/systemd/tetragon.service /usr/lib/systemd/system/tetragon.service

install -d /etc/tetragon/tetragon.conf.d/

systemctl daemon-reload
systemctl enable tetragon
systemctl start tetragon

echo "Tetragon installed successfully!"

#!/usr/bin/env bash

set -eu

SRC_DIR=$(dirname -- "$(readlink -f -- "$0")")

cp -vRf ${SRC_DIR}/usr/local/* /usr/local/

cp -vf /usr/local/lib/tetragon/systemd/tetragon.service /usr/lib/systemd/system/tetragon.service

install -d /etc/tetragon/tetragon.conf.d/
install -d /etc/tetragon/tetragon.tp.d/

cp -v -n -r /usr/local/lib/tetragon/tetragon.conf.d /etc/tetragon/

# Default Tracing Policies
install -d /usr/lib/tetragon/
cp -v -r /usr/local/lib/tetragon/tetragon.tp.d /usr/lib/tetragon/

systemctl daemon-reload
systemctl enable tetragon
systemctl start tetragon

echo "Tetragon installed successfully!"

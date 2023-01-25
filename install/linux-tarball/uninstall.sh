#!/usr/bin/env bash

set -xu

if [ "$(id -u)" -ne 0 ]; then
        echo "Error: to uninstall Tetragon please run as root." >&2
        exit 1
fi

systemctl stop tetragon
systemctl disable tetragon

sudo rm -fr /usr/lib/systemd/system/tetragon.service
# Cleanup systemd state
systemctl daemon-reload

sudo rm -fr /usr/local/bin/tetragon
sudo rm -fr /usr/local/bin/tetra
sudo rm -fr /usr/local/lib/tetragon/

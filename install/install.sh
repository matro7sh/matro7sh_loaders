#!/bin/env bash

# autoinstall script to install
# CMEPW loaders onto your machine
# Super user is required
#
# Usage: sudo ./install.sh




set -euo pipefail

# no argument is required, display help and exit
[ $# -ne 0 ] && { head -n 10 "${0}" && exit 1 ; }

# checking if sudo
[ "$EUID" -ne 0 ] && { echo "please run as sudo !" && head -n 10 "${0}" && exit 1 ; }

echo "[+] Installing myph loader"
go install github.com/cmepw/myph@latest


echo "[+] Installing 221b loader"

# goversioninfo is required to be installed externally for 221b
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo

cd /tmp
git clone https://github.com/CMEPW/221b.git

cd 221b
go build -o 221b ./main.go

mv -v 221b /usr/local/bin/221b

cd -


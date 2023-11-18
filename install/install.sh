#!/bin/env bash

# autoinstall script to install
# CMEPW loaders onto your machine
# Super user is required
#
# Usage: sudo ./install.sh




set -euo pipefail

# no argument is required, display help and exit
[ -z "${1}" ] || { tail -n 10 "${0}" && exit 1 ; }


# checking if sudo
[ "$EUID" -ne 0 ] && { tail -n 10 "${0}" && exit 1 ; }

echo "[+] Installing myph loader"
go install github.com/cmepw/myph@latest


echo "[+] Installing 221b loader"

cd /tmp
git clone https://github.com/CMEPW/221b.git

cd 221b
go build -o 221b ./main.go

mv -v 221b /usr/local/bin/221b

cd -


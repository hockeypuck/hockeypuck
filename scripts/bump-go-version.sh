#!/bin/bash
set -euo pipefail

newversion=$1

perl -pi.bak -e "s/^(Build-Depends: .*) golang-[0-9.]+/\$1 golang-$newversion/" ./debian/control
perl -pi.bak -e "s/^FROM golang:[0-9.]+/FROM golang:$newversion/" ./Dockerfile
perl -pi.bak -e "s/\bGo [0-9.]+/Go $newversion/" ./README.md
perl -pi.bak -e "s/go-version: '[0-9.]+'/go-version: '$newversion'/" ./.github/workflows/pr.yml
perl -pi.bak -e "s,\bgo/[0-9.]+/,go/$newversion/," ./snapcraft.yaml
perl -pi.bak -e "s/\bgo_[0-9]+_[0-9]+/go_${newversion/\./_}/" ./shell.nix

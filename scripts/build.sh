#!/bin/sh
# Independent Linux reconstruction by t.me/ir_spoof.
set -eu
export GOTELEMETRY=off GOTOOLCHAIN=local CGO_ENABLED=0
export GOPROXY=off GOSUMDB=off
case "$(uname -s)" in Linux) ;; *) printf '%s\n' 'Build on Linux or set GOOS=linux explicitly.' >&2; exit 1;; esac
mkdir -p build
go build -mod=vendor -trimpath -buildvcs=false -ldflags='-s -w' -o build/netrix ./cmd/netrix
build/netrix -version
sha256sum build/netrix

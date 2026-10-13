#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p web/edge-scan
for target in windows-amd64 linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
 scan_os=${target%-*}; scan_arch=${target#*-}; scan_suffix=
 if [ "$scan_os" = windows ]; then scan_suffix=.exe; fi
 CGO_ENABLED=0 GOOS="$scan_os" GOARCH="$scan_arch" go build -buildvcs=false -trimpath -ldflags="-s -w" -o "web/edge-scan/aria-edge-scan-$target$scan_suffix" ./cmd/edge-scan
done
(cd web/edge-scan && sha256sum aria-edge-scan-* > SHA256SUMS)

#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p web/game-agent
for target in windows-amd64 linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
  agent_os=${target%-*}
  agent_arch=${target#*-}
  agent_suffix=
  if [ "$agent_os" = windows ]; then agent_suffix=.exe; fi
  CGO_ENABLED=0 GOOS="$agent_os" GOARCH="$agent_arch" go build -buildvcs=false -trimpath -ldflags="-s -w" -o "web/game-agent/game-route-agent-$target$agent_suffix" ./cmd/game-route-agent
done
(cd web/game-agent && sha256sum game-route-agent-* > SHA256SUMS)

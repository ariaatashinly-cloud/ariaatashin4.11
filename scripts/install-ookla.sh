#!/bin/sh
set -eu
# Running requires the operator's explicit confirmation and appropriate use license.
ookla_dest=${1:-/usr/local/bin}
ookla_work=$(mktemp -d)
trap 'rm -rf "$ookla_work"' EXIT
curl -fL --retry 2 https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz -o "$ookla_work/ookla.tgz"
echo "5690596c54ff9bed63fa3732f818a05dbc2db19ad36ed68f21ca5f64d5cfeeb7  $ookla_work/ookla.tgz" | sha256sum -c -
tar -xzf "$ookla_work/ookla.tgz" -C "$ookla_work"
mkdir -p "$ookla_dest"
install -m 0755 "$ookla_work/speedtest" "$ookla_dest/ookla-speedtest"

#!/bin/sh
# Packs the self-contained tshark of pcap-analyzer-py (musl, with its own loader and libraries) into the WAR's resources,
# so the WAR runs on any Linux x86_64 server without tshark installed.
# Usage: tools/bundle-tshark.sh PATH_TO_pcap-analyzer-py
set -eu
src="$1/linux-glibc2.26-server/runtime"
out="$(dirname "$0")/../src/main/resources/tshark/tshark-linux-x86_64.tar.gz"
tar -C "$src" --owner=0 --group=0 --sort=name --mtime=@0 -cf - tshark | gzip -9n > "$out"
"$src/tshark/bin/tshark" --version | head -1 | sed 's/^TShark (Wireshark) //' > "$(dirname "$out")/VERSION"
ls -l "$out"

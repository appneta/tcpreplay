#!/bin/sh
#
#   Copyright (c) 2026 Fred Klassen <tcpreplay.dev at gmail dot com> - AppNeta by Broadcom
#
#   The Tcpreplay Suite of tools is free software: you can redistribute it
#   and/or modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation, either version 3 of the
#   License, or with the authors permission any later version.
#
#   The Tcpreplay Suite is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
#
# Replay a truncated capture (60 of 1000 bytes captured, snaplen 60) over
# AF_XDP. The AF_XDP path used to copy the on-the-wire length into the umem
# frame, reading past libpcap's buffer and transmitting heap contents; under
# ASan that aborts.
#
# AF_XDP needs a driver that supports it, so this runs on a throwaway veth
# pair. It skips (77) off Linux, with --io-uring, without --xdp support, without root, or when
# the AF_XDP socket can't be set up - tcpreplay falls back to another injector
# then, which would make a pass meaningless.
#
# usage: xdp_truncated.sh <logfile> <tcpreplay-binary> [args...]

set -u

if [ $# -lt 2 ]; then
    echo "usage: $0 <logfile> <tcpreplay-binary> [args...]" >&2
    exit 99
fi

logfile="$1"; shift
dir=$(dirname "$0")
pcap="$dir/test_xdp_truncated.pcap"
iface="tcprxdp0"
peer="tcprxdp1"

if [ "$(uname -s)" != "Linux" ]; then
    echo "xdp_truncated: AF_XDP is Linux-only, skipping" >> "$logfile"
    exit 77
fi

for arg in "$@"; do
    if [ "$arg" = "--io-uring" ]; then
        echo "xdp_truncated: --io-uring excludes --xdp, skipping" >> "$logfile"
        exit 77
    fi
done

if ! "$1" --help 2>&1 | grep -q -- '--xdp'; then
    echo "xdp_truncated: built without AF_XDP support, skipping" >> "$logfile"
    exit 77
fi

if ! command -v ip >/dev/null 2>&1; then
    echo "xdp_truncated: 'ip' not found, skipping" >> "$logfile"
    exit 77
fi

cleanup() {
    ip link delete "$iface" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

ip link delete "$iface" >/dev/null 2>&1 || true
if ! ip link add "$iface" type veth peer name "$peer" >> "$logfile" 2>&1; then
    echo "xdp_truncated: could not create $iface (need root?), skipping" >> "$logfile"
    exit 77
fi
ip link set "$iface" up >> "$logfile" 2>&1
ip link set "$peer" up >> "$logfile" 2>&1

out=$("$@" --xdp -i "$iface" "$pcap" 2>&1)
rc=$?
echo "$out" >> "$logfile"

if echo "$out" | grep -q "unable to set up an AF_XDP socket"; then
    echo "xdp_truncated: AF_XDP unavailable on $iface, skipping" >> "$logfile"
    exit 77
fi

exit $rc

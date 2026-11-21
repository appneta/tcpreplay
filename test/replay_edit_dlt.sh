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
# tcpreplay-edit must decode a capture with the capture's own DLT, not the
# output interface's. Replays a Linux SLL capture onto an Ethernet NIC with
# --dlt=enet and --ttl, captures what goes out, and checks the frames are
# Ethernet with the given destination MAC and TTL. When tcpedit decoded the
# SLL header as Ethernet, nothing was converted or edited and no such frame
# was sent.
#
# usage: replay_edit_dlt.sh <interface> <logfile> <tcpreplay-edit> [args...]

set -u

if [ $# -lt 3 ]; then
    echo "usage: $0 <interface> <logfile> <tcpreplay-edit> [args...]" >&2
    exit 99
fi

iface="$1"; shift
logfile="$1"; shift
dir=$(dirname "$0")
pcap="$dir/test_sll_ipv4.pcap"
dmac="00:01:02:03:04:05"

if ! command -v tcpdump >/dev/null 2>&1; then
    echo "replay_edit_dlt: tcpdump not found, skipping" >> "$logfile"
    exit 77
fi

# Count matching frames from tcpdump's own output rather than reading back a
# capture file: AppArmor's tcpdump profile (Ubuntu) refuses to read a file
# without a .pcap-style name, which is what mktemp produces. The filter does
# the checking: Ethernet, the new destination MAC, and TTL 5.
filter="ether dst $dmac and udp dst port 5678 and ip[8] = 5"

attempt=1
while [ $attempt -le 3 ]; do
    out=$(mktemp) || exit 99
    err=$(mktemp) || { rm -f "$out"; exit 99; }
    tcpdump -i "$iface" -n -l "$filter" > "$out" 2> "$err" &
    tcpdump_pid=$!

    # wait until the capture socket is attached rather than guessing a delay
    i=0
    while [ $i -lt 50 ] && ! grep -q "listening on" "$err" 2>/dev/null; do
        if ! kill -0 "$tcpdump_pid" 2>/dev/null; then
            echo "replay_edit_dlt: tcpdump exited before capturing (need root?), skipping" >> "$logfile"
            cat "$err" >> "$logfile"
            rm -f "$out" "$err"
            exit 77
        fi
        sleep 0.1
        i=$((i + 1))
    done

    "$@" -i "$iface" --dlt=enet --enet-dmac="$dmac" --enet-smac=00:01:02:03:04:06 --ttl=5 \
        "$pcap" >> "$logfile" 2>&1
    rc=$?
    sleep 1
    kill "$tcpdump_pid" 2>/dev/null
    wait "$tcpdump_pid" 2>/dev/null

    count=$(grep -c "10.0.0.2.5678" "$out")
    cat "$out" >> "$logfile"
    rm -f "$out" "$err"

    if [ $rc -ne 0 ]; then
        echo "replay_edit_dlt: tcpreplay-edit exited $rc" >> "$logfile"
        exit 1
    fi

    if [ "$count" -ge 3 ]; then
        exit 0
    fi

    echo "replay_edit_dlt: captured $count of 3 converted, edited frames (attempt $attempt/3)" >> "$logfile"
    attempt=$((attempt + 1))
done

exit 1

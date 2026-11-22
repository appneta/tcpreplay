# $Id$
MAKEFLAGS=-s -k
PRINTF = @PRINTF@
HOST = @host@
TARGET = @target@
BUILD = @build@
nic1 = @nic1@
nic2 = @nic2@
hexdump = @test_hexdump@

ENABLE_DEBUG = @debug_run_time_flag@
TCPPREP=../src/tcpprep --no-arg-comment
TCPREPLAY=../src/tcpreplay
TCPREPLAY_EDIT=../src/tcpreplay-edit
TCPREWRITE=../src/tcprewrite
TCPBRIDGE=../src/tcpbridge
TCPCAPINFO=../src/tcpcapinfo
# verifies packets a replay reported as sent actually reached the wire (#1094)
WIRECHECK=$(srcdir)/wirecheck.sh
# replays against dummy interfaces at MTUs the default test NIC never
# exercises, to catch #1079/#1090-class bugs (#1097)
MTU_MATRIX=$(srcdir)/mtu_matrix.sh
# tcpreplay-edit must decode a capture with its own DLT, not the NIC's
REPLAY_EDIT_DLT=$(srcdir)/replay_edit_dlt.sh
# replays a truncated capture over AF_XDP on a throwaway veth pair
XDP_TRUNCATED=$(srcdir)/xdp_truncated.sh

TEST_PCAP=$(srcdir)/test.pcap
# frames sized either side of TX_RING's old 4096-byte truncation point (#1079)
TEST_JUMBO_PCAP=$(srcdir)/test_jumbo.pcap

# IP-only capture for the fragroute tests: fragroute aborts on the first
# non-IP packet, and test.pcap contains plenty of those.
FRAGROUTE_PCAP=$(srcdir)/test_fragroute.pcap
# single packets cut off inside the L4 header, snaplen == packet length so the
# replay buffer ends where the packet does (an overrun shows up under ASan)
TRUNC_L4_PCAPS = test_trunc_ipv6_plen.pcap test_trunc_udp_frag.pcap \
		test_trunc_tcp.pcap test_trunc_ipv6_udp.pcap
# edits that grow a packet: snaplen == captured length, so libpcap's buffer
# ends where the packet does and writing past it shows up under ASan
GROW_PCAPS = test_grow_pad.pcap test_grow_vlan.pcap test_maxsnaplen_raw.pcap

if COMPILE_FRAGROUTE
FRAGROUTE_TESTS = fragroute_valid fragroute_negsize fragroute_badrules
else
FRAGROUTE_TESTS =
endif

EXTRA_DIST = wirecheck.sh mtu_matrix.sh mtu_check_jumbo.py gen_jumbo_pcap.py replay_edit_dlt.sh xdp_truncated.sh \
		replay_order.sh order_compare.py \
		test.pcap test_jumbo.pcap test_nano.pcap test_fragroute.pcap test_sll_ipv4.pcap test_arp_sll.pcap test_fuzz_short_payload.pcap test_ipv6_remap.pcap test_xdp_truncated.pcap test_flow_hbh_trunc.pcap test_jnpr_ether.pcap test_capinfo_v23.pcap test_capinfo_v94.pcap test_capinfo_big.pcap $(TRUNC_L4_PCAPS) $(GROW_PCAPS) \
		test.auto_bridge test.auto_client test.auto_router \
		test.auto_server test.auto_first test.cidr test.comment test.port test.mac \
		test.cidr_reverse test.mac_reverse test.regex_reverse \
		test.include_packets test.exclude_packets test.include_source \
		test.include_dest test.prep_config \
		test.primary test.regex test.secondary \
		test.rewrite_seed test.rewrite_portmap test.rewrite_endpoint \
		test.rewrite_pnat test.rewrite_ipv6_prefix_remap test.rewrite_pad test.rewrite_trunc \
		test.rewrite_mac test.rewrite_layer2 test.rewrite_config \
		test.rewrite_skip test.rewrite_dltuser test.rewrite_dlthdlc test.rewrite_dltraw test.rewrite_nanosec \
		test.rewrite_vlan802.1ad test.rewrite_vlandel test.rewrite_efcs \
		test.rewrite_1ttl test.rewrite_2ttl test.rewrite_3ttl \
		test.rewrite_1ttl-hdrfix test.rewrite_2ttl-hdrfix test.rewrite_3ttl-hdrfix \
		test.rewrite_enet_subsmac \
		test.rewrite_mtutrunc test.rewrite_mac_seed test.rewrite_range_portmap \
		test.rewrite_mac_seed_keep test.rewrite_l7fuzzing test.rewrite_sequence test.rewrite_fixcsum \
		test.rewrite_fixlen_pad test.rewrite_fixlen_trunc test.rewrite_fixlen_del \
		test.replay_unique_ip test.replay_include test.replay_exclude \
		test2.rewrite_seed test2.rewrite_portmap test2.rewrite_endpoint \
		test2.rewrite_pnat test2.rewrite_ipv6_prefix_remap test2.rewrite_pad test2.rewrite_trunc \
		test2.rewrite_mac test2.rewrite_layer2 test2.rewrite_config \
		test2.rewrite_skip test2.rewrite_dltuser test2.rewrite_dlthdlc test2.rewrite_dltraw test2.rewrite_nanosec \
		test2.rewrite_vlan802.1ad test2.rewrite_vlandel test2.rewrite_efcs \
		test2.rewrite_1ttl test2.rewrite_2ttl test2.rewrite_3ttl \
		test2.rewrite_1ttl-hdrfix test2.rewrite_2ttl-hdrfix test2.rewrite_3ttl-hdrfix \
		test2.rewrite_mtutrunc test2.rewrite_enet_subsmac \
		test.rewrite_tos test2.rewrite_tos \
		test2.rewrite_enet_subsmac test2.rewrite_mac_seed \
		test2.rewrite_range_portmap test2.rewrite_mac_seed_keep \
		test2.rewrite_l7fuzzing test2.rewrite_sequence test2.rewrite_fixcsum \
		test2.rewrite_fixlen_pad test2.rewrite_fixlen_trunc test2.rewrite_fixlen_del \
		test2.replay_unique_ip test2.replay_include test2.replay_exclude

test: all
all: clearlog check tcpprep tcpreplay tcprewrite tcpcapinfo

clearlog:
	-rm test.log

check:
	$(PRINTF) "%s\n" "NOTICE: Tests must be run as root"
	$(PRINTF) "%s\n" "Sending traffic on '$(nic1)' and '$(nic2)'"

if WORDS_BIGENDIAN
STANDARD_REWRITE = standard_bigendian
REWRITE_WARN = "big"
VARIANT=
else
STANDARD_REWRITE = standard_littleendian
REWRITE_WARN = "little"
VARIANT="2"
endif

if HAVE_PCAP_NANO
STANDARD_NANOSEC = standard_nanosec
else
STANDARD_NANOSEC =
endif

standard: standard_prep $(STANDARD_REWRITE) $(STANDARD_NANOSEC)
	$(PRINTF) "Warning: only creating %s endian standard test files\n" $(REWRITE_WARN)

standard_prep:
	$(TCPPREP) -i $(TEST_PCAP) -o test.auto_router -a router
	$(TCPPREP) -i $(TEST_PCAP) -o test.auto_bridge -a bridge
	$(TCPPREP) -i $(TEST_PCAP) -o test.auto_client -a client
	$(TCPPREP) -i $(TEST_PCAP) -o test.auto_server -a server
	$(TCPPREP) -i $(TEST_PCAP) -o test.auto_first -a first
	$(TCPPREP) --load-opts config -o test.prep_config
	$(TCPPREP) -i $(TEST_PCAP) -o test.port -p
	$(TCPPREP) -i $(TEST_PCAP) -o test.mac -e 00:1f:f3:3c:e1:13
	$(TCPPREP) -i $(TEST_PCAP) -o test.cidr -c '96.17.211.0/24'
	$(TCPPREP) -i $(TEST_PCAP) -o test.regex -r '96.17.211.*'
	$(TCPPREP) -i $(TEST_PCAP) -o test.comment -C "This is a comment" -p
	$(TCPPREP) -i $(TEST_PCAP) -o test.mac_reverse -e 00:1f:f3:3c:e1:13 --reverse
	$(TCPPREP) -i $(TEST_PCAP) -o test.cidr_reverse -c '96.17.211.0/24' --reverse
	$(TCPPREP) -i $(TEST_PCAP) -o test.regex_reverse -r '96.17.211.*' --reverse
	$(TCPPREP) -i $(TEST_PCAP) -o test.exclude_packets -c '96.17.211.0/24' --exclude 'P:61-65,88-91'
	$(TCPPREP) -i $(TEST_PCAP) -o test.include_packets -c '96.17.211.0/24' --include 'P:61-65,88-91'
	$(TCPPREP) -i $(TEST_PCAP) -o test.include_source -c '96.17.211.0/24' --include 'S:96.0.0.0/8'
	$(TCPPREP) -i $(TEST_PCAP) -o test.include_dest -c '96.17.211.0/24' --include 'D:96.0.0.0/8'

standard_nanosec:
	$(TCPREWRITE) -i $(srcdir)/test_nano.pcap -o test$(VARIANT).rewrite_nanosec

standard_bigendian:
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_seed -s 55
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_tos --tos=50
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_portmap -r 80:8080
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_range_portmap -r 1-100:49148
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_sequence --tcp-sequence 42
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_endpoint \
		-e 10.10.0.1:10.10.0.2 -c test.auto_router
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_pnat \
		-N 96.17.211.0/24:172.16.0.0/24
	$(TCPREWRITE) -i $(srcdir)/test_ipv6_remap.pcap -o test.rewrite_ipv6_prefix_remap \
		--srcipmap="[2001:db8:8000::/33]:[2001:dbff::/33]"
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_pad -F pad
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_trunc -F trunc
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_mac \
		--enet-dmac=00:12:13:14:15:16,00:22:33:44:55:66 \
		--enet-smac=00:22:33:44:55:66,00:12:13:14:15:16  -c $(srcdir)/test.auto_router
	 $(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_enet_subsmac \
		--enet-subsmac=00:1f:f3:3c:e1:13,00:22:33:44:55:66 \
		--enet-subsmac=f8:1e:df:e5:84:3a,00:66:55:44:33:22
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_mac_seed --enet-mac-seed=42
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_mac_seed_keep --enet-mac-seed=42 \
		--enet-mac-seed-keep-bytes=3
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_layer2 \
		 --dlt=user --user-dlink=00,50,da,5d,46,55,0,7,eb,30,a4,c3,08,0
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_config --enet-vlan=add --enet-vlan-tag=45 \
		--enet-vlan-cfi=1 --enet-vlan-pri=5
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_skip \
	    --skipbroadcast --skipl2broadcast --skip-soft-errors --seed 55 \
		--enet-dmac=00:12:13:14:15:16,00:22:33:44:55:66 \
		--enet-smac=00:22:33:44:55:66,00:12:13:14:15:16  -c $(srcdir)/test.auto_router
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_dltuser --dlt=user \
		--user-dlink=0x0f,0x00,0x08,0x00 --user-dlt=104
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_dlthdlc --dlt=hdlc \
		--hdlc-control=0 --hdlc-address=0x0F
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_dltraw --dlt=raw \
		--skip-soft-errors
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_vlan802.1ad \
		--enet-vlan=add --enet-vlan-tag=42 --enet-vlan-cfi=1 \
		--enet-vlan-pri=2 --enet-vlan-proto=802.1ad
	$(TCPREWRITE) -i $(srcdir)/test.rewrite_config -o test.rewrite_vlandel \
		--enet-vlan=del
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_efcs --efcs
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_1ttl --ttl=58
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_2ttl --ttl=+58
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_3ttl --ttl=-58
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_1ttl-hdrfix --ttl=59 --fixhdrlen
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_2ttl-hdrfix --ttl=+59 --fixhdrlen
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_3ttl-hdrfix --ttl=-59 --fixhdrlen
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_mtutrunc --mtu-trunc --mtu=300
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_l7fuzzing \
		--fuzz-seed=42 --fuzz-factor=2
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_fixcsum --fixcsum
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_fixlen_pad --fixlen=pad
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_fixlen_trunc --fixlen=trunc
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.rewrite_fixlen_del --fixlen=del
	$(TCPREPLAY) -w test.replay_include -t --include=7,11,20-23,174- $(TEST_PCAP)
	$(TCPREPLAY) -w test.replay_exclude -t --exclude=23-,11-20,2,3 $(TEST_PCAP)
	$(TCPREPLAY) -w test.replay_unique_ip -t --unique-ip --loop=2 $(TEST_PCAP)

standard_littleendian:
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_seed -s 55
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_tos --tos=50
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_portmap -r 80:8080
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_range_portmap -r 1-100:49148
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_sequence --tcp-sequence 42
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_endpoint \
		-e 10.10.0.1:10.10.0.2 -c test.auto_router
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_pnat \
		-N 96.17.211.0/24:172.16.0.0/24
	$(TCPREWRITE) -i $(srcdir)/test_ipv6_remap.pcap -o test2.rewrite_ipv6_prefix_remap \
		--srcipmap="[2001:db8:8000::/33]:[2001:dbff::/33]"
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_pad -F pad
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_trunc -F trunc
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_mac \
		--enet-dmac=00:12:13:14:15:16,00:22:33:44:55:66 \
		--enet-smac=00:22:33:44:55:66,00:12:13:14:15:16  -c $(srcdir)/test.auto_router
	 $(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_enet_subsmac \
		--enet-subsmac=00:1f:f3:3c:e1:13,00:22:33:44:55:66 \
		--enet-subsmac=f8:1e:df:e5:84:3a,00:66:55:44:33:22
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_mac_seed --enet-mac-seed=42
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_mac_seed_keep --enet-mac-seed=42 \
		--enet-mac-seed-keep-bytes=3
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_layer2 \
		 --dlt=user --user-dlink=00,50,da,5d,46,55,0,7,eb,30,a4,c3,08,0
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_config --enet-vlan=add --enet-vlan-tag=45 \
		--enet-vlan-cfi=1 --enet-vlan-pri=5
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_skip \
	    --skipbroadcast --skipl2broadcast --skip-soft-errors --seed 55 \
		--enet-dmac=00:12:13:14:15:16,00:22:33:44:55:66 \
		--enet-smac=00:22:33:44:55:66,00:12:13:14:15:16  -c $(srcdir)/test.auto_router
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_dltuser --dlt=user \
		--user-dlink=0x0f,0x00,0x08,0x00 --user-dlt=104
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_dlthdlc --dlt=hdlc \
		--hdlc-control=0 --hdlc-address=0x0F
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_dltraw --dlt=raw \
		--skip-soft-errors
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_vlan802.1ad \
		--enet-vlan=add --enet-vlan-tag=42 --enet-vlan-cfi=1 \
		--enet-vlan-pri=2 --enet-vlan-proto=802.1ad
	$(TCPREWRITE) -i $(srcdir)/test.rewrite_config -o test2.rewrite_vlandel \
		--enet-vlan=del
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_efcs --efcs
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_1ttl --ttl=58
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_2ttl --ttl=+58
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_3ttl --ttl=-58
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_1ttl-hdrfix --ttl=59 --fixhdrlen
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_2ttl-hdrfix --ttl=+59 --fixhdrlen
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_3ttl-hdrfix --ttl=-59 --fixhdrlen
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_mtutrunc --mtu-trunc --mtu=300
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_l7fuzzing \
		--fuzz-seed=42 --fuzz-factor=2
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_fixcsum --fixcsum
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_fixlen_pad --fixlen=pad
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_fixlen_trunc --fixlen=trunc
	$(TCPREWRITE) -i $(TEST_PCAP) -o test2.rewrite_fixlen_del --fixlen=del
	$(TCPREPLAY) -w test2.replay_include -t --include=7,11,20-23,174- $(TEST_PCAP)
	$(TCPREPLAY) -w test2.replay_exclude -t --exclude=23-,11-20,2,3 $(TEST_PCAP)
	$(TCPREPLAY) -w test2.replay_unique_ip -t --unique-ip --loop=2 $(TEST_PCAP)

tcpcapinfo: capinfo_version capinfo_big_packet

tcpprep: auto_router auto_bridge auto_client auto_server auto_first cidr regex \
	port mac comment print_info print_comment prep_config \
	mac_reverse cidr_reverse regex_reverse exclude_packets \
	include_packets include_source include_dest

tcprewrite: rewrite_portmap rewrite_range_portmap rewrite_endpoint \
	rewrite_pnat rewrite_ipv6_prefix_remap rewrite_portmap_invalid rewrite_portmap_big \
	rewrite_jnpr_ether \
	rewrite_arp_align \
	rewrite_cidr_invalid \
	rewrite_trunc rewrite_pad rewrite_seed rewrite_mac \
	rewrite_layer2 rewrite_config rewrite_skip rewrite_dltuser rewrite_dlthdlc rewrite_dltraw rewrite_nanosec \
	rewrite_vlan802.1ad rewrite_vlandel rewrite_efcs \
	rewrite_1ttl rewrite_2ttl rewrite_3ttl rewrite_1ttl-hdrfix rewrite_2ttl-hdrfix rewrite_3ttl-hdrfix \
	rewrite_tos rewrite_mtutrunc rewrite_enet_subsmac rewrite_mac_seed \
	rewrite_mac_seed_keep rewrite_l7fuzzing rewrite_sequence rewrite_fixcsum \
	rewrite_fixlen_pad rewrite_fixlen_trunc rewrite_fixlen_del \
	rewrite_dltuser_maxsnaplen rewrite_cache_short rewrite_seed_arp_dlt $(FRAGROUTE_TESTS)

tcpreplay: replay_wirecheck replay_mtu_jumbo replay_mtu_small replay_ordering replay_basic replay_nano_timer replay_cache \
	replay_pps replay_rate replay_top \
	replay_config replay_multi replay_pps_multi replay_precache \
	replay_stats replay_dualfile replay_maxsleep replay_include replay_exclude replay_unique_ip \
	replay_edit_trunc_l4 replay_edit_grow replay_xdp_truncated replay_flow_hbh_trunc replay_edit_fuzz_short replay_edit_dlt

# re-run the whole tcpreplay test group with the io_uring injection method;
# not part of 'make test' - CI invokes it explicitly on Linux builds
if COMPILE_LIBURING
tcpreplay_io_uring:
	$(PRINTF) "%s\n" "Repeating tcpreplay tests with --io-uring:"
	$(PRINTF) "%s\n" "*** Repeating tcpreplay tests with --io-uring: " >> test.log
	$(MAKE) tcpreplay TCPREPLAY="$(TCPREPLAY) --io-uring"
endif

prep_config:
	$(PRINTF) "%s" "[tcpprep] Config mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Config mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) --load-opts=config -o test.$@1  >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

auto_router:
	$(PRINTF) "%s" "[tcpprep] Auto/Router mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Auto/Router mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -a router  >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

auto_bridge:
	$(PRINTF) "%s" "[tcpprep] Auto/Bridge mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Auto/Bridge mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -a bridge  >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

auto_client:
	$(PRINTF) "%s" "[tcpprep] Auto/Client mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Auto/Client mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -a client  >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

auto_server:
	$(PRINTF) "%s" "[tcpprep] Auto/Server mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Auto/Server mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -a server >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

auto_first:
	$(PRINTF) "%s" "[tcpprep] Auto/First mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Auto/First mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -a first >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

regex:
	$(PRINTF) "%s" "[tcpprep] Regex mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Regex mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -r '96.17.211.*' >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

cidr:
	$(PRINTF) "%s" "[tcpprep] CIDR mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] CIDR mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -c '96.17.211.0/24' >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

port:
	$(PRINTF) "%s" "[tcpprep] Port mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Port mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -p >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

mac:
	$(PRINTF) "%s" "[tcpprep] MAC mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] MAC mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -e 00:1f:f3:3c:e1:13 >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

comment:
	$(PRINTF) "%s" "[tcpprep] Comment mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Comment mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -C "This is a comment" -p >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

print_comment:
	$(PRINTF) "%s" "[tcpprep] Print comment mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Print comment mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -P $(srcdir)/test.comment >$(srcdir)/test.$@1 >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; else $(PRINTF) "\t\t%s\n" "FAILED"; false; fi

print_info:
	$(PRINTF) "%s" "[tcpprep] Print info mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Print info mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -I $(srcdir)/test.comment >$(srcdir)/test.$@1 >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; else $(PRINTF) "\t\t%s\n" "FAILED"; false; fi


regex_reverse:
	$(PRINTF) "%s" "[tcpprep] Regex reverse mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Regex reverse mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -r '96.17.211.*' --reverse >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

cidr_reverse:
	$(PRINTF) "%s" "[tcpprep] CIDR reverse mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] CIDR reverse mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -c '96.17.211.0/24' --reverse >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

mac_reverse:
	$(PRINTF) "%s" "[tcpprep] MAC reverse mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] MAC reverse mode test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -e 00:1f:f3:3c:e1:13 --reverse >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

exclude_packets:
	$(PRINTF) "%s" "[tcpprep] exclude packets test: "
	$(PRINTF) "%s\n" "*** [tcpprep] exclude packets test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -c '96.17.211.0/24' --exclude 'P:61-65,88-91' >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

include_packets:
	$(PRINTF) "%s" "[tcpprep] include packets test: "
	$(PRINTF) "%s\n" "*** [tcpprep] include packets test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -c '96.17.211.0/24' --include 'P:61-65,88-91' >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

include_source:
	$(PRINTF) "%s" "[tcpprep] include source test: "
	$(PRINTF) "%s\n" "*** [tcpprep] include source test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -c '96.17.211.0/24' --include 'S:96.0.0.0/8' >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

include_dest:
	$(PRINTF) "%s" "[tcpprep] include destination test: "
	$(PRINTF) "%s\n" "*** [tcpprep] include destination test: " >> test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -c '96.17.211.0/24' --include 'D:96.0.0.0/8' >> test.log 2>&1
	if diff $(srcdir)/test.$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

# #1078 regression: TX_RING stranded frames in the ring and reported them as
# sent, so a short replay claimed 179 packets sent and transmitted zero while
# exiting 0. Only the interface counter can tell those apart. -l 1 is the
# worst case, where the entire run was lost.
replay_wirecheck:
	$(PRINTF) "%s" "[tcpreplay] Wire delivery test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Wire delivery test: " >> test.log
	$(WIRECHECK) $(nic1) test.log $(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -l 1 -t $(TEST_PCAP); \
	rc=$$?; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; \
	elif [ $$rc -eq 77 ] ; then $(PRINTF) "\t\t%s\n" "SKIPPED"; \
	else $(PRINTF) "\t\t%s\n" "FAILED"; false; fi

# #1097: the default test NIC never exercises an MTU that reproduces #1079
# (jumbo) or #1090 (small, the IPv6 minimum). Linux-only (dummy interfaces);
# skips cleanly elsewhere.
# AF_XDP must send only the captured bytes of a truncated packet. Linux with
# libxdp only; skips cleanly elsewhere.
replay_xdp_truncated:
	$(PRINTF) "%s" "[tcpreplay] AF_XDP truncated capture test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] AF_XDP truncated capture test: " >> test.log
	$(XDP_TRUNCATED) test.log $(TCPREPLAY) $(ENABLE_DEBUG); \
	rc=$$?; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t%s\n" "OK"; \
	elif [ $$rc -eq 77 ] ; then $(PRINTF) "\t%s\n" "SKIPPED"; \
	else $(PRINTF) "\t%s\n" "FAILED"; tail -n 20 test.log >&2; false; fi

# a Linux SLL capture replayed onto an Ethernet NIC with --dlt=enet and --ttl
# must go out converted and edited; skips without tcpdump
replay_edit_dlt:
	$(PRINTF) "%s" "[tcpreplay-edit] Capture DLT test: "
	$(PRINTF) "%s\n" "*** [tcpreplay-edit] Capture DLT test: " >> test.log
	$(REPLAY_EDIT_DLT) $(nic1) test.log $(TCPREPLAY_EDIT) $(ENABLE_DEBUG); \
	rc=$$?; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; \
	elif [ $$rc -eq 77 ] ; then $(PRINTF) "\t\t%s\n" "SKIPPED"; \
	else $(PRINTF) "\t\t%s\n" "FAILED"; tail -n 20 test.log >&2; false; fi

replay_mtu_jumbo:
	$(PRINTF) "%s" "[tcpreplay] Jumbo MTU (9000) test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Jumbo MTU (9000) test: " >> test.log
	$(MTU_MATRIX) jumbo test.log $(TCPREPLAY) $(ENABLE_DEBUG); \
	rc=$$?; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; \
	elif [ $$rc -eq 77 ] ; then $(PRINTF) "\t\t%s\n" "SKIPPED"; \
	else $(PRINTF) "\t\t%s\n" "FAILED"; tail -n 40 test.log >&2; false; fi

replay_mtu_small:
	$(PRINTF) "%s" "[tcpreplay] Small MTU (1280) test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Small MTU (1280) test: " >> test.log
	$(MTU_MATRIX) small test.log $(TCPREPLAY) $(ENABLE_DEBUG); \
	rc=$$?; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; \
	elif [ $$rc -eq 77 ] ; then $(PRINTF) "\t\t%s\n" "SKIPPED"; \
	else $(PRINTF) "\t\t%s\n" "FAILED"; tail -n 40 test.log >&2; false; fi

# #1098: ordering was never verified empirically, only reasoned about from
# the code (#1074, #1078). Linux-only (dummy interfaces); skips cleanly
# elsewhere.
replay_ordering:
	$(PRINTF) "%s" "[tcpreplay] Packet ordering test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Packet ordering test: " >> test.log
	$(srcdir)/replay_order.sh test.log $(TCPREPLAY) $(ENABLE_DEBUG); \
	rc=$$?; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; \
	elif [ $$rc -eq 77 ] ; then $(PRINTF) "\t\t%s\n" "SKIPPED"; \
	else $(PRINTF) "\t\t%s\n" "FAILED"; tail -n 40 test.log >&2; false; fi

replay_basic:
	$(PRINTF) "%s" "[tcpreplay] Basic test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Basic test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -t $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

replay_nano_timer:
	$(PRINTF) "%s" "[tcpreplay] Nano timer test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Nano timer test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) --loop=2 --loopdelay-ns=125000000 -t $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

replay_cache:
	$(PRINTF) "%s" "[tcpreplay] Cache test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Cache test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -c $(srcdir)/test.cidr -i $(nic1) -I $(nic2) -t $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi


# TCP packets with a 1-byte payload, snaplen == packet length: every packet is
# fuzzed, and any mutation that runs past the payload shows up under ASan
replay_edit_fuzz_short:
	$(PRINTF) "%s" "[tcpreplay-edit] Fuzz short payload test: "
	$(PRINTF) "%s\n" "*** [tcpreplay-edit] Fuzz short payload test: " >> test.log
	$(TCPREPLAY_EDIT) $(ENABLE_DEBUG) -i $(nic1) --fuzz-seed=7 --fuzz-factor=1 \
		$(srcdir)/test_fuzz_short_payload.pcap >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t%s\n" "OK"; else $(PRINTF) "\t%s\n" "FAILED"; false; fi

# IPv6 hop-by-hop next header with nothing captured after the IPv6 header,
# snaplen == packet length; flow stats are on by default
replay_flow_hbh_trunc:
	$(PRINTF) "%s" "[tcpreplay] Truncated IPv6 hop-by-hop flow test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Truncated IPv6 hop-by-hop flow test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -t $(srcdir)/test_flow_hbh_trunc.pcap >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t%s\n" "OK"; else $(PRINTF) "\t%s\n" "FAILED"; false; fi

replay_edit_trunc_l4:
	$(PRINTF) "%s" "[tcpreplay-edit] Truncated L4 header test: "
	$(PRINTF) "%s\n" "*** [tcpreplay-edit] Truncated L4 header test: " >> test.log
	rc=0; \
	for t in "--fixcsum test_trunc_ipv6_plen.pcap" "--mtu-trunc test_trunc_udp_frag.pcap" \
		 "--tcp-sequence=5 test_trunc_tcp.pcap" "--seed=42 test_trunc_ipv6_udp.pcap"; do \
	    set -- $$t; \
	    $(PRINTF) "%s\n" "--- $$t" >> test.log; \
	    $(TCPREPLAY_EDIT) $(ENABLE_DEBUG) -i $(nic1) $$1 $(srcdir)/$$2 >> test.log 2>&1 || rc=1; \
	done; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t%s\n" "OK"; else $(PRINTF) "\t%s\n" "FAILED"; false; fi

replay_edit_grow:
	$(PRINTF) "%s" "[tcpreplay-edit] Packet growing edits test: "
	$(PRINTF) "%s\n" "*** [tcpreplay-edit] Packet growing edits test: " >> test.log
	rc=0; \
	$(TCPREPLAY_EDIT) $(ENABLE_DEBUG) -i $(nic1) --fixlen=pad \
		$(srcdir)/test_grow_pad.pcap >> test.log 2>&1 || rc=1; \
	$(TCPREPLAY_EDIT) $(ENABLE_DEBUG) -i $(nic1) --preload-pcap --fixlen=pad \
		$(srcdir)/test_grow_pad.pcap >> test.log 2>&1 || rc=1; \
	$(TCPREPLAY_EDIT) $(ENABLE_DEBUG) -i $(nic1) --enet-vlan=add --enet-vlan-tag=5 \
		$(srcdir)/test_grow_vlan.pcap >> test.log 2>&1 || rc=1; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t%s\n" "OK"; else $(PRINTF) "\t%s\n" "FAILED"; false; fi

replay_accurate:
	$(PRINTF) "%s" "[tcpreplay] Accurate test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Accurate test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -a -i $(nic1) $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

replay_stats:
	$(PRINTF) "%s" "[tcpreplay] Statistics test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Statistics test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) --stats=1 -i $(nic1) $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

rewrite_portmap:
	$(PRINTF) "%s" "[tcprewrite] Portmap test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Portmap test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -r 80:8080 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_range_portmap:
	$(PRINTF) "%s" "[tcprewrite] Portmap range test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Portmap range test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -r 1-100:49148 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_sequence:
	$(PRINTF) "%s" "[tcprewrite] TCP sequence test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] TCP sequence test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --tcp-sequence 42 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_endpoint:
	$(PRINTF) "%s" "[tcprewrite] Endpoint test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Endpoint test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -e 10.10.0.1:10.10.0.2 \
	    -c $(srcdir)/test.auto_router  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

# an IPv6 prefix that isn't a multiple of 8 bits splits a byte between the
# network and the original address
rewrite_ipv6_prefix_remap:
	$(PRINTF) "%s" "[tcprewrite] IPv6 /33 remap test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] IPv6 /33 remap test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(srcdir)/test_ipv6_remap.pcap -o test.$@1 \
	    --srcipmap="[2001:db8:8000::/33]:[2001:dbff::/33]" >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

# a malformed portmap must be refused, not crash (signals are exit 128-254)
rewrite_portmap_invalid:
	$(PRINTF) "%s" "[tcprewrite] Invalid portmap test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Invalid portmap test: " >> test.log
	rc=0; \
	for spec in "-:80" "+:80" "80:81,+:82"; do \
	    $(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -r "$$spec" > test.$@.out 2>&1; \
	    status=$$?; \
	    cat test.$@.out >> test.log; \
	    if [ $$status -eq 0 ] || { [ $$status -ge 128 ] && [ $$status -ne 255 ]; } || \
	       grep -q "Sanitizer\|runtime error" test.$@.out; then \
	        $(PRINTF) "%s\n" "ERROR: portmap '$$spec' exited $$status" >> test.log; rc=1; \
	    fi; \
	done; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

# ARP addresses aren't 4-byte aligned: -N and --seed read and wrote them through
# uint32_t pointers. clang's UBSan flags that (#1190); the output is covered by
# the rewrite_pnat/rewrite_seed golden files.
rewrite_arp_align:
	$(PRINTF) "%s" "[tcprewrite] ARP alignment test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] ARP alignment test: " >> test.log
	rc=0; \
	for args in "-N 10.0.0.0/8:172.16.0.0/12" "-s 55"; do \
	    $(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 $$args > test.$@.out 2>&1; \
	    status=$$?; \
	    cat test.$@.out >> test.log; \
	    if [ $$status -ne 0 ] || grep -q "Sanitizer\|runtime error" test.$@.out; then \
	        $(PRINTF) "%s\n" "ERROR: tcprewrite $$args exited $$status" >> test.log; rc=1; \
	    fi; \
	done; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; else $(PRINTF) "\t\t%s\n" "FAILED"; false; fi


# only pcap 2.4 is supported, but the check accepted 2.3 and 9.4 (#1187)
capinfo_version:
	$(PRINTF) "%s" "[tcpcapinfo] Version check test: "
	$(PRINTF) "%s\n" "*** [tcpcapinfo] Version check test: " >> test.log
	rc=0; \
	for f in test_capinfo_v23.pcap test_capinfo_v94.pcap; do \
	    $(TCPCAPINFO) $(srcdir)/$$f > test.$@.out 2>&1; \
	    cat test.$@.out >> test.log; \
	    grep -q "only support file format version 2.4" test.$@.out || rc=1; \
	done; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; else $(PRINTF) "\t\t%s\n" "FAILED"; false; fi

# a packet bigger than tcpcapinfo's 64 KB buffer but within the snaplen: the
# rest of it was then parsed as record headers (#1187)
capinfo_big_packet:
	$(PRINTF) "%s" "[tcpcapinfo] Large packet test: "
	$(PRINTF) "%s\n" "*** [tcpcapinfo] Large packet test: " >> test.log
	$(TCPCAPINFO) $(srcdir)/test_capinfo_big.pcap > test.$@.out 2>&1; \
	cat test.$@.out >> test.log; \
	if [ "$$(grep -c 'OK$$' test.$@.out)" -eq 2 ] && ! grep -q "TOOBIG\|truncated\|corrupt" test.$@.out; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; false; \
	fi

# Juniper Ethernet -> Ethernet must strip the 12-byte Juniper header (6 fixed,
# 6 of extensions) and keep the frame intact. Compares packet bytes only (past
# the 24-byte file and 16-byte record headers), so it holds for either byte
# order; the extension length was read as 0 on big-endian hosts (#1189)
rewrite_jnpr_ether:
	$(PRINTF) "%s" "[tcprewrite] Juniper Ethernet test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Juniper Ethernet test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(srcdir)/test_jnpr_ether.pcap -o test.$@1 --dlt=enet >> test.log 2>&1; \
	status=$$?; \
	tail -c +41 test.$@1 > test.$@.got 2>/dev/null; \
	tail -c +53 $(srcdir)/test_jnpr_ether.pcap > test.$@.want; \
	if [ $$status -eq 0 ] && cmp test.$@.want test.$@.got >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

# a negative IPv4 prefix length was accepted and matched every address (#1186)
rewrite_cidr_invalid:
	$(PRINTF) "%s" "[tcprewrite] Invalid CIDR test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Invalid CIDR test: " >> test.log
	rc=0; \
	for args in "-N 10.0.0.0/-5:172.16.0.0/24" "--srcipmap=10.0.0.0/24:172.16.0.0/-1" \
	            "-N 10.0.0.0/33:172.16.0.0/24"; do \
	    $(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 $$args > test.$@.out 2>&1; \
	    status=$$?; \
	    cat test.$@.out >> test.log; \
	    if [ $$status -eq 0 ] || { [ $$status -ge 128 ] && [ $$status -ne 255 ]; } || \
	       grep -q "Sanitizer\|runtime error" test.$@.out; then \
	        $(PRINTF) "%s\n" "ERROR: tcprewrite $$args exited $$status" >> test.log; rc=1; \
	    fi; \
	done; \
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -N 10.0.0.0/0:172.16.0.0/0 > test.$@.out 2>&1; \
	status=$$?; cat test.$@.out >> test.log; \
	if [ $$status -ne 0 ] || grep -q "Sanitizer\|runtime error" test.$@.out; then \
	    $(PRINTF) "%s\n" "ERROR: tcprewrite -N 10.0.0.0/0 exited $$status" >> test.log; rc=1; \
	fi; \
	$(TCPPREP) -i $(TEST_PCAP) -o test.$@.cache -c 10.0.0.0/-5 > test.$@.out 2>&1; \
	status=$$?; cat test.$@.out >> test.log; \
	if [ $$status -eq 0 ] || { [ $$status -ge 128 ] && [ $$status -ne 255 ]; }; then \
	    $(PRINTF) "%s\n" "ERROR: tcpprep -c 10.0.0.0/-5 exited $$status" >> test.log; rc=1; \
	fi; \
	if [ $$rc -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

# each port in a range is a list node: 4 full ranges is 262,148 nodes
rewrite_portmap_big:
	$(PRINTF) "%s" "[tcprewrite] Large portmap test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Large portmap test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 \
	    -r 0-65535:1,0-65535:2,0-65535:3,0-65535:4 >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

rewrite_pnat:
	$(PRINTF) "%s" "[tcprewrite] Pseudo NAT test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Pseudo NAT test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 \
	    -N 96.17.211.0/24:172.16.0.0/24  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_mac:
	$(PRINTF) "%s" "[tcprewrite] Src/Dst MAC test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Src/Dst MAC test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 \
		--enet-dmac=00:12:13:14:15:16,00:22:33:44:55:66 \
		--enet-smac=00:22:33:44:55:66,00:12:13:14:15:16  -c $(srcdir)/test.auto_router  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_enet_subsmac:
	$(PRINTF) "%s" "[tcprewrite] Substitute Src/Dst MAC test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Substitute Src/Dst MAC test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 \
		--enet-subsmac=00:1f:f3:3c:e1:13,00:22:33:44:55:66 \
		--enet-subsmac=f8:1e:df:e5:84:3a,00:66:55:44:33:22  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_mac_seed:
	$(PRINTF) "%s" "[tcprewrite] Seeded MAC test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Seeded MAC test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 \
		--enet-mac-seed=42 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_mac_seed_keep:
	$(PRINTF) "%s" "[tcprewrite] Seeded Keep MAC test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Seeded Keep MAC test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 \
		--enet-mac-seed=42 --enet-mac-seed-keep-bytes=3 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_trunc:
	$(PRINTF) "%s" "[tcprewrite] Truncate test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Truncate test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -F trunc -i $(TEST_PCAP) -o test.$@1 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_pad:
	$(PRINTF) "%s" "[tcprewrite] Pad test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Pad test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -F pad -i $(TEST_PCAP) -o test.$@1 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_seed:
	$(PRINTF) "%s" "[tcprewrite] Seed IP test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Seed IP test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -s 55 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_layer2:
	$(PRINTF) "%s" "[tcprewrite] Layer2 test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Layer2 test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) --dlt=user --user-dlink=00,50,da,5d,46,55,0,7,eb,30,a4,c3,08,0 \
		-i $(TEST_PCAP) -o test.$@1 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_config:
	$(PRINTF) "%s" "[tcprewrite] Config/VLAN Add test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Config/VLAN Add test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) --load-opts config  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_skip:
	$(PRINTF) "%s" "[tcprewrite] Skip bcast test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Skip bcast test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 \
	    --skipbroadcast --skipl2broadcast --skip-soft-errors --seed 55 \
		--enet-dmac=00:12:13:14:15:16,00:22:33:44:55:66 \
		--enet-smac=00:22:33:44:55:66,00:12:13:14:15:16  -c $(srcdir)/test.auto_router  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_dltuser:
	$(PRINTF) "%s" "[tcprewrite] DLT User test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] DLT User test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --dlt=user \
		--user-dlink=0x0f,0x00,0x08,0x00 --user-dlt=104  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_dlthdlc:
	$(PRINTF) "%s" "[tcprewrite] DLT Cisco HDLC test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] DLT Cisco HDLC test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --dlt=hdlc \
		--hdlc-control=0 --hdlc-address=0x0F  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_dltraw:
	$(PRINTF) "%s" "[tcprewrite] DLT Raw test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] DLT Raw test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --dlt=raw \
		--skip-soft-errors  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

if HAVE_PCAP_NANO
rewrite_nanosec:
	$(PRINTF) "%s" "[tcprewrite] Nanosecond timestamp test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Nanosecond timestamp test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(srcdir)/test_nano.pcap -o test.$@1  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi
else
rewrite_nanosec:
	$(PRINTF) "%s" "[tcprewrite] Nanosecond timestamp test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Nanosecond timestamp test: libpcap lacks nanosecond support" >> test.log
	$(PRINTF) "\t%s\n" "SKIPPED"
endif

rewrite_vlan802.1ad:
	$(PRINTF) "%s" "[tcprewrite] VLAN 802.1ad test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] VLAN 802.1ad test: " >> test.log
	$(TCPREWRITE) -i $(TEST_PCAP) -o test.$@1 \
		--enet-vlan=add --enet-vlan-tag=42 --enet-vlan-cfi=1 \
		--enet-vlan-pri=2 --enet-vlan-proto=802.1ad
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_vlandel:
	$(PRINTF) "%s" "[tcprewrite] VLAN Delete test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] VLAN Delete test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(srcdir)/test.rewrite_config -o test.$@1 \
		--enet-vlan=del  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_efcs:
	$(PRINTF) "%s" "[tcprewrite] Remove EFCS: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Remove EFCS: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --efcs >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_1ttl:
	$(PRINTF) "%s" "[tcprewrite] Force TTL: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Force TTL: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --ttl=58  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_2ttl:
	$(PRINTF) "%s" "[tcprewrite] Increase TTL: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Increase TTL: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --ttl=+58  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_3ttl:
	$(PRINTF) "%s" "[tcprewrite] Reduce TTL: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Reduce TTL: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --ttl=-58  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_1ttl-hdrfix:
	$(PRINTF) "%s" "[tcprewrite] Force TTL with header fix: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Force TTL header fix: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --ttl=59 --fixhdrlen >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_2ttl-hdrfix:
	$(PRINTF) "%s" "[tcprewrite] Increase TTL with header fix:"
	$(PRINTF) "%s\n" "*** [tcprewrite] Increase TTL with header fix: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --ttl=+59 --fixhdrlen  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_3ttl-hdrfix:
	$(PRINTF) "%s" "[tcprewrite] Reduce TTL with header fix: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Reduce TTL with header fix: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --ttl=-59 --fixhdrlen  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_tos:
	$(PRINTF) "%s" "[tcprewrite] TOS test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] TOS test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --tos=50  >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

# --seed on an ARP request converted from Linux SLL (16-byte L2) to Ethernet
# (14-byte L2): both IPs must change, and the ARP header and both MACs must not.
# Checked field by field because --seed's output depends on host byte order.
rewrite_seed_arp_dlt:
	$(PRINTF) "%s" "[tcprewrite] ARP seed with DLT conversion test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] ARP seed with DLT conversion test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(srcdir)/test_arp_sll.pcap -o test.$@1 --dlt=enet \
	    --enet-dmac=00:01:02:03:04:05 --enet-smac=00:01:02:03:04:06 --seed=7 >> test.log 2>&1
	f=test.$@1; \
	hdr=`od -An -tx1 -j 54 -N 8 $$f | tr -d ' \n'`; smac=`od -An -tx1 -j 62 -N 6 $$f | tr -d ' \n'`; \
	sip=`od -An -tx1 -j 68 -N 4 $$f | tr -d ' \n'`; tmac=`od -An -tx1 -j 72 -N 6 $$f | tr -d ' \n'`; \
	tip=`od -An -tx1 -j 78 -N 4 $$f | tr -d ' \n'`; \
	$(PRINTF) "%s\n" "arp=$$hdr smac=$$smac sip=$$sip tmac=$$tmac tip=$$tip" >> test.log; \
	if [ "$$hdr" = 0001080006040001 ] && [ "$$smac" = 0011223344aa ] && [ "$$tmac" = aabbccddeeff ] && \
	   [ "$$sip" != 0a010101 ] && [ "$$tip" != 0a020202 ]; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; false; \
	fi

# a cache for 20 packets used on a 259-packet capture must be refused, not
# read past (signals are exit 128-254)
rewrite_cache_short:
	$(PRINTF) "%s" "[tcprewrite] Short cache file test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Short cache file test: " >> test.log
	$(TCPPREP) -a client -i $(FRAGROUTE_PCAP) -o test.$@.cache >> test.log 2>&1
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 -c test.$@.cache >> test.log 2>&1; \
	status=$$?; \
	if [ $$status -ne 0 ] && [ $$status -lt 128 -o $$status -eq 255 ]; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; false; \
	fi

# a MAX_SNAPLEN frame given a 255-byte user L2 header would exceed MAXPACKET;
# it must be refused (written unedited), not overflow the buffer
rewrite_dltuser_maxsnaplen:
	$(PRINTF) "%s" "[tcprewrite] DLT User max length test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] DLT User max length test: " >> test.log
	dlink=aa; i=1; while [ $$i -lt 255 ]; do dlink="$$dlink,aa"; i=`expr $$i + 1`; done; \
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(srcdir)/test_maxsnaplen_raw.pcap -o test.$@1 \
		--dlt=user --user-dlt=147 --user-dlink=$$dlink >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; else $(PRINTF) "\t\t%s\n" "FAILED"; false; fi

rewrite_mtutrunc:
	$(PRINTF) "%s" "[tcprewrite] MTU Truncate test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] MTU Truncate test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1  --mtu-trunc --mtu=300 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_l7fuzzing:
	$(PRINTF) "%s" "[tcprewrite] L7 fuzzing test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] L7 fuzzing test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --fuzz-seed=42 --fuzz-factor=2 >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_fixcsum:
	$(PRINTF) "%s" "[tcprewrite] Fix checksum test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Fix checksum test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --fixcsum >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_fixlen_pad:
	$(PRINTF) "%s" "[tcprewrite] Fix length and pad test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Fix length and pad test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --fixlen=pad >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_fixlen_trunc:
	$(PRINTF) "%s" "[tcprewrite] Fix length and truncate test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Fix length and truncate test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --fixlen=trunc >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

rewrite_fixlen_del:
	$(PRINTF) "%s" "[tcprewrite] Fix length and delete test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Fix length and delete test: " >> test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i $(TEST_PCAP) -o test.$@1 --fixlen=del >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

replay_pps:
	$(PRINTF) "%s" "[tcpreplay] Packets/sec test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Packets/sec test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -p 25 $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

replay_rate:
	$(PRINTF) "%s" "[tcpreplay] Mbps test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Mbps test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -M 25.0 $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t\t%s\n" "FAILED"; false; fi

replay_multi:
	$(PRINTF) "%s" "[tcpreplay] Multiplier test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Multiplier test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -x 25.0 $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

replay_pps_multi:
	$(PRINTF) "%s" "[tcpreplay] Packets/sec Multiplier test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Packets/sec Multiplier test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -p 100 --pps-multi=5 $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t%s\n" "OK"; else $(PRINTF) "\t%s\n" "FAILED"; false; fi

replay_top:
	$(PRINTF) "%s" "[tcpreplay] Topspeed test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Topspeed test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -t $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

replay_precache:
	$(PRINTF) "%s" "[tcpreplay] Precache test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Precache test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) --preload-pcap $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

datadump_mode:
	$(PRINTF) "%s" "[tcpreplay] Data dump test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Data dump mode test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -D -i $(nic1) -I $(nic2) -w primary.data -W secondary.data -c $(srcdir)/test.cidr -R $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

replay_config:
	$(PRINTF) "%s" "[tcpreplay] Config file/VLAN add test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Config file/VLAN add test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) --load-opts=config $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; else $(PRINTF) "\t\t%s\n" "FAILED"; false; fi

replay_dualfile:
	$(PRINTF) "%s" "[tcpreplay] Dual file test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Dual file test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -I $(nic2) --dualfile $(TEST_PCAP) $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t\t%s\n" "OK"; else $(PRINTF) "\t\t\t%s\n" "FAILED"; false; fi

replay_maxsleep:
	$(PRINTF) "%s" "[tcpreplay] Maximum sleep test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Maximum sleep test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) --maxsleep=20 $(TEST_PCAP) $(TEST_PCAP) >> test.log 2>&1; \
	if [ $$? -eq 0 ] ; then $(PRINTF) "\t\t%s\n" "OK"; else $(PRINTF) "\t\t%s\n" "FAILED"; false; fi

# the following write to a file
replay_include:
	$(PRINTF) "%s" "[tcpreplay] Include rule test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Include rule test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -w test.$@1 -t --include=7,11,20-23,174- $(TEST_PCAP) >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

replay_exclude:
	$(PRINTF) "%s" "[tcpreplay] Exclude rule test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Exclude rule test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -w test.$@1 -t --exclude=23-,11-20,2,3 $(TEST_PCAP) >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

replay_unique_ip:
	$(PRINTF) "%s" "[tcpreplay] Unique IP test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Unique IP test: " >> test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -w test.$@1 -t --unique-ip --loop=2 $(TEST_PCAP) >> test.log 2>&1
	if diff $(srcdir)/test$(VARIANT).$@ test.$@1 >> test.log 2>&1; then \
	    $(PRINTF) "\t\t\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t\t\t%s\n" "FAILED"; od -Ax -tx1 -v test.$@1 >> test.log; false; \
	fi

if COMPILE_FRAGROUTE
# fragroute embeds random IP IDs and fills chaff packets with random bytes, so
# its output is not reproducible run to run and there is no golden file to diff
# against. These check exit status instead, and specifically distinguish a
# clean rejection from a crash: tcprewrite exits 255 on a fatal error, while a
# status of 128..254 means the shell saw it die from a signal (SIGSEGV is 139,
# SIGABRT 134), which is what the memory-safety bugs in these modules looked
# like.
#
# Note what fragroute_valid can and cannot catch. In an ordinary build it only
# proves that valid rules still parse, run and produce output - the one-byte
# heap overflows fixed in ip_chaff and tcp_chaff do not crash an unsanitized
# binary, so this target passes against the buggy code. Configure with
# --enable-asan to make those regressions fail here; the other two targets
# catch their bugs (SIGSEGV) in a plain build.

fragroute_valid:
	$(PRINTF) "%s" "[tcprewrite] Fragroute valid rules test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Fragroute valid rules test: " >> test.log
	rc=0; \
	for rule in "ip_frag 8" "ip_frag 16 old" "ip_frag 8 new" "tcp_seg 8" \
		    "tcp_seg 16 old" "ip_chaff dup" "ip_chaff opt" "tcp_chaff cksum" \
		    "tcp_chaff null" "dup random 100" "order random" "ip_ttl 5"; do \
	    $(PRINTF) "%s\n" "$$rule" > test.$@.rules; \
	    $(PRINTF) "%s\n" "--- $$rule" >> test.log; \
	    $(TCPREWRITE) $(ENABLE_DEBUG) --fragroute=test.$@.rules \
		-i $(FRAGROUTE_PCAP) -o test.$@1 >> test.log 2>&1; \
	    status=$$?; \
	    if [ $$status -ne 0 ]; then \
		$(PRINTF) "%s\n" "ERROR: '$$rule' exited $$status" >> test.log; rc=1; \
	    elif [ ! -s test.$@1 ]; then \
		$(PRINTF) "%s\n" "ERROR: '$$rule' produced no output" >> test.log; rc=1; \
	    fi; \
	done; \
	if [ $$rc -eq 0 ]; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; false; \
	fi

# A negative fragment/segment size used to pass validation (-8 % 8 == 0) and
# reach memcpy() as a huge size_t. It must be refused at parse time, and the
# refusal must not be a crash.
fragroute_negsize:
	$(PRINTF) "%s" "[tcprewrite] Fragroute negative size test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Fragroute negative size test: " >> test.log
	rc=0; \
	for rule in "ip_frag -8" "ip_frag -16" "ip_frag 0" "tcp_seg -8" "tcp_seg 0"; do \
	    $(PRINTF) "%s\n" "$$rule" > test.$@.rules; \
	    $(PRINTF) "%s\n" "--- $$rule" >> test.log; \
	    $(TCPREWRITE) $(ENABLE_DEBUG) --fragroute=test.$@.rules \
		-i $(FRAGROUTE_PCAP) -o test.$@1 > test.$@.out 2>&1; \
	    status=$$?; \
	    cat test.$@.out >> test.log; \
	    if [ $$status -eq 0 ]; then \
		$(PRINTF) "%s\n" "ERROR: '$$rule' was accepted" >> test.log; rc=1; \
	    elif [ $$status -ge 128 ] && [ $$status -le 254 ]; then \
		$(PRINTF) "%s\n" "ERROR: '$$rule' died from signal $$(($$status - 128))" >> test.log; rc=1; \
	    elif ! grep -q "must be between 1 and 65535" test.$@.out; then \
		$(PRINTF) "%s\n" "ERROR: '$$rule' failed, but not by rejecting the size" >> test.log; rc=1; \
	    fi; \
	done; \
	if [ $$rc -eq 0 ]; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; false; \
	fi

# Rules files that are degenerate but not invalid: many directives used to
# overflow the caller's error buffer, and a file with no rules at all used to
# index buf[strlen(buf) - 4]. Both must parse and run normally.
fragroute_badrules:
	$(PRINTF) "%s" "[tcprewrite] Fragroute degenerate rules test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Fragroute degenerate rules test: " >> test.log
	rc=0; \
	: > test.$@.empty.rules; \
	$(PRINTF) "%s\n" "# nothing but a comment" > test.$@.comment.rules; \
	awk 'BEGIN { for (i = 0; i < 300; i++) print "print" }' > test.$@.many.rules; \
	for f in empty comment many; do \
	    $(PRINTF) "%s\n" "--- $$f rules" >> test.log; \
	    $(TCPREWRITE) $(ENABLE_DEBUG) --fragroute=test.$@.$$f.rules \
		-i $(FRAGROUTE_PCAP) -o test.$@1 >> test.log 2>&1; \
	    status=$$?; \
	    if [ $$status -ne 0 ]; then \
		$(PRINTF) "%s\n" "ERROR: $$f rules exited $$status" >> test.log; rc=1; \
	    fi; \
	done; \
	if [ $$rc -eq 0 ]; then \
	    $(PRINTF) "\t%s\n" "OK"; \
	else \
	    $(PRINTF) "\t%s\n" "FAILED"; false; \
	fi
endif

clean:
	rm -f *1 test.log core* *~ primary.data secondary.data *.rules *.out

distclean: clean
	rm -f Makefile Makefile.in config

maintainer-clean: distclean

# $Id$
MAKEFLAGS=-s -k
PRINTF = @PRINTF@
HOST = @host@
TARGET = @target@
BUILD = @build@
nic1 = @nic1@
nic2 = @nic2@
ENABLE_DEBUG = @debug_flag@
TCPPREP=../src/tcpprep --no-arg-comment
TCPREPLAY=../src/tcpreplay
TCPREWRITE=../src/tcprewrite
TCPBRIDGE=../src/tcpbridge

EXTRA_DIST = test.pcap test.auto_bridge test.auto_client test.auto_router \
		test.auto_server test.cidr test.comment test.port test.mac \
		test.prep_config test.primary test.regex test.secondary \
		test.rewrite_seed test.rewrite_portmap test.rewrite_endpoint \
		test.rewrite_pnat test.rewrite_pad test.rewrite_trunc \
		test.rewrite_mac test.rewrite_layer2 test.rewrite_config

test: all
all: clearlog check tcpprep tcpreplay tcprewrite

clearlog:
	-rm test.log

check:
	$(PRINTF) "%s\n" "NOTICE: Tests must be run as root"
	$(PRINTF) "%s\n" "Sending traffic on '$(nic1)' and '$(nic2)'"

# the cache files to be used as the standard; be sure to do a cvs commit
# afterwords!
standard:
	$(TCPPREP) -i test.pcap -o test.auto_router -a router
	$(TCPPREP) -i test.pcap -o test.auto_bridge -a bridge
	$(TCPPREP) -i test.pcap -o test.auto_client -a client
	$(TCPPREP) -i test.pcap -o test.auto_server -a server
	$(TCPPREP) --load-opts config -o test.prep_config
	$(TCPPREP) -i test.pcap -o test.port -p
	$(TCPPREP) -i test.pcap -o test.mac -e 00:02:3b:00:3d:ce
	$(TCPPREP) -i test.pcap -o test.cidr -c '216.27.178.0/24'
	$(TCPPREP) -i test.pcap -o test.regex -r '216.27.178.*'
	$(TCPPREP) -i test.pcap -o test.comment -C "This is a comment" -p
	$(TCPREWRITE) -i test.pcap -o test.rewrite_seed -s 55
	$(TCPREWRITE) -i test.pcap -o test.rewrite_portmap -r 80:8080
	$(TCPREWRITE) -i test.pcap -o test.rewrite_endpoint -e 10.10.0.1:10.10.0.2
	$(TCPREWRITE) -i test.pcap -o test.rewrite_pnat -N 216.27.178.0/24:172.16.0.0/24
	$(TCPREWRITE) -i test.pcap -o test.rewrite_pad -F pad
	$(TCPREWRITE) -i test.pcap -o test.rewrite_trunc -F trunc
	$(TCPREWRITE) -i test.pcap -o test.rewrite_mac \
		-D 00:12:13:14:15:16,00:22:33:44:55:66 \
		-S 00:22:33:44:55:66,00:12:13:14:15:16  -c test.auto_router
	$(TCPREWRITE) -i test.pcap -o test.rewrite_layer2 \
		 -l 00,50,da,5d,46,55,0,7,eb,30,a4,c3,08,0
	$(TCPREWRITE) -i test.pcap -o test.rewrite_config --vlan=add --vlan-tag=45 \
		--vlan-cfi=1 --vlan-pri=5


tcpprep: auto_router auto_bridge auto_client auto_server cidr regex port mac comment print_info print_comment prep_config
tcprewrite: rewrite_portmap rewrite_endpoint rewrite_pnat rewrite_trunc rewrite_pad rewrite_seed rewrite_mac rewrite_layer2 rewrite_config
tcpreplay: replay_basic replay_cache replay_pps replay_rate replay_top replay_config replay_multi

prep_config:
	$(PRINTF) "%s" "[tcpprep] Config mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Config mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) --load-opts=config -o test.$@1 2>>test.log
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

auto_router:
	$(PRINTF) "%s" "[tcpprep] Auto/Router mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Auto/Router mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i test.pcap -o test.$@1 -a router 2>>test.log
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t%s\n" "FAILED"; else $(PRINTF) "\t%s\n" "OK"; fi

auto_bridge:
	$(PRINTF) "%s" "[tcpprep] Auto/Bridge mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Auto/Bridge mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i test.pcap -o test.$@1 -a bridge 2>>test.log
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t%s\n" "FAILED"; else $(PRINTF) "\t%s\n" "OK"; fi

auto_client:
	$(PRINTF) "%s" "[tcpprep] Auto/Client mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Auto/Client mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i test.pcap -o test.$@1 -a client 2>>test.log
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t%s\n" "FAILED"; else $(PRINTF) "\t%s\n" "OK"; fi

auto_server:
	$(PRINTF) "%s" "[tcpprep] Auto/Server mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Auto/Server mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i test.pcap -o test.$@1 -a server 2>>test.log
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t%s\n" "FAILED"; else $(PRINTF) "\t%s\n" "OK"; fi

regex:
	$(PRINTF) "%s" "[tcpprep] Regex mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Regex mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i test.pcap -o test.$@1 -r '216.27.178.*' 2>>test.log
	diff  test.$@ test.$@1 >>test.log 2>&1 
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

cidr:
	$(PRINTF) "%s" "[tcpprep] CIDR mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] CIDR mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i test.pcap -o test.$@1 -c '216.27.178.0/24' 2>>test.log
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

port:
	$(PRINTF) "%s" "[tcpprep] Port mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Port mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i test.pcap -o test.$@1 -p 2>>test.log
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

mac:
	$(PRINTF) "%s" "[tcpprep] MAC mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] MAC mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i test.pcap -o test.$@1 -e 00:02:3b:00:3d:ce 2>>test.log
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

comment:
	$(PRINTF) "%s" "[tcpprep] Comment mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Comment mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -i test.pcap -o test.$@1 -C "This is a comment" -p 2>>test.log
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

print_comment:
	$(PRINTF) "%s" "[tcpprep] Print comment mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Print comment mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -P test.comment >test.$@1 2>>test.log
	if [ $? ] ; then $(PRINTF) "\t%s\n" "FAILED"; else $(PRINTF) "\t%s\n" "OK"; fi

print_info:
	$(PRINTF) "%s" "[tcpprep] Print info mode test: "
	$(PRINTF) "%s\n" "*** [tcpprep] Print info mode test: " >>test.log
	$(TCPPREP) $(ENABLE_DEBUG) -I test.comment >test.$@1 2>>test.log
	if [ $? ] ; then $(PRINTF) "\t%s\n" "FAILED"; else $(PRINTF) "\t%s\n" "OK"; fi

replay_basic:
	$(PRINTF) "%s" "[tcpreplay] Basic test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Basic test: " >>test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -t test.pcap >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

replay_cache:
	$(PRINTF) "%s" "[tcpreplay] Cache test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Cache test: " >>test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -c test.cidr -i $(nic1) -I $(nic2) -t test.pcap >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

rewrite_portmap:
	$(PRINTF) "%s" "[tcprewrite] Portmap test: "
	$(PRINTF) "%s\n" "[tcprewrite] Portmap test: " >>test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i test.pcap -o test.rewrite_portmap1 -r 80:8080 >>test.log 2>&1
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi
	
rewrite_endpoint:
	$(PRINTF) "%s" "[tcprewrite] Endpoint test: "
	$(PRINTF) "%s\n" "[tcprewrite] Endpoint test: " >>test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i test.pcap -o test.rewrite_endpoint1 -e 10.10.0.1:10.10.0.2
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi
	
rewrite_pnat:
	$(PRINTF) "%s" "[tcprewrite] Pseudo NAT test: "
	$(PRINTF) "%s\n" "[tcprewrite] Pseudo NAT test: " >>test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i test.pcap -o test.rewrite_pnat1 -N 216.27.178.0/24:172.16.0.0/24
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi
	
rewrite_mac:
	$(PRINTF) "%s" "[tcprewrite] Src/Dst MAC test: "
	$(PRINTF) "%s\n" "[tcprewrite] Src/Dst MAC test: " >>test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i test.pcap -o test.rewrite_mac1 \
		-D 00:12:13:14:15:16,00:22:33:44:55:66 \
		-S 00:22:33:44:55:66,00:12:13:14:15:16  -c test.auto_router
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

rewrite_trunc:
	$(PRINTF) "%s" "[tcprewrite] Truncate test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Truncate test: " >>test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -F trunc -i test.pcap -o test.rewrite_trunc1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

rewrite_pad:
	$(PRINTF) "%s" "[tcprewrite] Pad test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Pad test: " >>test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -F pad -i test.pcap -o test.rewrite_pad1 >>test.log 2>&1
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t\t%s\n" "OK"; fi

rewrite_seed:
	$(PRINTF) "%s" "[tcprewrite] Seed IP test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Seed IP test: " >>test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -i test.pcap -o test.rewrite_seed1 -s 55 >>test.log 2>&1
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

rewrite_layer2:
	$(PRINTF) "%s" "[tcprewrite] Layer2 test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Layer2 test: " >>test.log
	$(TCPREWRITE) $(ENABLE_DEBUG) -l 00,50,da,5d,46,55,0,7,eb,30,a4,c3,08,0 \
		-i test.pcap -o test.rewrite_layer21 >>test.log 2>&1
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi
	
rewrite_config:
	$(PRINTF) "%s" "[tcprewrite] Config test: "
	$(PRINTF) "%s\n" "*** [tcprewrite] Config test: " >>test.log
	$(TCPREWRITE) -i test.pcap -o test.rewrite_config1 --load-opts config
	diff test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

replay_pps:
	$(PRINTF) "%s" "[tcpreplay] Packets/sec test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Packets/sec test: " >>test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -p 25 test.pcap >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

replay_rate:
	$(PRINTF) "%s" "[tcpreplay] Mbps test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Mbps test: " >>test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -M 25.0 test.pcap >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t\t%s\n" "OK"; fi

replay_multi:
	$(PRINTF) "%s" "[tcpreplay] Multiplier test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Multiplier test: " >>test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -m 25.0 test.pcap >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

replay_top:
	$(PRINTF) "%s" "[tcpreplay] Topspeed test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Topspeed test: " >>test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -i $(nic1) -t test.pcap >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t\t%s\n" "FAILED"; else $(PRINTF) "\t\t%s\n" "OK"; fi

datadump_mode:
	$(PRINTF) "%s" "[tcpreplay] Data dump mode test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Data dump mode test: " >>test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) -D -i $(nic1) -j $(nic2) -w primary.data -W secondary.data -c test.cidr -R test.pcap >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t%s\n" "FAILED"; else $(PRINTF) "\t%s\n" "OK"; fi

replay_config:
	$(PRINTF) "%s" "[tcpreplay] Config file (VLAN Add) mode test: "
	$(PRINTF) "%s\n" "*** [tcpreplay] Config file (VLAN Add) mode test: " >>test.log
	$(TCPREPLAY) $(ENABLE_DEBUG) --load-opts=config test.pcap >>test.log 2>&1
	if [ $? ] ; then $(PRINTF) "\t%s\n" "FAILED"; else $(PRINTF) "\t%s\n" "OK"; fi

clean:
	rm -f *1 test.log core* *~ primary.data secondary.data

distclean: clean
	rm -f Makefile config

maintainer-clean: distclean

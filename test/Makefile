MAKEFLAGS=-s -k

# these need to be dynamic based on OS
nic1=eth0
nic2=eth0

test: all
all: check tcpprep tcpreplay

check:
	echo "NOTICE: Tests must be run as root"
	echo "Sending traffic on $(nic1) and $(nic2)"
	


tcpprep: auto_router auto_bridge cidr regex
tcpreplay: replay_basic replay_cache replay_cidr replay_trunc replay_pad replay_rand replay_include replay_exclude

auto_router:
	echo -n "[tcpprep] Auto/Router mode test: "
	../tcpprep -i test.pcap -o test.$@1 -a -n router -N client
	diff -q test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then echo "\tFAILED"; else echo -e "\tOK"; fi

auto_bridge:
	echo -n "[tcpprep] Auto/Bridge mode test: "
	../tcpprep -i test.pcap -o test.$@1 -a -n bridge -N client
	diff -q test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then echo "\tFAILED"; else echo -e "\tOK"; fi

regex:
	echo -n "[tcpprep] Regex mode test: "
	../tcpprep -i test.pcap -o test.$@1 -r '216.27.178.*' -N client
	diff -q test.$@ test.$@1 >>test.log 2>&1 
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

cidr:
	echo -n "[tcpprep] CIDR mode test: "
	../tcpprep -i test.pcap -o test.$@1 -c '216.27.178.0/24' -N client
	diff -q test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_basic:
	echo -n "[tcpreplay] Basic test: "
	../tcpreplay -i $(nic1) test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_cache:
	echo -n "[tcpreplay] Cache test: "
	../tcpreplay -c test.cidr -i $(nic1) -j $(nic2) test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_cidr:
	echo -n "[tcpreplay] CIDR test: "
	../tcpreplay -C 216.27.178.0/24 -i $(nic1) -j $(nic2) test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\t\tFAILED"; else echo -e "\t\t\tOK"; fi

replay_trunc:
	echo -n "[tcpreplay] Trunc test: "
	../tcpreplay -i $(nic1) -u trunc test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_pad:
	echo -n "[tcpreplay] Pad test: "
	../tcpreplay -i $(nic1) -u pad test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\t\tFAILED"; else echo -e "\t\t\tOK"; fi

replay_rand:
	echo -n "[tcpreplay] Random IP test: "
	../tcpreplay -i $(nic1) -s 666 test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_include:
	echo -n "[tcpreplay] Include only test: "
	../tcpreplay -i $(nic1) -x P:1,5,7-53,88,93-100 test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_exclude:
	echo -n "[tcpreplay] Exclude test: "
	../tcpreplay -i $(nic1) -X P:1,5,7-53,88,93-100 test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

clean: distclean

distclean:
	rm *1 test.log core

MAKEFLAGS=-s -k

# these need to be dynamic based on OS
nic1=eth0
nic2=eth0

test: all
all: check tcpprep tcpreplay

check:
	echo "NOTICE: Tests must be run as root"
	echo "Sending traffic on $(nic1) and $(nic2)"
	
# the cache files to be used as the standard; be sure to do a cvs commit
# afterwords!
standard:
	../tcpprep -i test.pcap -o test.auto_router -a -n router -N client
	../tcpprep -i test.pcap -o test.auto_bridge -a -n bridge -N client
	../tcpprep -i test.pcap -o test.cidr -c '216.27.178.0/24' -N client
	../tcpprep -i test.pcap -o test.regex -r '216.27.178.*' -N client

	
tcpprep: auto_router auto_bridge cidr regex
tcpreplay: replay_basic replay_cache replay_cidr replay_trunc replay_pad replay_rand replay_include replay_exclude

auto_router:
	echo -n "[tcpprep] Auto/Router mode test: "
	echo "[tcpprep] Auto/Router mode test: " >>test.log
	../tcpprep -i test.pcap -o test.$@1 -a -n router -N client
	diff -q test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then echo "\tFAILED"; else echo -e "\tOK"; fi

auto_bridge:
	echo -n "[tcpprep] Auto/Bridge mode test: "
	echo "[tcpprep] Auto/Bridge mode test: " >>test.log
	../tcpprep -i test.pcap -o test.$@1 -a -n bridge -N client
	diff -q test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then echo "\tFAILED"; else echo -e "\tOK"; fi

regex:
	echo -n "[tcpprep] Regex mode test: "
	echo "[tcpprep] Regex mode test: " >>test.log
	../tcpprep -i test.pcap -o test.$@1 -r '216.27.178.*' -N client
	diff -q test.$@ test.$@1 >>test.log 2>&1 
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

cidr:
	echo -n "[tcpprep] CIDR mode test: "
	echo "[tcpprep] CIDR mode test: " >>test.log
	../tcpprep -i test.pcap -o test.$@1 -c '216.27.178.0/24' -N client
	diff -q test.$@ test.$@1 >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_basic:
	echo -n "[tcpreplay] Basic test: "
	echo "[tcpreplay] Basic test: " >>test.log
	../tcpreplay -i $(nic1) test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_cache:
	echo -n "[tcpreplay] Cache test: "
	echo "[tcpreplay] Cache test: " >>test.log
	../tcpreplay -c test.cidr -i $(nic1) -j $(nic2) test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_cidr:
	echo -n "[tcpreplay] CIDR test: "
	echo "[tcpreplay] CIDR test: " >>test.log
	../tcpreplay -C 216.27.178.0/24 -i $(nic1) -j $(nic2) test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\t\tFAILED"; else echo -e "\t\t\tOK"; fi

replay_trunc:
	echo -n "[tcpreplay] Trunc test: "
	echo "[tcpreplay] Trunc test: " >>test.log
	../tcpreplay -i $(nic1) -u trunc test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_pad:
	echo -n "[tcpreplay] Pad test: "
	echo "[tcpreplay] Pad test: " >>test.log
	../tcpreplay -i $(nic1) -u pad test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\t\tFAILED"; else echo -e "\t\t\tOK"; fi

replay_rand:
	echo -n "[tcpreplay] Random IP test: "
	echo "[tcpreplay] Random IP test: " >>test.log
	../tcpreplay -i $(nic1) -s 666 test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_include:
	echo -n "[tcpreplay] Include only test: "
	echo "[tcpreplay] Include only test: " >>test.log
	../tcpreplay -i $(nic1) -x P:1,5,7-53,88,93-100 test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

replay_exclude:
	echo -n "[tcpreplay] Exclude test: "
	echo "[tcpreplay] Exclude test: " >>test.log
	../tcpreplay -i $(nic1) -X P:1,5,7-53,88,93-100 test.pcap >>test.log 2>&1
	if [ $? ] ; then echo "\t\tFAILED"; else echo -e "\t\tOK"; fi

clean: distclean

distclean:
	rm -f *1 test.log core

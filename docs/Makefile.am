MAKEFLAGS=-s

.PHONY: manpages

MAN2HTML = ../scripts/man2html

docs: manpages


web/man/tcpreplay.html:
	$(MAN2HTML) < ../src/tcpreplay.1 > web/man/tcpreplay.html

web/man/tcpprep.html:
	$(MAN2HTML) < ../src/tcpprep.1 > web/man/tcpprep.html

web/man/flowreplay.html:
	$(MAN2HTML) < ../src/flowreplay.1 > web/man/flowreplay.html

web/man/tcprewrite.html:
	$(MAN2HTML) < ../src/tcprewrite.1 > web/man/tcprewrite.html

web/man/tcpbridge.html:
	$(MAN2HTML) < ../src/tcpbridge.1 > web/man/tcpbridge.html

manpages: web/man/tcpreplay.html web/man/tcpprep.html web/man/flowreplay.html \
	web/man/tcprewrite.html web/man/tcpbridge.html 

postweb: webfiles manpages
	rsync -e ssh --exclude '/**/.svn/' --exclude '/**~' --exclude '*~' \
		-avz web/ aturner@voigner.synfin.net:/var/www-vhosts/tcpreplay/
	scp CHANGELOG TODO aturner@voigner.synfin.net:/var/www-vhosts/tcpreplay/


EXTRA_DIST = CHANGELOG CREDIT HACKING INSTALL LICENSE \
	web/man/tcpbridge.html web/man/tcpreplay.html  web/man/tcpprep.html \
	web/man/flowreplay.html web/man/tcprewrite.html

clean-docs: clean
	-rm -f web/man/*.html

maintainer-clean-local: clean-docs
	-rm -f web/man/*.html

MAINTAINERCLEANFILES = Makefile.in 


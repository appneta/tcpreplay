MAKEFLAGS=-s

.PHONY: manpages

MAN2HTML = ../scripts/man2html

docs: manpages


web/tcpreplay.html:
	$(MAN2HTML) < ../src/tcpreplay.1 > web/tcpreplay.html

web/tcpprep.html:
	$(MAN2HTML) < ../src/tcpprep.1 > web/tcpprep.html

web/flowreplay.html:
	$(MAN2HTML) < ../src/flowreplay.1 > web/flowreplay.html

web/tcprewrite.html:
	$(MAN2HTML) < ../src/tcprewrite.1 > web/tcprewrite.html

web/tcpbridge.html:
	$(MAN2HTML) < ../src/tcpbridge.1 > web/tcpbridge.html

manpages: web/tcpreplay.html web/tcpprep.html web/flowreplay.html \
	web/tcprewrite.html web/tcpbridge.html 

postweb: manpages
	rsync -e ssh --exclude '/**/.svn/' --exclude '/**~' --exclude '*~' \
		-avz web/ aturner@voigner.synfin.net:/var/www-vhosts/tcpreplay/
	scp CHANGELOG TODO aturner@voigner.synfin.net:/var/www-vhosts/tcpreplay/


EXTRA_DIST = CHANGELOG CREDIT HACKING INSTALL LICENSE 

clean-docs: clean
	-rm -f web/*.html

maintainer-clean-local: clean-docs
	-rm -f web/*.html

MAINTAINERCLEANFILES = Makefile.in 


MAKEFLAGS=-s

.PHONY: manpages

docs: clean-docs manpages

web/tcpreplay.html: $(srcdir)/tcpreplay.1.adoc
	mkdir -p web; @ASCIIDOCTOR@ --backend html5 --out-file web/tcpreplay.html $(srcdir)/tcpreplay.1.adoc

web/tcpprep.html: $(srcdir)/tcpprep.1.adoc
	mkdir -p web; @ASCIIDOCTOR@ --backend html5 --out-file web/tcpprep.html $(srcdir)/tcpprep.1.adoc

web/tcprewrite.html: $(srcdir)/tcprewrite.1.adoc $(srcdir)/tcpedit_options.adoc
	mkdir -p web; @ASCIIDOCTOR@ --backend html5 --out-file web/tcprewrite.html $(srcdir)/tcprewrite.1.adoc

web/tcpbridge.html: $(srcdir)/tcpbridge.1.adoc $(srcdir)/tcpedit_options.adoc
	mkdir -p web; @ASCIIDOCTOR@ --backend html5 --out-file web/tcpbridge.html $(srcdir)/tcpbridge.1.adoc

web/tcpreplay-edit.html: $(srcdir)/tcpreplay-edit.1.adoc $(srcdir)/tcpedit_options.adoc
	mkdir -p web; @ASCIIDOCTOR@ --backend html5 --out-file web/tcpreplay-edit.html $(srcdir)/tcpreplay-edit.1.adoc

web/tcpliveplay.html: $(srcdir)/tcpliveplay.1.adoc
	mkdir -p web; @ASCIIDOCTOR@ --backend html5 --out-file web/tcpliveplay.html $(srcdir)/tcpliveplay.1.adoc

web/tcpcapinfo.html: $(srcdir)/tcpcapinfo.1.adoc
	mkdir -p web; @ASCIIDOCTOR@ --backend html5 --out-file web/tcpcapinfo.html $(srcdir)/tcpcapinfo.1.adoc

manpages: web/tcpreplay.html web/tcpprep.html web/tcprewrite.html \
    web/tcpbridge.html web/tcpreplay-edit.html web/tcpliveplay.html \
    web/tcpcapinfo.html

postweb: manpages
	rsync -qe ssh --exclude '.git/' --exclude '/**/.git/' --exclude '/**~' \
	--exclude '*~' -avz web/ \
	aturner@malbec.synfin.net:/var/vhosts/tcpreplay/
	scp CHANGELOG TODO aturner@malbec.synfin.net:/var/vhosts/tcpreplay/


EXTRA_DIST = CHANGELOG CREDIT HACKING INSTALL LICENSE Win32Readme.txt \
    tcpcapinfo.1.adoc tcpliveplay.1.adoc tcpprep.1.adoc \
    tcprewrite.1.adoc tcpbridge.1.adoc tcpedit_options.adoc \
    tcpreplay.1.adoc tcpreplay-edit.1.adoc tcpreplay_options.adoc

clean-docs: clean
	-rm -f web/*.html

maintainer-clean-local: clean-docs
	-rm -f web/*.html

MAINTAINERCLEANFILES = Makefile.in 


MAKEFLAGS=-s

if HAVE_DOCTOOLS

PHONY: docs webfiles manpages

MAN2HTML=../scripts/man2html

L2HFLAGS = -show_section_numbers -no_footnode -split +1 -info 0 \
	-auto_navigation -local_icons -mkdir -html_version 4.0

webfiles: web/FAQ/FAQ.html web/manual/manual.html web/flowreplay/flowreplay.html

docs: FAQ.pdf flowreplay.pdf manual.pdf webfiles manpages

clean-docs: clean
	-rm -rf *.pdf web/manual web/FAQ web/flowreplay web/man/*

latex:
	@LYX@ -e latex FAQ.lyx
	@LYX@ -e latex manual.lyx
	@LYX@ -e latex flowreplay.lyx

FAQ.pdf: latex
	@TEXI2DVI@ FAQ.tex
	@DVIPDFM@ FAQ.dvi

web/FAQ/FAQ.html: latex
	@LATEX2HTML@ $(L2HFLAGS) -dir web/FAQ FAQ.tex

flowreplay.pdf: latex
	@FIG2DEV@ -L eps flowheader.fig flowheader.eps
	@TEXI2DVI@ flowreplay.tex
	@DVIPDFM@ flowreplay.dvi

web/flowreplay/flowreplay.html: latex
	@LATEX2HTML@ $(L2HFLAGS) -dir web/flowreplay flowreplay.tex

manual.pdf: latex
	@TEXI2DVI@ manual.tex
	@DVIPDFM@ manual.dvi

web/manual/manual.html: latex
	@LATEX2HTML@ $(L2HFLAGS) -dir web/manual manual.tex

web/man/tcpreplay.html:
	$(MAN2HTML) < ../src/tcpreplay.1 > web/man/tcpreplay.html

web/man/tcpprep.html:
	$(MAN2HTML) < ../src/tcpprep.1 > web/man/tcpprep.html

web/man/flowreplay.html:
	$(MAN2HTML) < ../src/flowreplay.1 > web/man/flowreplay.html

web/man/tcprewrite.html:
	$(MAN2HTML) < ../src/tcprewrite.1 > web/man/tcprewrite.html

manpages: web/man/tcpreplay.html web/man/tcpprep.html web/man/flowreplay.html \
	web/man/tcprewrite.html

postweb: webfiles manpages
	rsync -e ssh --exclude '/**/.svn/' --exclude '/**~' --exclude '*~' \
		-avz web/ aturner@tequila.synfin.net:/var/www-vhosts/tcpreplay/

postwebsf: webfiles manpages
	rsync -e ssh --exclude '/**/.svn/' --exclude '/**~' --exclude '*~' \
		-avz web/ aturner@shell.sf.net:htdocs/

endif

EXTRA_DIST = CHANGELOG CREDIT HACKING INSTALL LICENSE TODO \
	FAQ.lyx FAQ.pdf web/FAQ/FAQ.html web/FAQ \
	flowreplay.lyx flowreplay.pdf web/flowreplay/flowreplay.html web/flowreplay \
	flowheader.fig \
	manual.lyx manual.pdf web/manual/manual.html web/manual \
	web/index.html web/web.css \
	web/man/tcpreplay.html  web/man/tcpprep.html web/man/flowreplay.html \
	web/man web/man/tcprewrite.html web/tcpreplay-2-faq.html web/tcpreplay-2-faq.css

MOSTLYCLEANFILES = FAQ.aux FAQ.log FAQ.toc FAQ.dvi FAQ.tex \
	manual.aux manual.log manual.dvi manual.tex manual.toc \
	flowreplay.aux flowreplay.log flowheader.eps flowreplay.tex \
	flowreplay.log flowreplay.toc flowreplay.dvi \
	images.aux images.log images.pl images.tex img1.png labels.pl \
	*~ web/*~

maintainer-clean-local: clean-docs
	-rm -rf web/flowreplay web/FAQ web/manual web/man/*.html

MAINTAINERCLEANFILES = FAQ.pdf flowreplay.pdf manual.pdf Makefile.in 


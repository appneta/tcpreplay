MAKEFLAGS=-s

if HAVE_DOCTOOLS

MAN2HTML=../scripts/man2html

L2HFLAGS = -show_section_numbers -no_footnode -split +1 -info 0 \
	-auto_navigation -local_icons -mkdir -html_version 4.0

webfiles: web/FAQ/FAQ.html web/manual/manual.html web/flowreplay/flowreplay.html

docs: FAQ.pdf flowreplay.pdf manual.pdf webfiles manpages

clean-docs: clean
	-rm -rf *.pdf web/manual web/FAQ web/flowreplay web/man/*

FAQ.pdf:
	@LYX@ -e latex FAQ.lyx
	@TEXI2DVI@ FAQ.tex
	@DVIPDFM@ FAQ.dvi

web/FAQ/FAQ.html: FAQ.pdf
	@LATEX2HTML@ $(L2HFLAGS) -dir web/FAQ FAQ.tex

flowreplay.pdf: 
	@FIG2DEV@ -L eps flowheader.fig flowheader.eps
	@LYX@ -e latex flowreplay.lyx
	@TEXI2DVI@ flowreplay.tex
	@DVIPDFM@ flowreplay.dvi

web/flowreplay/flowreplay.html: flowreplay.pdf
	@LATEX2HTML@ $(L2HFLAGS) -dir web/flowreplay flowreplay.tex

manual.pdf:
	@LYX@ -e latex manual.lyx
	@TEXI2DVI@ manual.tex
	@DVIPDFM@ manual.dvi

web/manual/manual.html: manual.pdf
	@LATEX2HTML@ $(L2HFLAGS) -dir web/manual manual.tex

manpages:
	$(MAN2HTML) < ../man/tcpreplay.8 > web/man/tcpreplay.html
	$(MAN2HTML) < ../man/tcpprep.1 > web/man/tcpprep.html
#	$(MAN2HTML) < ../man/tcprewrite.1 > web/man/tcprewrite.html
	$(MAN2HTML) < ../man/flowreplay.1 > web/man/flowreplay.html

postweb: webfiles manpages
	rsync -e ssh -avz web/ aturner@synfin.net:/var/www-vhosts/tcpreplay/

endif

EXTRA_DIST = CHANGELOG CREDIT HACKING INSTALL LICENSE TODO \
	FAQ.lyx FAQ.pdf web/FAQ/* \
	flowreplay.lyx flowreplay.pdf web/flowreplay/* flowheader.fig \
	manual.lyx manual.pdf web/manual/* FAQ.lyx \
	web/index.html web/web.css web/man/tcpreplay.html web/man/tcprewrite.html \
	web/man/tcpprep.html web/man/tcprewrite.html

MOSTLYCLEANFILES = FAQ.aux FAQ.log FAQ.toc FAQ.dvi FAQ.tex \
	manual.aux manual.log manual.dvi manual.tex manual.toc \
	flowreplay.aux flowreplay.log flowheader.eps flowreplay.tex \
	flowreplay.log flowreplay.toc flowreplay.dvi \
	images.aux images.log images.pl images.tex img1.png labels.pl \
	*~ web/*~

maintainer-clean: clean-docs
	-rm -rf web/flowreplay web/FAQ web/manual web/man/*.html

MAINTAINERCLEANFILES = FAQ.pdf flowreplay.pdf manual.pdf Makefile.in 


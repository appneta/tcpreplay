MAKEFLAGS=-s

if HAVE_DOCTOOLS

L2HFLAGS = -show_section_numbers -no_footnode -split +1 -info 0 \
	-auto_navigation -local_icons -mkdir -html_version 4.0

docs: webdir FAQ.pdf web/FAQ/FAQ.html flowreplay.pdf \
	web/flowreplay/flowreplay.html manual.pdf web/manual/manual.html

webdir:
	if ! test -d web ; then mkdir web ; fi

clean-docs: clean
	-rm -rf *.pdf web/*

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

endif

EXTRA_DIST = CHANGELOG CREDIT HACKING INSTALL LICENSE TODO \
	FAQ.lyx FAQ.pdf web/FAQ/* \
	flowreplay.lyx flowreplay.pdf web/flowreplay/* flowheader.fig \
	manual.lyx manual.pdf web/manual/* FAQ.lyx

MOSTLYCLEANFILES = FAQ.aux FAQ.log FAQ.toc FAQ.dvi FAQ.tex \
	manual.aux manual.log manual.dvi manual.tex \
	flowreplay.aux flowreplay.log flowheader.eps flowreplay.tex \
	flowreplay.log flowreplay.toc flowreplay.dvi \
	images.aux images.log images.pl images.tex img1.png labels.pl \
	*~ WARNINGS

MAINTAINERCLEANFILES = FAQ.pdf flowreplay.pdf manual.pdf Makefile.in


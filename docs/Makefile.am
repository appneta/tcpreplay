MAKEFLAGS=-s

if HAVE_DOCTOOLS

docs: FAQ.pdf FAQ.html flowreplay.pdf flowreplay.html
#docs: all

#all: FAQ-pdf FAQ-html flowreplay-pdf flowreplay-html

clean-docs: clean
	-rm *.pdf *.css *.html

FAQ.pdf:
	@LYX@ -e latex FAQ.lyx
	@TEXI2DVI@ FAQ.tex
	@DVIPDFM@ FAQ.dvi

FAQ.html: FAQ.pdf
	@LATEX2HTML@ -nonavigation -no_subdir -split 0 \
		-show_section_numbers FAQ.tex


flowreplay.pdf: 
	@FIG2DEV@ -L eps flowheader.fig flowheader.eps
	@LYX@ -e latex flowreplay.lyx
	@TEXI2DVI@ flowreplay.tex
	@DVIPDFM@ flowreplay.dvi

flowreplay.html: flowreplay.pdf
	@LATEX2HTML@ -nonavigation -no_subdir -split 0 \
		-show_section_numbers flowreplay.tex

endif

EXTRA_DIST = CHANGELOG CREDIT HACKING INSTALL LICENSE TODO \
	     FAQ.pdf FAQ.html FAQ.css flowreplay.pdf flowreplay.html \
	     flowreplay.css FAQ.lyx flowreplay.lyx flowheader.fig

MOSTLYCLEANFILES = flowheader.eps FAQ.aux FAQ.log FAQ.toc FAQ.txt FAQ.dvi \
		   WARNINGS flowreplay.aux flowreplay.log \
		   flowreplay.txt images.aux images.log images.pl \
		   images.tex img1.png index.html labels.pl FAQ.dvi \
		   FAQ.ps FAQ.tex flowreplay.dvi flowreplay.ps \
		   flowreplay.tex *~

MAINTAINERCLEANFILES = FAQ.pdf FAQ.html FAQ.css flowreplay.pdf \
		       flowreplay.html flowreplay.css Makefile.in

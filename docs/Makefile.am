MAKEFLAGS=-s

#if HAVE_DOCTOOLS

all: FAQ.pdf FAQ.html flowreplay.pdf flowreplay.html

flowheader.eps: flowheader.fig
	@FIG2DEV@ -L eps $< $@

FAQ.tex:
	@LYX@ -e latex FAQ.lyx

flowreplay.tex:
	@LYX@ -e latex flowreplay.lyx


FAQ.dvi: FAQ.tex
	@TEXI2DVI@ FAQ.tex

flowreplay.dvi: flowreplay.tex flowheader.eps
	@TEXI2DVI@ flowreplay.tex


FAQ.pdf: FAQ.dvi
	@DVIPDFM@ FAQ.dvi

flowreplay.pdf: flowreplay.dvi
	@DVIPDFM@ flowreplay.dvi

FAQ.html: FAQ.tex
	@LATEX2HTML@ -nonavigation -no_subdir -split 0 \
		-show_section_numbers FAQ.tex

flowreplay.html: flowreplay.tex
	@LATEX2HTML@ -nonavigation -no_subdir -split 0 \
		-show_section_numbers flowreplay.tex
#endif


EXTRA_DIST = CHANGELOG CREDIT HACKING INSTALL LICENSE TODO 

MOSTLYCLEANFILES = flowheader.eps FAQ.aux FAQ.log FAQ.toc FAQ.txt \
		   WARNINGS flowreplay.aux flowreplay.log \
		   flowreplay.txt images.aux images.log images.pl \
		   images.tex img1.png index.html labels.pl FAQ.dvi \
		   FAQ.ps FAQ.tex flowreplay.dvi flowreplay.ps \
		   flowreplay.tex *~

MAINTAINERCLEANFILES = FAQ.pdf FAQ.html FAQ.css flowreplay.pdf \
		       flowreplay.html flowreplay.css

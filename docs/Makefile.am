MAKEFLAGS=-s

all: images pdf txt ps rmtemp html

images:
	@FIG2DEV@ -L eps flowheader.fig flowheader.eps

tex: images
	@LYX@ -e latex FAQ.lyx
	@LYX@ -e latex flowreplay.lyx

dvi: tex 
	@TEXI2DVI@ FAQ.tex
	@TEXI2DVI@ flowreplay.tex

html: tex 
	@LATEX2HTML@ -nonavigation -no_subdir -split 0 \
		-show_section_numbers FAQ.tex
	@LATEX2HTML@ -nonavigation -no_subdir -split 0 \
		-show_section_numbers flowreplay.tex


pdf: dvi
	@DVIPDFM@ FAQ.dvi
	@DVIPDFM@ flowreplay.dvi

txt:
	@LYX@ -e text FAQ.lyx
	@LYX@ -e text flowreplay.lyx

ps: dvi
	@DVIPS@ -o FAQ.ps FAQ.dvi
	@DVIPS@ -o flowreplay.ps flowreplay.dvi

rmtemp:
	rm -f labels.pl *.log *.toc WARNINGS *.aux index.html 

clean: rmtemp
	rm -f *~

distclean: rmtemp clean
	rm -f *.html *.pdf *.txt *.ps *.dvi *.tex  *.css images.pl img1.png *.eps

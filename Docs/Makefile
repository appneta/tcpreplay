MAKEFLAGS=-s

all: images pdf txt ps rmtemp html

images:
	fig2dev -L eps flowheader.fig flowheader.eps

tex: images
	lyx -e latex FAQ.lyx
	lyx -e latex flowreplay.lyx

dvi: tex 
	texi2dvi FAQ.tex
	texi2dvi flowreplay.tex

html: tex 
	latex2html -nonavigation -no_subdir -split 0 -show_section_numbers FAQ.tex
	latex2html -nonavigation -no_subdir -split 0 -show_section_numbers flowreplay.tex


pdf: dvi
	dvipdfm FAQ.dvi
	dvipdfm flowreplay.dvi

txt:
	lyx -e text FAQ.lyx
	lyx -e text flowreplay.lyx

ps: dvi
	dvips -o FAQ.ps FAQ.dvi
	dvips -o flowreplay.ps flowreplay.dvi

rmtemp:
	rm -f labels.pl *.log *.toc WARNINGS *.aux index.html 

clean: rmtemp
	rm -f *~

distclean: rmtemp clean
	rm -f *.html *.pdf *.txt *.ps *.dvi *.tex  *.css images.pl img1.png *.eps

MAKEFLAGS=-s

all: html pdf txt ps rmtemp

FAQ.tex:
	lyx -e latex FAQ.lyx

dvi: FAQ.tex 
	texi2dvi FAQ.tex

html: FAQ.tex 
	latex2html -nonavigation -no_subdir -split 0 -show_section_numbers FAQ.tex


pdf: FAQ.tex dvi
	dvipdf FAQ.dvi

txt:
	lyx -e text FAQ.lyx

ps: FAQ.tex dvi
	dvips -o FAQ.ps FAQ.dvi

rmtemp:
	rm -f labels.pl FAQ.log FAQ.toc WARNINGS FAQ.aux index.html FAQ.dvi FAQ.tex

clean: rmtemp
	rm -f FAQ.html FAQ.pdf FAQ.txt FAQ.ps FAQ.dvi FAQ.tex FAQ.css index.html

distclean: clean
	rm -f *~

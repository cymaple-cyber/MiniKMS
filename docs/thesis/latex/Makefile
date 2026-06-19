MAIN = main
TEX  = xelatex -interaction=nonstopmode -halt-on-error

$(MAIN).pdf: $(MAIN).tex preamble.tex chapters/*.tex
	$(TEX) $(MAIN).tex
	$(TEX) $(MAIN).tex

.PHONY: clean
clean:
	rm -f *.aux *.log *.toc *.lof *.lot *.out chapters/*.aux $(MAIN).pdf

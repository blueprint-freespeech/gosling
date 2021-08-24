.DEFAULT_GOAL := all

all: *.uml
	for file in $^; do plantuml -tsvg $${file}; done

clean: *.svg
	rm -f $^

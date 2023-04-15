.DEFAULT_GOAL := all

all: *.uml
	for file in $^; do plantuml -tsvg $${file}; done
	tidy -xml -indent --hide-comments 1 --write-back 1 *.svg

clean: *.svg
	rm -f $^

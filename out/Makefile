.DEFAULT_GOAL := all

all:
	mkdir -p Debug Release MinSizeRel RelWithDebInfo
	cd Debug && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug ../../source/
	cd Release && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release ../../source/
	cd MinSizeRel && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=MinSizeRel ../../source/
	cd RelWithDebInfo && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo ../../source/

clean:
	rm -rf Debug Release MinSizeRel RelWithDebInfo

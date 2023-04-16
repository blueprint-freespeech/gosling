
debug:
	mkdir -p out/debug
	cd out/debug && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug ../../source/
	@$(MAKE) -C out/debug

release:
	mkdir -p out/release
	cd out/release && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo ../../source/
	@$(MAKE) -C out/release

test:
	mkdir -p out/debug
	cd out/debug && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug ../../source/
	@$(MAKE) test -C out/debug

test-debug: test

test-release:
	mkdir -p out/release
	cd out/release && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo ../../source/
	@$(MAKE) test -C out/release

clean:
	rm -rf out

format:
	cd source/gosling && cargo fmt
	cd source/test/functional && clang-format -i *.cpp *.hpp
	cd source/test/unit && clang-format -i *.cpp *.hpp


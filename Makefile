.DEFAULT_GOAL := debug

# build debug target
debug:
	mkdir -p out/debug
	cd out/debug && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../../source/
	@$(MAKE) -C out/debug

# build release target
release:
	mkdir -p out/release
	cd out/release && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../../source/
	@$(MAKE) -C out/release

# build and run debug target tests
test:
	mkdir -p out/debug
	cd out/debug && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug ../../source/
	@$(MAKE) test -C out/debug

test-debug: test

# build and run release target tests
test-release:
	mkdir -p out/release
	cd out/release && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo ../../source/
	@$(MAKE) test -C out/release

# delete all build artifacts
clean:
	rm -rf out

# format Rust code with cargo fmt and C++ code with clang-format
format:
	cd source/gosling && cargo fmt
	cd source/test/functional && clang-format -i *.cpp *.hpp
	cd source/test/unit && clang-format -i *.cpp *.hpp

# line Rust code with cargo clippy and C++ code with clang-tidy
lint: debug
	cd source/gosling && cargo clippy
	jq 'del(.[]|select(.directory|test("Catch2/src$$")))' out/debug/compile_commands.json > out/debug/compile_commands.sans-catch2.json
	cppcheck\
		--enable=all\
		--inline-suppr\
		--suppress=missingIncludeSystem\
		--include=out/debug/gosling/crates/gosling-ffi/include/libgosling.h\
		--include=out/debug/gosling/crates/gosling-ffi/include/libgosling.hpp\
		--project=out/debug/compile_commands.sans-catch2.json\
		-isource/sans-catch2


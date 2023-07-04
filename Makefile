.DEFAULT_GOAL := debug

# delete all build artifacts
clean:
	rm -rf out

# cmake debug config
config-debug:
	mkdir -p out/debug
	cd out/debug && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../../source/

# cmake release config
config-release:
	mkdir -p out/release
	cd out/release && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../../source/
# build debug target
debug: config-debug
	@$(MAKE) -C out/debug

# build release target
release: config-release
	@$(MAKE) -C out/release

# build and run debug target tests
test-debug: config-debug
	# test each of our crates
	@$(MAKE) honk_rpc_cargo_test -C out/debug
	@$(MAKE) tor_interface_cargo_test -C out/debug
	@$(MAKE) gosling_cargo_test -C out/debug
	@$(MAKE) gosling_ffi_cargo_test -C out/debug
	@$(MAKE) gosling_functional_test -C out/debug
	@$(MAKE) gosling_unit_test -C out/debug

# build and run release target tests
test-release: config-release
	# test each of our crates
	@$(MAKE) honk_rpc_cargo_test -C out/release
	@$(MAKE) tor_interface_cargo_test -C out/release
	@$(MAKE) gosling_cargo_test -C out/release
	@$(MAKE) gosling_ffi_cargo_test -C out/release
	@$(MAKE) gosling_functional_test -C out/release
	@$(MAKE) gosling_unit_test -C out/release

# debug tests which do not require access to the tor network
test-offline-debug: config-debug
	# test each of our crates
	@$(MAKE) honk_rpc_cargo_test -C out/debug
	@$(MAKE) tor_interface_cargo_test_offline -C out/debug
	@$(MAKE) gosling_cargo_test_offline -C out/debug
	@$(MAKE) gosling_ffi_cargo_test -C out/debug
	@$(MAKE) gosling_unit_test -C out/debug

# release tests which do not require access to the tor network
test-offline-release: config-release
	# test each of our crates
	@$(MAKE) honk_rpc_cargo_test -C out/release
	@$(MAKE) tor_interface_cargo_test_offline -C out/release
	@$(MAKE) gosling_cargo_test_offline -C out/release
	@$(MAKE) gosling_ffi_cargo_test -C out/release
	@$(MAKE) gosling_unit_test -C out/release

# build test code coverage report
coverage: config-release
	@$(MAKE) gosling_cargo_tarpaulin -C out/release

# build test code coverge report using only the mock tor backend
coverage-offline: config-release
	@$(MAKE) gosling_cargo_tarpaulin_offline -C out/release

# format Rust code with cargo fmt and C++ code with clang-format
format:
	cd source/gosling && cargo fmt
	cd source/gosling/crates/gosling-ffi && clang-format -i libgosling.hpp
	cd source/test/functional && clang-format -i *.cpp *.hpp
	cd source/test/unit && clang-format -i *.cpp *.hpp

# line Rust code with cargo clippy and C++ code with clang-tidy
lint: config-debug
	@$(MAKE) gosling_cargo_clippy -C out/debug
	jq 'del(.[]|select(.directory|test("Catch2/src$$")))' out/debug/compile_commands.json > out/debug/compile_commands.sans-catch2.json
	cppcheck\
		--enable=all\
		--inline-suppr\
		--suppress=missingIncludeSystem\
		--include=out/debug/gosling/crates/gosling-ffi/include/libgosling.h\
		--include=out/debug/gosling/crates/gosling-ffi/include/libgosling.hpp\
		--project=out/debug/compile_commands.sans-catch2.json\
		-isource/sans-catch2

# build programmer documentation
docs: config-release
	@$(MAKE) gosling_cargo_doc -C out/release
	@$(MAKE) gosling_ffi_doxygen -C out/release

# build the website
pages: config-release
	@$(MAKE) gosling_pages -C out/release


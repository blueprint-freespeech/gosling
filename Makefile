.DEFAULT_GOAL := debug

# delete all build artifacts
clean:
	rm -rf out
	rm -rf dist

define config
	mkdir -p out/$(1)
	cd out/$(1) && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=$(2) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../../source/ -DCMAKE_INSTALL_PREFIX=../../dist/$(1)
endef

# cmake debug config
config-debug:
	@$(call config,"debug","Debug")

# cmake release config
config-release:
	@$(call config,"release","RelWithDebInfo")

# build debug target
debug: config-debug
	@$(MAKE) -C out/debug

# build release target
release: config-release
	@$(MAKE) -C out/release

define test
	@$(MAKE) honk_rpc_cargo_test -C out/$(1)
	@$(MAKE) tor_interface_cargo_test -C out/$(1)
	@$(MAKE) gosling_cargo_test -C out/$(1)
	@$(MAKE) gosling_ffi_cargo_test -C out/$(1)
	@$(MAKE) gosling_functional_test -C out/$(1)
	@$(MAKE) gosling_unit_test -C out/$(1)
endef

# build and run debug target tests
test-debug: config-debug
	@$(call test,"debug")

# build and run release target tests
test-release: config-release
	@$(call test,"release")

define test-offline
	@$(MAKE) honk_rpc_cargo_test -C out/$(1)
	@$(MAKE) tor_interface_cargo_test_offline -C out/$(1)
	@$(MAKE) gosling_cargo_test_offline -C out/$(1)
	@$(MAKE) gosling_ffi_cargo_test_offline -C out/$(1)
	@$(MAKE) gosling_unit_test -C out/$(1)
endef

# debug tests which do not require access to the tor network
test-offline-debug: config-debug
	@$(call test-offline,"debug")

# release tests which do not require access to the tor network
test-offline-release: config-release
	@$(call test-offline,"release")

# build release test code coverage report
coverage-debug: config-debug
	@$(MAKE) gosling_cargo_tarpaulin -C out/debug

# build debug test code coverage report
coverage-release: config-release
	@$(MAKE) gosling_cargo_tarpaulin -C out/release

# build debug test code coverge report using only the mock tor backend
coverage-offline-debug: config-debug
	@$(MAKE) gosling_cargo_tarpaulin_offline -C out/debug

# build release test code coverge report using only the mock tor backend
coverage-offline-release: config-release
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
		--include=out/debug/gosling/include/libgosling.h\
		--include=out/debug/gosling/include/libgosling.hpp\
		--project=out/debug/compile_commands.sans-catch2.json\
		-isource/sans-catch2

define pages
	@$(MAKE) gosling_cargo_doc -C out/$(1)
	@$(MAKE) gosling_ffi_doxygen -C out/$(1)
	@$(MAKE) gosling_pages -C out/$(1)
endef

# debug build the website, code coverage, c/c++ apis, and rust docs
pages-debug: config-debug coverage-debug
	@$(call pages,"debug")

# release build the website, code coverage, c/c++ apis, and rust docs
pages-release: config-release coverage-release
	@$(call pages,"release")

# debug build everything and deploy to dist
install-debug: debug pages-debug
	@$(MAKE) install -C out/debug

# release build everything and deploy to dist
install-release: release pages-release
	@$(MAKE) install -C out/release

# fuzzing targets
define fuzz
	@$(MAKE) $(1) -C out/$(2)
endef

fuzz-honk-rpc-session: config-release
	@$(call fuzz,"honk_rpc_cargo_fuzz_session","release/gosling/crates/honk-rpc")

fuzz-tor-interface-crypto: config-release
	@$(call fuzz,"tor_interface_cargo_fuzz_crypto","release/gosling/crates/tor-interface")
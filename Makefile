.DEFAULT_GOAL := debug

# Delete all build artifacts
clean:
	rm -rf out
	rm -rf dist

#
# Config Targets
#

define config
	mkdir -p out/$(1)
	cd out/$(1) && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=$(2) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../../source/ -DCMAKE_INSTALL_PREFIX=../../dist/$(1)
endef

# cmake Debug config
config-debug:
	@$(call config,"debug","Debug")

# cmake Release config
config-release:
	@$(call config,"release","Release")

# cmake RelWithDebInfo
config-rel-with-deb-info:
	@$(call config,"rel-with-deb-info","RelWithDebInfo")

# cmake RelWithDebInfo
config-min-size-rel:
	@$(call config,"min-size-rel","MinSizeRel")

#
# Build Targets
#

# build debug target
debug: config-debug
	@$(MAKE) build_target -C out/debug

# build release target
release: config-release
	@$(MAKE) build_target -C out/release

# build release target
rel-with-deb-info: config-rel-with-deb-info
	@$(MAKE) build_target -C out/rel-with-deb-info

# build release target
min-size-rel: config-min-size-rel
	@$(MAKE) build_target -C out/min-size-rel

#
# Online Test Targets (invokes real tor)
#

# build and run debug target tests
test-debug: config-debug
	@$(MAKE) test_target -C out/debug

# build and run release target tests
test-release: config-release
	@$(MAKE) test_target -C out/release

# build and run rel-with-deb-info target tests
test-rel-with-deb-info: config-rel-with-deb-info
	@$(MAKE) test_target -C out/rel-with-deb-info

# build and run min-size-rel target tests
test-min-size-rel: config-min-size-rel
	@$(MAKE) test_target -C out/min-size-rel

#
# Offline Test targets (mock tor)
#

# debug tests which do not require access to the tor network
test-offline-debug: config-debug
	@$(MAKE) test_offline_target -C out/debug

# release tests which do not require access to the tor network
test-offline-release: config-release
	@$(MAKE) test_offline_target -C out/release

# release tests which do not require access to the tor network
test-offline-rel-with-deb-info: config-rel-with-deb-info
	@$(MAKE) test_offline_target -C out/rel-with-deb-info

# release tests which do not require access to the tor network
test-offline-min-size-rel: config-min-size-rel
	@$(MAKE) test_offline_target -C out/min-size-rel

#
# Rust Code Coverage Targets
#

# build release test code coverage report
coverage-debug: config-debug
	@$(MAKE) gosling_cargo_tarpaulin -C out/debug

# build debug test code coverage report
coverage-rel-with-deb-info: config-rel-with-deb-info
	@$(MAKE) gosling_cargo_tarpaulin -C out/rel-with-deb-info

# build debug test code coverge report using only the mock tor backend
coverage-offline-debug: config-debug
	@$(MAKE) gosling_cargo_tarpaulin_offline -C out/debug

# build release test code coverge report using only the mock tor backend
coverage-offline-rel-with-deb-info: config-rel-with-deb-info
	@$(MAKE) gosling_cargo_tarpaulin_offline -C out/rel-with-deb-info

# format Rust code with cargo fmt and C++ code with clang-format
format:
	cd source/gosling && cargo fmt
	cd source/test/functional && clang-format -i *.cpp *.hpp
	cd source/test/unit && clang-format -i *.cpp *.hpp

# line Rust code with cargo clippy and C++ code with clang-tidy
lint: config-debug
	@$(MAKE) gosling_cargo_clippy -C out/debug
	# generate our c and cpp headers
	@$(MAKE) gosling_c_bindings_target -C out/debug
	@$(MAKE) gosling_cpp_bindings_target -C out/debug
	@$(MAKE) gosling_java_bindings_target -C out/debug
	# remove Catch2 files from lint set
	jq 'del(.[]|select(.directory|test("Catch2/src$$")))' out/debug/compile_commands.json > out/debug/compile_commands.sans-catch2.json
	cppcheck\
		--enable=all\
		--inline-suppr\
		--suppress=missingIncludeSystem\
		--suppress=*:source/extern/Catch2/src/catch2/*\
		--include=out/debug/bindings/c/include/cgosling.h\
		--include=out/debug/bindings/cpp/include/cgosling.hpp\
		--project=out/debug/compile_commands.sans-catch2.json

#
# Website Install Targets
#

website-debug: config-debug
	@$(MAKE) website_target -C out/debug

website-rel-with-deb-info: config-rel-with-deb-info
	@$(MAKE) website_target -C out/rel-with-deb-info

#
# Library Install Targets
#

# debug build everything and deploy to dist
install-debug: debug
	@$(MAKE) install -C out/debug

# release build everything and deploy to dist
install-release: release
	@$(MAKE) install -C out/release

# rel-with-deb-info build everything and deploy to dist
install-rel-with-deb-info: rel-with-deb-info
	@$(MAKE) install -C out/rel-with-deb-info

# min-size-rel build everything and deploy to dist
install-min-size-rel: min-size-rel
	@$(MAKE) install -C out/min-size-rel

#
# Fuzzing targets
#

define fuzz
	@$(MAKE) $(1) -C out/$(2)
endef

fuzz-honk-rpc-session: config-rel-with-deb-info
	@$(call fuzz,"honk_rpc_cargo_fuzz_session","rel-with-deb-info/gosling/crates/honk-rpc")

fuzz-tor-interface-crypto: config-rel-with-deb-info
	@$(call fuzz,"tor_interface_cargo_fuzz_crypto","rel-with-deb-info/gosling/crates/tor-interface")

fuzz-gosling-identity-server: config-rel-with-deb-info
	@$(call fuzz,"gosling_cargo_fuzz_identity_server","rel-with-deb-info/gosling/crates/gosling")

fuzz-gosling-identity-client: config-rel-with-deb-info
	@$(call fuzz,"gosling_cargo_fuzz_identity_client","rel-with-deb-info/gosling/crates/gosling")

fuzz-gosling-endpoint-server: config-rel-with-deb-info
	@$(call fuzz,"gosling_cargo_fuzz_endpoint_server","rel-with-deb-info/gosling/crates/gosling")

fuzz-gosling-endpoint-client: config-rel-with-deb-info
	@$(call fuzz,"gosling_cargo_fuzz_endpoint_client","rel-with-deb-info/gosling/crates/gosling")

fuzz-cgosling: config-rel-with-deb-info
	@$(call fuzz,"gosling_cargo_fuzz_cgosling","rel-with-deb-info/gosling/crates/cgosling")

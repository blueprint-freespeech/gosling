# Description

Gosling is a protocol and reference library implementation of said protocol. The protocol enables building peer-to-peer applications over the tor network whereby each node's connection has the following properties:

- **anonymous:** the real identity of a node is hidden using tor onion services
- **secure:** all network traffic is end-to-end encrypted by virtue of using tor and tor onion services
- **private+meta-data resistant:** nodes have fine control over their visibility/online-status to other nodes

It is meant to generalize (and improve upon) the authentication scheme [Ricochet-Refresh](https://github.com/blueprint-freespeech/ricochet-refresh) clients use to verify to each other's identity. Details can be found in the protocol specification here:

- [Gosling Protocol](https://blueprint-freespeech.github.io/gosling/gosling-spec.xhtml)


## Building

Gosling is built using cmake. By default, only the cgosling static libraries, shared libraries, and C/C++ headers are built. A typical development setup would be:

```shell
# Create out-of-tree build directory
mkdir build && cd build

# Generate Makefiles
cmake .. -DCMAKE_INSTALL_PREFIX=../dist -DCMAKE_BUILD_TYPE=Release

# Build default targets
make

# Install to ../dist
make install
```

You must explicitly set the `CMAKE_BUILD_TYPE` variable. The usual CMake build types are supported and mapped to equivalent cargo flags:

- **Debug**: no optimization, asserts enabled, debug symbols generated
- **Release**: optimize for speed, asserts disabled, debug symbols stripped
- **ReleaseWithDebInfo**: optimize for speed, asserts disabled, debug symbols generated
- **MinSizeRel**: optimize for size, asserts disabled, debug symbols stripped

See CMake's [CMAKE_BUILD_TYPE](https://cmake.org/cmake/help/v3.16/variable/CMAKE_BUILD_TYPE.html) documentation for additional information.

Tests and examples depend on additional libraries consumed as git submodules. They can be initialised by:

```shell
$ git submodule update --init
```

## Required Dependencies

Gosling currently has the following required build dependencies:

- [cmake >= 3.17](https://cmake.org)
- [rust >= 1.70.0](https://rust-lang.org)

Cargo will automatically download and build the required Rust crates. The list of current dependencies can be found in each crate's Cargo.toml file:

- [honk-rpc](./source/gosling/crates/honk-rpc/Cargo.toml)
- [tor-interface](./source/gosling/crates/tor-interface/Cargo.toml)
- [gosling](./source/gosling/crates/gosling/Cargo.toml)
- [cgosling](./source/gosling/crates/cgosling/Cargo.toml.in)

## Configuration Options

Build-time configuration options for features which may be conditionally enabled or disabled.

### ENABLE_MOCK_TOR_PROVIDER

```shell
cmake -DENABLE_MOCK_TOR_PROVIDER=ON
```

Enable the mock TorProvider implementation. This TorProvider is in-process and local only; it does not connect to the internet or the real Tor Network. It is only useful for testing. This option is **ON** by default.

### ENABLE_LEGACY_TOR_PROVIDER

```shell
cmake -DENABLE_LEGACY_TOR_PROVIDER=ON
```

Enable the (for now, default) c-tor daemon TorProvider implementation. This allows Gosling to connect to the Tor Network using the legacy c-tor daemon. This option is **ON** by default.

## Additional Configuration Options and Optional Dependencies

Additional optional bindings, tests, and documentation can be enabled with the following cmake options. Each of these options are **OFF** by default.

### ENABLE_TESTS

```shell
cmake -DENABLE_TESTS=ON
```

Enables the following ctest test targets (internet access is only required when a non-mock tor provider is enabled):

- honk_rpc_cargo_test
- tor_interface_cargo_test
- gosling_cargo_test
- cgosling_cargo_test
- gosling_functional_test
- gosling_unit_test

The following additional dependencies are required for this configure option:

- [boost >= 1.66](https://www.boost.org/)
- [Catch2 >= 3.0](https://github.com/catchorg/Catch2)

### ENABLE_FUZZ_TESTS

```shell
cmake -DENABLE_FUZZ_TESTS=ON
```

Enables the following cargo-fuzz ctest test targets (enabling this option also enables the **ENABLE_TESTS** option):

- honk_rpc_cargo_fuzz_test
- tor_interface_crypto_cargo_fuzz_test
- gosling_identity_server_cargo_fuzz_test
- gosling_identity_client_cargo_fuzz_test
- gosling_endpoint_server_cargo_fuzz_test
- gosling_endpoint_client_cargo_fuzz_test
- cgosling_cargo_fuzz_test

The following additional dependencies are required for this configure option:

- rust nightly (for `-z`  rustc compiler flag)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [libfuzzer](https://www.llvm.org/docs/LibFuzzer.html)

### ENABLE_LINTING

```shell
cmake -DENABLE_LINTING=ON
```

The following additional dependencies are required for this configure option:

- [cppcheck](https://cppcheck.sourceforge.io/)
- [jq](https://jqlang.github.io/jq/)

### ENABLE_FORMATTING

```shell
cmake -DENABLE_FORMATTING=ON
```

The following additional dependencies are required for this configure option:

- [clang-format](https://clang.llvm.org/docs/ClangFormat.html)

### BUILD_PYTHON_BINDINGS

```shell
cmake -DBUILD_PYTHON_BINDINGS=ON
```

Generates cgosling.py Python bindings as part of build

### BUILD_JAVA_BINDINGS

```shell
cmake -DBUILD_JAVA_BINDINGS=ON
```

Builds a cgosling-based JNI shared library and Gosling.jar java bindings.

The following additional dependencies are required for this configure option:

- [Java JDK](https://openjdk.org/)
- [boost >= 1.66](https://www.boost.org/)

### BUILD_EXAMPLES

```shell
cmake -DBUILD_EXAMPLES=ON
```

Builds a cgosling-based C++ example program.

The following additional dependencies are required for this configure option:

- [boost >= 1.66](https://www.boost.org/)
- [ncurses](https://invisible-mirror.net/ncurses/ncurses.html)
- [nlohmann::json](https://github.com/nlohmann/json/releases/tag/v3.11.3)

### BUILD_DEBIAN_SOURCE_PACKAGE

```shell
cmake -DBUILD_DEBIAN_SOURCE_PACKAGE=ON
```

Builds a debian source package which generate `libcgosling0`, `libcgosling-dev`, and `libcgosling0-dbgsym` debian packages.

The following additional dependencies are required for this configure option:

- tar
- dpkg-source

See [source/packages/debian-source/README.md](source/packages/debian-source/README.md) for additional information.

### BUILD_HOMEBREW_FORMULA

```shell
cmake -DBUILD_HOMEBREW_FORMULA=ON
```

Builds a homebrew flask formula which installs libcgosling static libs, shared libs, and developemnt headers.

See [source/packages/homebrew-formula/README.md](source/packages/homebrew-formula/README.md) for more additional information.

### BUILD_MSYS2_PKGBUILD

```shell
cmake -DBUILD_MSYS2_PKGBUILD=ON
```

Builds an MSYS2 PKGBUILD script which builds and installs libcgosling static libs, shared libs, and development headers.

See [source/packages/msys2-pckbuild/README.md](source/packages/msys2-pckbuild/README.md) for more additional information.

### BUILD_PAGES

```shell
cmake -DBUILD_PAGES=ON
```

Generate the gosling.technolgoy website including test code-coverage, Rust crate documentation, cgosling C/C++ documentation, and specifications. This configuration is only valid for **Debug** and **RelWithDebInfo** cmake targets.

Access to the tor network is required to run the tests and generate code-coverage.

The following additional dependencies are required for this configure option:

- [doxygen](https://www.doxygen.nl/)
- [graphviz](https://www.graphviz.org/)
- [mustache](http://mustache.github.io/)
- [pandoc](https://pandoc.org)
- [plantuml](https://github.com/plantuml/plantuml)
- [tidy](https://github.com/htacg/tidy-html5)

---

## Acknowledgements

Creation of innovative free software needs support. We thank the NGI Assure Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073

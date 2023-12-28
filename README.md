# Description

Gosling is a protocol and reference library implementation of said protocol. The protocol enables building peer-to-peer applications over the tor network whereby each node's connection has the following properties:

- **anonymous:** the real identity of a node is hidden using tor onion services
- **secure:** all network traffic is end-to-end encrypted by virtue of using tor and tor onion services
- **private+meta-data resistant:** nodes have fine control over their visibility/online-status to other nodes

It is meant to generalize (and improve upon) the authentication scheme [Ricochet-Refresh](https://github.com/blueprint-freespeech/ricochet-refresh) clients use to verify to each other's identity. Details can be found in the protocol specification here:

- [Gosling Protocol](https://blueprint-freespeech.github.io/gosling/gosling-spec.xhtml)


## Dependencies

Gosling currently has the following external build dependencies:

- rust >= [1.66.0](https://github.com/blueprint-freespeech/gosling/blob/main/source/gosling/Cargo.toml#L6)
- cargo
- cmake >= [3.17](https://github.com/blueprint-freespeech/gosling/blob/main/source/CMakeLists.txt#L1)
- boost >= [1.66](https://github.com/blueprint-freespeech/gosling/blob/main/source/test/functional/CMakeLists.txt#L1) (for C++ example and tests)

Gosling additionally has the following dependencies consumed as git submodules:

- [Catch2](https://github.com/catchorg/Catch2) (for C++ tests)
- [nlforohmann::json](https://github.com/nlohmann/json/releases/tag/v3.11.3) (for C++ example)

Cargo will automatically download and build the required Rust crates. The list of current dependencies can be found in each crate's Cargo.toml file:

- [honk-rpc](./source/gosling/crates/honk-rpc/Cargo.toml)
- [tor-interface](./source/gosling/crates/tor-interface/Cargo.toml)
- [gosling](./source/gosling/crates/gosling/Cargo.toml)
- [gosling-ffi](./source/gosling/crates/gosling-ffi/Cargo.toml)

## Optional Dependencies

The **coverage-** make targets have the following additional dependencies:

- [cargo-tarpaulin](https://crates.io/crates/cargo-tarpaulin)

The **fuzz-** make targets have the following additional dependencies:

- rust nightly (for `-z`  rustc compiler flag)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [libfuzzer](https://www.llvm.org/docs/LibFuzzer.html)

The **pages-** make target has the following additional dependencies:

- [doxygen](https://www.doxygen.nl/)
- [graphviz](https://www.graphviz.org/)
- [mustache](http://mustache.github.io/)
- [pandoc](https://pandoc.org)
- [plantuml](https://github.com/plantuml/plantuml)
- [tidy](https://github.com/htacg/tidy-html5)

The **format** make target has the following additional dependencies:

- [clang-format](https://clang.llvm.org/docs/ClangFormat.html)

The **lint** make target has the following additional dependencies:

- [cppcheck](https://cppcheck.sourceforge.io/)
- [jq](https://jqlang.github.io/jq/)

The **examples** make targets have the following additional dependencies:

- [ ncurses](https://invisible-mirror.net/ncurses/ncurses.html)

## Building

The reference implementation is a work-in-progress and the API is not yet fully stable.

You will need to initialize the git submodules by:

```shell
$ git submodule update --init
```

The following make targets are supported:

- **Misc**
    - **clean** - deletes **all** build artifacts in `out` and `dist` directories
    - **format** - runs `cargo fmt` on Rust source and `clang-format` on the C++ source
    - **lint** - runs `cargo clippy` on the Rust source and `cppcheck` on the C++ source
- **Config Targets:** creates Makefiles for different build types
    - **config-debug** - **Debug** CMake build type: no optimization, asserts enabled, debug symbols generated; build artifacts placed in `out/debug`
    - **config-release** - **Release** Cmake build type: optimize for speed, asserts disabled, debug symbols stripped; build artifacts placed in `out/release`
    - **config-rel-with-deb-info** - **RelWithDebInfo** CMake build type: optimize for speed, asserts disabled, debug symbols generated; build artifacts placed in `out/rel-with-deb-info`
    - **config-min-size-rel** - **MinSizeRel** CMake build type: optimize for size, asserts disabled, debug symbols stripped; build artifacts placed in `out/min-size-rel`

    Further information about CMake build types can be found in the CMake documentation:
    - https://cmake.org/cmake/help/v3.16/variable/CMAKE_BUILD_TYPE.html
- **Build Targets:** build gosling crates, language bindings, tests, and examples
    - **debug**
    - **release**
    - **rel-with-deb-info**
    - **min-size-rel**
- **Install Targets:** build and deploy `cgosling` headers and static+shared libraries to `dist*`
    - **install-debug**
    - **install-release**
    - **install-rel-with-deb-info**
    - **install-min-size-rel**
- **Test Targets:** build and run all tests using real tor daemon
    - **test-debug**
    - **test-release**
    - **test-rel-with-deb-info**
    - **test-min-size-rel**
- **Offline Test Targets:** build and run all tests using mock offline tor daemon
    - **test-offline-debug**
    - **test-offline-release**
    - **test-offline-rel-with-deb-info**
    - **test-offline-min-size-rel**
- **Rust Test Coverage:** build and run Rust tests and calculate code coverage using real tor daemon
    - **coverage-debug**
    - **coverage-rel-with-deb-info**
- **Rust Offline Test Coverage:** build and run Rust tets and calculate code coverage using mock offline tor daemon
    - **coverage-offline-debug**
    - **coverage-offline-rel-with-deb-info**
- **Fuzz Targets:** run `cargo-fuzz` tests
    - **fuzz-honk-rpc-session** - honk-rpc session
    - **fuzz-tor-interface-crypto** - tor-interface cryptography
    - **fuzz-gosling-identity-server** - gosling identity server protocol
    - **fuzz-gosling-identity-client** - gosling identity client protocol
    - **fuzz-gosling-endpoint-server** - gosling endpoint server protocol
    - **fuzz-gosling-endpoint-client** - gosling endpoint client protocol
    - **fuzz cgosling** - cgosling C FFI
- **Website Targets:** build pages, Rust crate documentation, C/C++ doxygen documentation, and Rust test coverage; websites deployed to `dist/*`
    - **install-pages-debug**
    - **install-pages-rel-with-deb-info**

## Acknowledgements

Creation of innovative free software needs support. We thank the NGI Assure Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073
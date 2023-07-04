# Description

Gosling is a protocol and reference library implementation of said protocol. The protocol enables building peer-to-peer applications over the tor network whereby each node's connection has the following properties:

- **anonymous:** the real identity of a node is hidden using tor onion services
- **secure:** all network traffic is end-to-end encrypted by virtue of using tor and tor onion services
- **private+meta-data resistant:** nodes have fine control over their visibility/online-status to other nodes

It is meant to generalize (and improve upon) the authentication scheme [Ricochet-Refresh](https://github.com/blueprint-freespeech/ricochet-refresh) clients use to verify to each other. Details can be found in the protocol specification here:

- [Gosling Protocol](./docs/gosling_protocol/protocol.md)


## Dependencies

Libgosling currently has the following build dependencies:

- rust >= [1.66.0](https://github.com/blueprint-freespeech/gosling/blob/main/source/gosling/Cargo.toml#L6)
- cargo
- cmake >= [3.17](https://github.com/blueprint-freespeech/gosling/blob/main/source/CMakeLists.txt#L1)
- boost >= [1.66](https://github.com/blueprint-freespeech/gosling/blob/main/source/test/functional/CMakeLists.txt#L1) (for C++ tests)

Cargo will automatically download and build the required Rust crates. The list of current dependencies can be found in each crate's Cargo.toml file:

- [honk-rpc](./source/gosling/crates/honk-rpc/Cargo.toml)
- [tor-interface](./source/gosling/crates/tor-interface/Cargo.toml)
- [gosling](./source/gosling/crates/gosling/Cargo.toml)
- [gosling-ffi](./source/gosling/crates/gosling-ffi/Cargo.toml)

## Optional Dependencis

The **coverage-** make targets have the following additional dependencies:

- [cargo-tarpaulin](https://crates.io/crates/cargo-tarpaulin)

The **format** make target has the following additional dependencies:

- [clang-format](https://clang.llvm.org/docs/ClangFormat.html)

The **lint** make target has the following additional dependencies:

- [cppcheck](https://cppcheck.sourceforge.io/)
- [jq](https://jqlang.github.io/jq/)

The **docs** make target has the following additional dependencies:

- [doxygen](https://www.doxygen.nl/)

The **pages** make target has the following additional dependencies:

- [markdown](https://daringfireball.net/projects/markdown/)
- [mustache](http://mustache.github.io/)

The documentation has the following build dependencies:

- [plantuml](https://github.com/plantuml/plantuml)
- [tidy](https://github.com/htacg/tidy-html5)

## Building

The reference implementation is a work-in-progress and the API is not yet fully stable.

You will need to initialize the git submodules by:

```shell
$ git submodule update --init
```

The following make targets are supported:

- **clean** - deletes all build artifacts in `out` directory
- **config-debug** - builds Makefiles for the **Debug** CMake build type: no optimization, asserts enabled, debug symbols generated; bulid artifacts placed in `out/debug`
- **config-release** - builds Makefile for the **RelWithDebInfo** CMake build type: optimize for speed, asserts disabled, debug symbols generated; build artifacts placed in `out/release`
- **debug** - builds debug version of the gosling library
- **release** - builds release version of the gosling library
- **test-debug** - builds and runs debug versions of all tests
- **test-release** - builds and runs release versions of all tests
- **test-offline-debug** - builds and runs debug versions of only tests which do not need access to the internet
- **test-offline-release** - builds and runs release versions of only tests which do not need access to the internet
- **coverage** - generates test code coverage of all crates using `cargo-tarpaulin` crate
- **coverage-offline** - generates offline test code coverage of all crates using `cargo-tarpulin` crate
- **format** - runs `cargo fmt` on Rust source and `clang-format` on the C++ source
- **lint** - runs `cargo clippy` on the Rust source and `cppcheck` on the C++ source
- **docs** - builds the cargo docs for the crates and the doxygen docs for gosling-ffi
- **pages** - builds the static website

Further information about CMake build types can be found in the CMake documentation:
- https://cmake.org/cmake/help/v3.16/variable/CMAKE_BUILD_TYPE.html

## Acknowledgements

Creation of innovative free software needs support. We thank the NGI Assure Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073
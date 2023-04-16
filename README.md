# Description

Gosling is a protocol and reference library implementation of said protocol. The protocol enables building peer-to-peer applications over the tor network whereby each node's connection has the following properties:

- **anonymous:** the real identity of a node is hidden using tor onion services
- **secure:** all network traffic is end-to-end encrypted by virtue of using tor and tor onion services
- **private+meta-data resistant:** nodes have fine control over their visibility/online-status to other nodes

It is meant to generalize (and improve upon) the authentication scheme [Ricochet-Refresh](https://github.com/blueprint-freespeech/ricochet-refresh) clients use to verify to each other. Details can be found in the protocol specification here:

- [Gosling Protocol](./docs/gosling_protocol/protocol.md)


## Dependencies

Libgosling currently has the following build dependencies:

- rust >= [1.61.0](https://github.com/blueprint-freespeech/gosling/blob/main/source/gosling/Cargo.toml#L6)
- cargo
- cmake >= [3.16.6](https://github.com/blueprint-freespeech/gosling/blob/main/source/CMakeLists.txt#L1)
- boost >= [1.66](https://github.com/blueprint-freespeech/gosling/blob/main/source/test/functional/CMakeLists.txt#L1) (for C++ tests)

Cargo will automatically download and build the required Rust crates. The list of current dependencies can be found in [Cargo.toml](https://github.com/blueprint-freespeech/gosling/blob/main/source/gosling/Cargo.toml)

## Optional Dependencis

The **format** make target has the following dependencies:

- clang-format

The documentation has the following build dependencies:

- [plantuml](https://github.com/plantuml/plantuml)
- [tidy](https://github.com/htacg/tidy-html5)

## Building

The reference implementation is a work-in-progress and the API is not yet fully stable.

You will need to initialize the git submodules by:

```
$ git submodule update --init
```

The following make targets are supported:

- **debug** - corresponds to the **Debug** CMake build type: no optimization, asserts enabled, debug symbols generated; bulid artifacts placed in out/debug
- **release** - corresponds to the **RelWithDebInfo** CMake build type: optimize for speed, asserts disabled, debug symbols generated; build artifacts placed in out/release
- **test-debug** - builds debug target and runs all tests
- **test-release** - builds release target and runs all tests
- **format** - runs cargo fmt on Rust source
- **clean** - deletes build artifacts

Further information about CMake build types can be found in the CMake documentation:
- https://cmake.org/cmake/help/v3.16/variable/CMAKE_BUILD_TYPE.html

## Acknowledgements

Creation of innovative free software needs support. We thank the NGI Assure Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073
set(CGOSLING_MAJOR_VERSION "0" CACHE STRING "SemVer major version of cgosling library" FORCE)
set(CGOSLING_MINOR_VERSION "2" CACHE STRING "SemVer minor version of cgosling library" FORCE)
set(CGOSLING_PATCH_VERSION "1" CACHE STRING "SemVer patch version of cgosling library" FORCE)
set(CGOSLING_VERSION "${CGOSLING_MAJOR_VERSION}.${CGOSLING_MINOR_VERSION}.${CGOSLING_PATCH_VERSION}" CACHE STRING "SemVer of the cgosling library" FORCE)

# generate Cargo.toml file
set(CARGO_TOML_IN ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml.in)
set(CARGO_TOML_OUT ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml)
configure_file(${CARGO_TOML_IN} ${CARGO_TOML_OUT} @ONLY)

set(cgosling_sources
    build.rs
    Cargo.toml
    cbindgen.toml
    src/ffi.rs
    src/lib.rs
    src/object_registry.rs)

set(CGOSLING_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}cgosling${CMAKE_STATIC_LIBRARY_SUFFIX}" CACHE STRING "cgosling static library filename" FORCE)
if (WINDOWS)
    set(CGOSLING_SHARED "cgosling${CMAKE_SHARED_LIBRARY_SUFFIX}" CACHE STRING "cgosling shared library filename" FORCE)
    set(CGOSLING_IMPORT "libcgosling${CMAKE_IMPORT_LIBRARY_SUFFIX}" CACHE STRING "cgosling import library filename" FORCE)
else()
    set(CGOSLING_SHARED "${CMAKE_SHARED_LIBRARY_PREFIX}cgosling${CMAKE_SHARED_LIBRARY_SUFFIX}" CACHE STRING "cgosling shared library filename" FORCE)
endif()

set(cgosling_outputs
    ${CARGO_TARGET_DIR}/include/cgosling.h
    ${CARGO_TARGET_DIR}/cgosling.json
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libcgosling.d
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libcgosling.rlib
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_STATIC}
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}
)

# add shared library import library if platform supports it
if ((DEFINED CGOSLING_IMPORT))
    list(APPEND cgosling_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_IMPORT})
endif()

#
# build target
#
add_custom_command(
    DEPENDS ${cgosling_sources}
    OUTPUT ${cgosling_outputs}
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(cgosling_target
    DEPENDS ${cgosling_outputs})
add_dependencies(cgosling_target gosling_target)

if (ENABLE_TESTS)
    #
    # cargo test target
    #
    if (ENABLE_ONLINE_TESTS)
        add_test(NAME cgosling_cargo_test
            COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    #
    # cargo test (offline) target
    #
    add_test(NAME cgosling_offline_cargo_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS} --features offline-test
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

    #
    # fuzz targets
    #
    if (ENABLE_FUZZ_TESTS)
        add_test(NAME cgosling_cargo_fuzz_test
            COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_cgosling ${CARGO_FLAGS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
endif()

set(cgosling_sources
    src/ffi.rs
    src/lib.rs
    src/object_registry.rs
    build.rs
    Cargo.toml
    cbindgen.toml)

set(cgosling_outputs
    ${CARGO_TARGET_DIR}/include/libgosling.h
    ${CARGO_TARGET_DIR}/libgosling.json
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_STATIC_LIBRARY_PREFIX}cgosling${CMAKE_STATIC_LIBRARY_SUFFIX}
)

# Rust incorrectly does not include the 'lib' prefix for mingw shared-library targets, so we need to handle that for cmake to play nicely
if (MINGW)
    list(APPEND cgosling_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling${CMAKE_SHARED_LIBRARY_SUFFIX})
else()
    list(APPEND cgosling_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_SHARED_LIBRARY_PREFIX}cgosling${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    list(APPEND cgosling_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_IMPORT_LIBRARY_PREFIX}cgosling${CMAKE_IMPORT_LIBRARY_SUFFIX})
endif()

#
# cgosling build target
#
add_custom_command(
    DEPENDS ${cgosling_sources} gosling_target
    OUTPUT ${cgosling_outputs}
    # cargo test of this same project will also run build.rs, so we need to touch build.rs
    # to force cargo to re-run it and generate cbindgen headers (cmake seems to delete the first output file)
    COMMAND touch ${CMAKE_CURRENT_SOURCE_DIR}/build.rs
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(cgosling_target
    DEPENDS ${cgosling_outputs})

#
# cargo test target
#
add_custom_target(cgosling_cargo_test
    COMMAND RUSTFLAGS=${RUSTFLAGS} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# cargo test (offline)
#
add_custom_target(cgosling_cargo_test_offline
    COMMAND RUSTFLAGS=${RUSTFLAGS} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS} --features offline-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# fuzz targets
#
add_custom_target(gosling_cargo_fuzz_cgosling
    COMMAND RUSTFLAGS=${RUSTFLAGS} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUST_BACKTRACE=full cargo fuzz run fuzz_cgosling ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
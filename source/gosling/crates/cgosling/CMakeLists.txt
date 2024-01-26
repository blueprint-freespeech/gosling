set(cgosling_sources
    build.rs
    Cargo.toml
    cbindgen.toml
    src/ffi.rs
    src/lib.rs
    src/object_registry.rs)

set(cgosling_outputs
    ${CARGO_TARGET_DIR}/include/cgosling.h
    ${CARGO_TARGET_DIR}/cgosling.json
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libcgosling.d
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libcgosling.rlib
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_STATIC_LIBRARY_PREFIX}cgosling${CMAKE_STATIC_LIBRARY_SUFFIX}
)

# add shared library
if (MINGW)
    # Rust does not include the 'lib' prefix for mingw shared-library targets, so we need to handle that for mingw cmake to play nicely
    list(APPEND cgosling_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling${CMAKE_SHARED_LIBRARY_SUFFIX})
else()
    list(APPEND cgosling_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_SHARED_LIBRARY_PREFIX}cgosling${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

# add shared library import library if platform supports it
if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    list(APPEND cgosling_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_IMPORT_LIBRARY_PREFIX}cgosling${CMAKE_IMPORT_LIBRARY_SUFFIX})
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

#
# test target
#
add_custom_target(cgosling_cargo_test
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# test target (offline)
#
add_custom_target(cgosling_cargo_test_offline
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS} --features offline-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# fuzz targets
#
add_custom_target(gosling_cargo_fuzz_cgosling
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_cgosling ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
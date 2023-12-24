set(gosling_ffi_sources
    src/ffi.rs
    src/lib.rs
    src/object_registry.rs
    build.rs
    Cargo.toml
    cbindgen.toml)

set(gosling_ffi_outputs
    ${CARGO_TARGET_DIR}/include/libgosling.h
    ${CARGO_TARGET_DIR}/libgosling.json
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_STATIC_LIBRARY_PREFIX}goslingffi${CMAKE_STATIC_LIBRARY_SUFFIX}
)

# Rust incorrectly does not include the 'lib' prefix for mingw shared-library targets, so we need to manually add it back for
# cmake to play nicely
if (MINGW)
    list(APPEND gosling_ffi_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/goslingffi${CMAKE_SHARED_LIBRARY_SUFFIX})
else()
    list(APPEND gosling_ffi_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_SHARED_LIBRARY_PREFIX}goslingffi${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    list(APPEND gosling_ffi_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_IMPORT_LIBRARY_PREFIX}goslingffi${CMAKE_IMPORT_LIBRARY_SUFFIX})
endif()

#
# gosling_ffi build target
#
add_custom_command(
    DEPENDS ${gosling_ffi_sources} gosling_target
    OUTPUT ${gosling_ffi_outputs}
    # cargo test of this same project will also run build.rs, so we need to touch build.rs
    # to force cargo to re-run it and generate cbindgen headers (cmake seems to delete the first output file)
    COMMAND touch ${CMAKE_CURRENT_SOURCE_DIR}/build.rs
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# fixup prefix for mingw dll output
if (MINGW)
    add_custom_command(
        DEPENDS ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/goslingffi${CMAKE_SHARED_LIBRARY_SUFFIX}
        OUTPUT ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_SHARED_LIBRARY_PREFIX}goslingffi${CMAKE_SHARED_LIBRARY_SUFFIX}
        COMMAND mv ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/goslingffi${CMAKE_SHARED_LIBRARY_SUFFIX} ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_SHARED_LIBRARY_PREFIX}goslingffi${CMAKE_SHARED_LIBRARY_SUFFIX}
    )
    list(REMOVE_ITEM gosling_ffi_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/goslingffi${CMAKE_SHARED_LIBRARY_SUFFIX})
    list(APPEND gosling_ffi_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_SHARED_LIBRARY_PREFIX}goslingffi${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

add_custom_target(gosling_ffi_target
    DEPENDS ${gosling_ffi_outputs})

#
# cargo test target
#
add_custom_target(gosling_ffi_cargo_test
    COMMAND RUSTFLAGS=${RUSTFLAGS} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# cargo test (offline)
#
add_custom_target(gosling_ffi_cargo_test_offline
    COMMAND RUSTFLAGS=${RUSTFLAGS} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS} --features offline-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# fuzz targets
#
add_custom_target(gosling_cargo_fuzz_gosling_ffi
    COMMAND RUSTFLAGS=${RUSTFLAGS} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUST_BACKTRACE=full cargo fuzz run fuzz_gosling_ffi ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
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
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libgoslingffi.a)
#
# gosling_ffi_static build target
#
add_custom_command(
    OUTPUT ${gosling_ffi_outputs}
    DEPENDS ${gosling_ffi_sources} gosling_target
    # cargo test of this same project will also run build.rs, so we need to touch build.rs
    # to force cargo to re-run it and generate cbindgen headers (cmake seems to delete the first output file)
    COMMAND touch ${CMAKE_CURRENT_SOURCE_DIR}/build.rs
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target(gosling_ffi_target
    DEPENDS ${gosling_ffi_outputs})

# create gosling library target
add_library(gosling_ffi_static STATIC IMPORTED GLOBAL)
# which depends on the above command target
add_dependencies(gosling_ffi_static gosling_ffi_target)

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
    COMMAND RUSTFLAGS=${RUSTFLAGS} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUST_BACKTRACE=full cargo fuzz run fuzz_gosling_ffi_static ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
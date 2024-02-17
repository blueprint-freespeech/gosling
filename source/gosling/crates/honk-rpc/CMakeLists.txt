set(honk_rpc_depends
    Cargo.toml
    src/byte_counter.rs
    src/honk_rpc.rs
    src/lib.rs)

set(honk_rpc_outputs
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libhonk_rpc.d
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libhonk_rpc.rlib)

#
# build target
#
add_custom_command(
    DEPENDS ${honk_rpc_depends}
    OUTPUT ${honk_rpc_outputs}
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(honk_rpc_target
    DEPENDS ${honk_rpc_outputs})

#
# cargo test target
#
add_custom_target(honk_rpc_cargo_test_target
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_dependencies(test_target honk_rpc_cargo_test_target)
add_dependencies(test_offline_target honk_rpc_cargo_test_target)

#
# fuzz target
#
add_custom_target(honk_rpc_cargo_fuzz_session
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_session ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

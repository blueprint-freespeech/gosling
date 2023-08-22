set(honk_rpc_sources
    src/honk_rpc.rs
    src/lib.rs)

#
# build target
#
add_custom_target(honk_rpc_target
    DEPENDS ${honk_rpc_sources}
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

#
# test target
#
add_custom_target(honk_rpc_cargo_test
    COMMAND RUSTFLAGS=${RUSTFLAGS} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# fuzz target
#
add_custom_target(honk_rpc_cargo_fuzz_session
    COMMAND RUSTFLAGS=${RUSTFLAGS} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUST_BACKTRACE=full cargo fuzz run fuzz_session ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

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

if (ENABLE_TESTS)
    #
    # cargo test target
    #
    add_test(NAME honk_rpc_cargo_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    #
    # fuzz target
    #
    if (ENABLE_FUZZ_TESTS)
        add_test(NAME honk_rpc_cargo_fuzz_test
            COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_session -- -max_total_time=${FUZZ_TEST_MAX_TOTAL_TIME}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    endif()
endif()

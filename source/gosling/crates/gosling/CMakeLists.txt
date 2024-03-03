set(gosling_sources
    Cargo.toml
    src/ascii_string.rs
    src/context.rs
    src/endpoint_client.rs
    src/endpoint_server.rs
    src/gosling.rs
    src/identity_client.rs
    src/identity_server.rs
    src/lib.rs)

set(gosling_outputs
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libgosling.d
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libgosling.rlib)

#
# build target
#
add_custom_command(
    DEPENDS ${gosling_sources}
    OUTPUT ${gosling_outputs}
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(gosling_target
    DEPENDS ${gosling_outputs})
add_dependencies(gosling_target honk_rpc_target tor_interface_target)

if (ENABLE_TESTS)
    if (ENABLE_ONLINE_TESTS)
        #
        # cargo test target
        #
        add_test(NAME gosling_cargo_test
            COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    endif()

    #
    # cargo test (offline) target
    #
    add_test(NAME gosling_offline_cargo_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS} --features offline-test
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    #
    # fuzz targets
    #
    if (ENABLE_FUZZ_TESTING)
        add_test(NAME gosling_identity_server_cargo_fuzz_test
            COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_identity_server ${CARGO_FLAGS}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )

        add_test(NAME gosling_identity_client_cargo_fuzz_test
            COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_identity_client ${CARGO_FLAGS}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )

        add_test(NAME gosling_endpoint_server_cargo_fuzz_test
            COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_endpoint_server ${CARGO_FLAGS}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )

        add_test(NAME gosling_endpoint_client_cargo_fuzz_test
            COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_endpoint_client ${CARGO_FLAGS}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    endif()
endif()

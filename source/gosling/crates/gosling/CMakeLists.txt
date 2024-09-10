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
# gosling crate feature flags
#

set(GOSLING_FEATURE_LIST)
if (ENABLE_MOCK_TOR_PROVIDER)
    list(APPEND GOSLING_FEATURE_LIST "mock-tor-provider")
endif()
if (ENABLE_LEGACY_TOR_PROVIDER)
    list(APPEND GOSLING_FEATURE_LIST "legacy-tor-provider")
endif()
if (ENABLE_ARTI_CLIENT_TOR_PROVIDER)
    list(APPEND GOSLING_FEATURE_LIST "arti-client-tor-provider")
endif()

list(JOIN GOSLING_FEATURE_LIST "," GOSLING_FEATURES)
if (GOSLING_FEATURES)
    set(GOSLING_FEATURES "--features" "${GOSLING_FEATURES}")
endif()

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

#
# cargo test target
#
if (ENABLE_TESTS)
    add_test(NAME gosling_cargo_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS} ${GOSLING_FEATURES} -- --nocapture
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

#
# fuzz targets
#
if (ENABLE_FUZZ_TESTS)
    add_test(NAME gosling_identity_server_cargo_fuzz_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_identity_server -- -max_total_time=${FUZZ_TEST_MAX_TOTAL_TIME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_test(NAME gosling_identity_client_cargo_fuzz_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_identity_client -- -max_total_time=${FUZZ_TEST_MAX_TOTAL_TIME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_test(NAME gosling_endpoint_server_cargo_fuzz_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_endpoint_server -- -max_total_time=${FUZZ_TEST_MAX_TOTAL_TIME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_test(NAME gosling_endpoint_client_cargo_fuzz_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_endpoint_client -- -max_total_time=${FUZZ_TEST_MAX_TOTAL_TIME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

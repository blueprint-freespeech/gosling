add_test(NAME gosling_test
    COMMAND cargo test ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
set_tests_properties(gosling_test
    PROPERTIES ENVIRONMENT "RUSTFLAGS=${RUSTFLAGS};CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR};RUST_BACKTRACE=full"
)
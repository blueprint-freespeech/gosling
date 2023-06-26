add_subdirectory(crates)

add_custom_target(gosling_cargo_tarpaulin
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out Html --output-dir ${CMAKE_CURRENT_BINARY_DIR}/tarpaulin --timeout 600 --features tor-interface/offline-test gosling/offline-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS
)

add_subdirectory(crates)

# code coverage target
add_custom_target(gosling_cargo_tarpaulin
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out Html --output-dir ${CMAKE_CURRENT_BINARY_DIR}/tarpaulin --timeout 600
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS
)

add_custom_target(gosling_cargo_tarpaulin_offline
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out Html --output-dir ${CMAKE_CURRENT_BINARY_DIR}/tarpaulin-offline --features tor-interface/offline-test gosling/offline-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS
)

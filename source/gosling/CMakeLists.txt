add_subdirectory(crates)

set(crate_sources
    crates/honk-rpc/src/memory_stream.rs
    crates/honk-rpc/src/lib.rs
    crates/honk-rpc/src/honk_rpc.rs
    crates/tor-interface/src/legacy_tor_controller.rs
    crates/tor-interface/src/legacy_tor_process.rs
    crates/tor-interface/src/tor_crypto.rs
    crates/tor-interface/src/mock_tor_client.rs
    crates/tor-interface/src/tor_provider.rs
    crates/tor-interface/src/legacy_tor_client.rs
    crates/tor-interface/src/legacy_tor_version.rs
    crates/tor-interface/src/lib.rs
    crates/tor-interface/src/legacy_tor_control_stream.rs
    crates/gosling/src/context.rs
    crates/gosling/src/endpoint_client.rs
    crates/gosling/src/identity_server.rs
    crates/gosling/src/endpoint_server.rs
    crates/gosling/src/memory_stream.rs
    crates/gosling/src/identity_client.rs
    crates/gosling/src/ascii_string.rs
    crates/gosling/src/lib.rs
    crates/gosling/src/gosling.rs
    crates/gosling-ffi/src/ffi.rs
    crates/gosling-ffi/src/lib.rs
    crates/gosling-ffi/src/object_registry.rs
    crates/gosling-ffi/build.rs)

#
# code coverage
#
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/tarpaulin/tarpaulin-report.html
    DEPENDS ${crate_sources}
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out Html --output-dir ${CMAKE_CURRENT_BINARY_DIR}/tarpaulin --timeout 600
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(gosling_cargo_tarpaulin
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/tarpaulin/tarpaulin-report.html
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# offline code coverage
#
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/tarpaulin-offline/tarpaulin-report.html
    DEPENDS ${crate_sources}
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out Html --output-dir ${CMAKE_CURRENT_BINARY_DIR}/tarpaulin-offline --features tor-interface/offline-test gosling/offline-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(gosling_cargo_tarpaulin_offline
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/tarpaulin-offline/tarpaulin-report.html
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/tarpaulin-offline/tarpaulin-report.html
    DESTINATION pages
    RENAME coverage.html)

#
# crate linting
#
add_custom_target(gosling_cargo_clippy
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo clippy
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

#
# crate documentation
#
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/doc
    DEPENDS ${crate_sources}
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo doc --no-deps --workspace --exclude gosling-ffi
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/crates)

add_custom_target(gosling_cargo_doc
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/doc)

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doc/
    DESTINATION pages/crates)

set(gosling_python_bindings_sources
    build_python_bindings.rs
    Cargo.toml
    cgosling.py.handlebars
    ${CARGO_TARGET_DIR}/cgosling.json)

set(gosling_python_bindings_outputs
    ${CMAKE_CURRENT_BINARY_DIR}/cgosling.py)

#
# generate cgosling.py using handlebars
#
add_custom_command(
    DEPENDS ${gosling_python_bindings_sources} cgosling_target
    OUTPUT ${gosling_python_bindings_outputs}
    COMMAND  env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo run --bin build_python_bindings ${CARGO_TARGET_DIR}/cgosling.json cgosling.py.handlebars ${CMAKE_CURRENT_BINARY_DIR}/cgosling.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target(gosling_python_bindings_target ALL
    DEPENDS ${gosling_python_bindings_outputs})
add_subdirectory(crates)

#
# code coverage
#
add_custom_command(
    OUTPUT ${CARGO_TARGET_DIR}/tarpaulin/tarpaulin-report.html
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out html --output-dir ${CARGO_TARGET_DIR}/tarpaulin --timeout 600
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(gosling_cargo_tarpaulin_target
    DEPENDS ${CARGO_TARGET_DIR}/tarpaulin/tarpaulin-report.html
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# Install Rust test code-coverage report
#
add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/website/coverage.html
    DEPENDS ${CARGO_TARGET_DIR}/tarpaulin/tarpaulin-report.html
    COMMAND mkdir -p ${CMAKE_INSTALL_PREFIX}/website
    COMMAND cp ${CARGO_TARGET_DIR}/tarpaulin/tarpaulin-report.html ${CMAKE_INSTALL_PREFIX}/website/coverage.html
)

add_custom_target(install_gosling_code_coverage
    DEPENDS ${CMAKE_INSTALL_PREFIX}/website/coverage.html gosling_cargo_tarpaulin_target
)

#
# offline code coverage
#
add_custom_command(
    OUTPUT ${CARGO_TARGET_DIR}/tarpaulin-offline/tarpaulin-report.html
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out html --output-dir ${CARGO_TARGET_DIR}/tarpaulin-offline --features tor-interface/offline-test gosling/offline-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(gosling_cargo_tarpaulin_offline
    DEPENDS ${CARGO_TARGET_DIR}/tarpaulin-offline/tarpaulin-report.html
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# crate linting
#
add_custom_target(gosling_cargo_clippy
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo clippy
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

#
# crate documentation
#
add_custom_command(
    OUTPUT ${CARGO_TARGET_DIR}/doc
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo doc --no-deps --workspace --exclude cgosling
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/crates)

add_custom_target(gosling_cargo_doc
    DEPENDS ${CARGO_TARGET_DIR}/doc)

#
# Install Rust crate documenation
#
add_custom_command(
    DEPENDS gosling_cargo_doc
    OUTPUT ${CMAKE_INSTALL_PREFIX}/website/crates
    COMMAND mkdir -p ${CMAKE_INSTALL_PREFIX}/website/crates
    COMMAND cp -r ${CARGO_TARGET_DIR}/doc/* ${CMAKE_INSTALL_PREFIX}/website/crates/.
)
add_custom_target(install_crate_docs
    DEPENDS ${CMAKE_INSTALL_PREFIX}/website/crates
)

add_subdirectory(crates)

find_program(CARGO_TARPAULIN_EXECUTABLE NAMES cargo-tarpaulin)

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    message(WARNING "Debug symbols not available; will not generate Rust test coverage")
elseif (NOT CARGO_TARPAULIN_EXECUTABLE)
    message(WARNING "Could not find cargo-tarpaulin; will not generate Rust test coverage")
else()

    #
    # Code coverage
    #
    add_custom_command(
        OUTPUT ${CARGO_TARGET_DIR}/tarpaulin/coverage.html
        COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out html --output-dir ${CARGO_TARGET_DIR}/tarpaulin --timeout 600
        COMMAND mv ${CARGO_TARGET_DIR}/tarpaulin/tarpaulin-report.html ${CARGO_TARGET_DIR}/tarpaulin/coverage.html
        COMMAND ${CMAKE_COMMAND} -E echo "Test Coverage Report: ${CARGO_TARGET_DIR}/tarpaulin/coverage.html"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_custom_target(gosling_cargo_tarpaulin
        DEPENDS ${CARGO_TARGET_DIR}/tarpaulin/coverage.html
    )

    #
    # Code coverage (offline)
    #
    add_custom_command(
        OUTPUT ${CARGO_TARGET_DIR}/tarpaulin/coverage-offline.html
        COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out html --output-dir ${CARGO_TARGET_DIR}/tarpaulin --features tor-interface/offline-test gosling/offline-test cgosling/offline-test
        COMMAND mv ${CARGO_TARGET_DIR}/tarpaulin/tarpaulin-report.html ${CARGO_TARGET_DIR}/tarpaulin/coverage-offline.html
        COMMAND ${CMAKE_COMMAND} -E echo "Test Coverage Report: ${CARGO_TARGET_DIR}/tarpaulin/coverage-offline.html"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_custom_target(gosling_cargo_tarpaulin_offline
        DEPENDS ${CARGO_TARGET_DIR}/tarpaulin/coverage-offline.html
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    #
    # Deploy Rust test code-coverage reports to website
    #
    add_custom_command(
        OUTPUT ${CMAKE_INSTALL_PREFIX}/website/coverage.html ${CMAKE_INSTALL_PREFIX}/website/coverage-offline.html
        DEPENDS ${CARGO_TARGET_DIR}/tarpaulin/coverage.html ${CARGO_TARGET_DIR}/tarpaulin/coverage-offline.html
        COMMAND mkdir -p ${CMAKE_INSTALL_PREFIX}/website
        COMMAND cp ${CARGO_TARGET_DIR}/tarpaulin/coverage.html ${CMAKE_INSTALL_PREFIX}/website/coverage.html
        COMMAND cp ${CARGO_TARGET_DIR}/tarpaulin/coverage-offline.html ${CMAKE_INSTALL_PREFIX}/website/coverage-offline.html
    )
    add_custom_target(deploy_gosling_test_coverage_website_target
        DEPENDS ${CMAKE_INSTALL_PREFIX}/website/coverage.html ${CMAKE_INSTALL_PREFIX}/website/coverage-offline.html
    )
    add_dependencies(website_target deploy_gosling_test_coverage_website_target)
endif()

#
# Run crate linting
#
add_custom_target(gosling_cargo_clippy
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo clippy
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

#
# Build crate documentation
#
add_custom_command(
    OUTPUT ${CARGO_TARGET_DIR}/doc
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo doc --no-deps --workspace --exclude cgosling
    COMMAND ${CMAKE_COMMAND} -E echo "Rust Crate Documentation: ${CARGO_TARGET_DIR}/doc/gosling/index.html"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/crates)

add_custom_target(gosling_cargo_doc_target
    DEPENDS ${CARGO_TARGET_DIR}/doc)

#
# Deploy Rust crate documenation to website
#
add_custom_command(
    DEPENDS gosling_cargo_doc_target
    OUTPUT ${CMAKE_INSTALL_PREFIX}/website/crates
    COMMAND mkdir -p ${CMAKE_INSTALL_PREFIX}/website/crates
    COMMAND cp -r ${CARGO_TARGET_DIR}/doc/* ${CMAKE_INSTALL_PREFIX}/website/crates/.
)
add_custom_target(deploy_crate_docs_website_target
    DEPENDS ${CMAKE_INSTALL_PREFIX}/website/crates
)
add_dependencies(website_target deploy_crate_docs_website_target)


# ensure we have required Rust components
find_program(RUSTC_EXECUTABLE NAMES rustc)
find_program(CARGO_EXECUTABLE NAMES cargo)
find_program(CARGO_TARPAULIN_EXECUTABLE NAMES cargo-tarpaulin)
find_program(CARGO_SBOM_EXECUTABLE NAMES cargo-sbom)
find_program(CARGO_FUZZ_EXECUTABLE NAMES cargo-fuzz)

if (NOT RUSTC_EXECUTABLE)
    message(FATAL_ERROR "rustc not found; required to build gosling")
elseif (NOT CARGO_EXECUTABLE)
    message(FATAL_ERROR "cargo not found; required to build gosling")
elseif (NOT CARGO_TARPAULIN_EXECUTABLE AND BUILD_PAGES)
    message(FATAL_ERROR "cargo-tarpaulin not found; required to generate Rust test coverage and build pages")
elseif (NOT CARGO_SBOM_EXECUTABLE AND BUILD_PAGES)
    message(FATAL_ERROR "cargo-sbom not found; required to generate gosling software bill of materials and build pages")
elseif (NOT CARGO_FUZZ_EXECUTABLE AND ENABLE_FUZZ_TESTS)
    message(FATAL_ERROR "cargo-fuzz not found; required to run fuzz tests")
endif()

add_subdirectory(crates)

if (BUILD_PAGES)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        message(FATAL_ERROR "Debug symbols not available; required to generate Rust test coverage")
    endif()

    #
    # code-coverage feature flags
    #
    set(TARPAULIN_FEATURES_LIST)
    if (ENABLE_MOCK_TOR_PROVIDER)
        list(APPEND TARPAULIN_FEATURES_LIST "tor-interface/mock-tor-provider")
        list(APPEND TARPAULIN_FEATURES_LIST "gosling/mock-tor-provider")
        list(APPEND TARPAULIN_FEATURES_LIST "cgosling/mock-tor-provider")
    endif()
    if (ENABLE_LEGACY_TOR_PROVIDER)
        list(APPEND TARPAULIN_FEATURES_LIST "tor-interface/legacy-tor-provider")
        list(APPEND TARPAULIN_FEATURES_LIST "gosling/legacy-tor-provider")
        list(APPEND TARPAULIN_FEATURES_LIST "cgosling/legacy-tor-provider")
    endif()
    if (ENABLE_ARTI_CLIENT_TOR_PROVIDER)
        list(APPEND TARPAULIN_FEATURES_LIST "tor-interface/arti-client-tor-provider")
        list(APPEND TARPAULIN_FEATURES_LIST "gosling/arti-client-tor-provider")
        list(APPEND TARPAULIN_FEATURES_LIST "cgosling/arti-client-tor-provider")
    endif()
    if (ENABLE_ARTI_TOR_PROVIDER)
        list(APPEND TARPAULIN_FEATURES_LIST "tor-interface/arti-client-tor-provider")
    endif()

    list(JOIN TARPAULIN_FEATURES_LIST "," TARPAULIN_FEATURES)
    if (TARPAULIN_FEATURES)
        set(TARPAULIN_FEATURES "--features" "\"${TARPAULIN_FEATURES}\"")
    endif()

    #
    # Code coverage
    #
    add_custom_command(
        OUTPUT ${CARGO_TARGET_DIR}/tarpaulin/coverage.html
        COMMAND TEB_PATH=${TEB_PATH} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out html --output-dir ${CARGO_TARGET_DIR}/tarpaulin --timeout 1800 ${TARPAULIN_FEATURES}
        COMMAND mv ${CARGO_TARGET_DIR}/tarpaulin/tarpaulin-report.html ${CARGO_TARGET_DIR}/tarpaulin/coverage.html
        COMMAND ${CMAKE_COMMAND} -E echo "Test Coverage Report: ${CARGO_TARGET_DIR}/tarpaulin/coverage.html"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_custom_target(gosling_cargo_tarpaulin ALL
        DEPENDS ${CARGO_TARGET_DIR}/tarpaulin/coverage.html
    )
    if (ENABLE_TOR_EXPERT_BUNDLE)
        add_dependencies(gosling_cargo_tarpaulin tor_expert_bundle_target)
    endif()

    #
    # Install code coverage pages
    #
    install(FILES
        ${CARGO_TARGET_DIR}/tarpaulin/coverage.html
        DESTINATION ${CMAKE_INSTALL_DOCDIR})

    #
    # Build crate documentation
    #
    add_custom_command(
        OUTPUT ${CARGO_TARGET_DIR}/doc
        COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo doc --no-deps --package honk-rpc --all-features
        COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo doc --no-deps --package tor-interface --all-features
        COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo doc --no-deps --package gosling --all-features
        COMMAND ${CMAKE_COMMAND} -E echo "Rust Crate Documentation: ${CARGO_TARGET_DIR}/doc/gosling/index.html"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/crates)
    add_custom_target(gosling_cargo_doc_target ALL
        DEPENDS ${CARGO_TARGET_DIR}/doc
    )

    #
    # Install crate documentation pages
    #
    install(DIRECTORY ${CARGO_TARGET_DIR}/doc/
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/crates)

    #
    # Build software bill of materials (SBOM) using cargo-sbom:
    # - https://docs.rs/crate/cargo-sbom/latest
    #
    add_custom_command(
        OUTPUT ${CARGO_TARGET_DIR}/gosling.spdx.json
        COMMAND cargo sbom > ${CARGO_TARGET_DIR}/gosling.spdx.json
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_custom_target(gosling_cargo_sbom_target ALL
        DEPENDS ${CARGO_TARGET_DIR}/gosling.spdx.json
    )

    #
    # Instal sbom
    #
    install(FILES ${CARGO_TARGET_DIR}/gosling.spdx.json
        DESTINATION ${CMAKE_INSTALL_DOCDIR})

endif()

if (ENABLE_LINTING)
    #
    # Run crate linting
    #
    add_custom_target(gosling_cargo_clippy
        COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo clippy
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_dependencies(linting gosling_cargo_clippy)
endif()

if (ENABLE_FORMATTING)
    #
    # Run rust formatting
    #
    add_custom_target(format_rust_source
        COMMAND cargo fmt
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_dependencies(format format_rust_source)
endif()
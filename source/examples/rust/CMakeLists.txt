if (BUILD_EXAMPLES AND ENABLE_LEGACY_TOR_PROVIDER)

    #
    # Build example_chat_rs binary
    #

    set(example_chat_rs_sources
        Cargo.toml
        src/commands.rs
        src/globals.rs
        src/main.rs
        src/terminal.rs)

    set(example_chat_rs_outputs
        ${CMAKE_CURRENT_BINARY_DIR}/${CARGO_PROFILE}/example_chat_rs${CMAKE_EXECUTABLE_SUFFIX})

    add_custom_command(
        DEPENDS ${example_chat_rs_sources}
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${CARGO_PROFILE}/example_chat_rs${CMAKE_EXECUTABLE_SUFFIX}
        COMMAND env CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

    add_custom_target(example_chat_rs_target ALL
        DEPENDS ${example_chat_rs_outputs})
    add_dependencies(example_chat_rs_target gosling_target)

    #
    # Install example_chat_rs binary
    #

    install(PROGRAMS
        ${example_chat_rs_outputs}
        TYPE BIN)
endif()

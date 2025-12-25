if (BUILD_PYTHON_BINDINGS)

    set(gosling_python_bindings_sources
        ${PROFILE_DIR}/cgosling.json
        build_python_bindings.rs
        Cargo.toml
        cgosling.py.handlebars)

    set(gosling_python_bindings_outputs
        ${CMAKE_CURRENT_BINARY_DIR}/cgosling.py)

    #
    # generate cgosling.py using handlebars
    #
    add_custom_command(
        DEPENDS ${gosling_python_bindings_sources}
        OUTPUT ${gosling_python_bindings_outputs}
        COMMAND  env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo run ${CARGO_FLAGS} --bin build_python_bindings ${PROFILE_DIR}/cgosling.json cgosling.py.handlebars ${CMAKE_CURRENT_BINARY_DIR}/cgosling.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_custom_target(gosling_python_bindings_target ALL
        DEPENDS ${gosling_python_bindings_outputs})
    add_dependencies(gosling_python_bindings_target gosling_c_shared_bindings)

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cgosling.py
        DESTINATION ${CMAKE_INSTALL_DATADIR}/gosling/bindings/python
    )

endif()

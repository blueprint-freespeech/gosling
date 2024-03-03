if (ENABLE_TESTS)
    if (NOT TARGET Catch2::Catch2WithMain)
        message(FATAL_ERROR "Catch2 3 or newer not found; required for gosling_unit_test")
    endif()
    add_executable(gosling_unit
        precomp.cpp
        test.cpp)
    target_precompile_headers(gosling_unit PRIVATE precomp.hpp)

    target_link_libraries(gosling_unit PRIVATE gosling_cpp_shared_bindings)
    target_link_libraries(gosling_unit PRIVATE Catch2::Catch2WithMain)

    # create soft-link to dependent cgosling.dll on Windows
    if(WINDOWS)
        add_custom_command(TARGET gosling_unit POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE:gosling_c_shared_bindings> $<TARGET_FILE_NAME:gosling_c_shared_bindings>
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        )
    endif()

    add_test(NAME gosling_unit_test
        COMMAND gosling_unit
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    if (ENABLE_FORMATTING)
        add_format_target(format_unit_target ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
endif()

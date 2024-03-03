if (ENABLE_TESTS AND ENABLE_ONLINE_TESTS)
    find_package(Boost 1.66.0)

    if (NOT TARGET Catch2::Catch2WithMain)
        message(FATAL_ERROR "Catch2 3 or newer not found; required for gosling_functional_test")
    elseif (NOT Boost_FOUND)
        message(FATAL_ERROR "Boost 1.66 or newer not found; required for gosling_functional_test")
    endif()

    add_executable(gosling_functional
        precomp.cpp
        test.cpp)
    target_precompile_headers(gosling_functional PRIVATE precomp.hpp)

    target_include_directories(gosling_functional PRIVATE ${Boost_INCLUDE_DIRS})

    target_link_libraries(gosling_functional PRIVATE gosling_cpp_shared_bindings)
    target_link_libraries(gosling_functional PRIVATE Catch2::Catch2WithMain)

    if(WINDOWS)
        target_link_libraries(gosling_functional PRIVATE ws2_32)
    endif()

    target_compile_features(gosling_functional PRIVATE cxx_std_17)

    # create soft-link to dependent cgosling.dll on Windows
    if(WINDOWS)
        add_custom_command(TARGET gosling_functional POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE:gosling_c_shared_bindings> $<TARGET_FILE_NAME:gosling_c_shared_bindings>
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        )
    endif()

    add_test(NAME gosling_functional_test
        COMMAND gosling_functional
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    if (ENABLE_FORMATTING)
        add_format_target(format_functional_target ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
endif()

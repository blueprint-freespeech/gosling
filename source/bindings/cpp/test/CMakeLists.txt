find_package(Boost 1.66.0)

if (NOT TARGET Catch2::Catch2WithMain)
    message(FATAL_ERROR "Catch2 3 or newer not found; required for gosling_cpp_bindings_test")
elseif (NOT Boost_FOUND)
    message(FATAL_ERROR "Boost 1.66 or newer not found; required for gosling_cpp_bindings_test")
endif()

add_executable(gosling_cpp_bindings_test_target
    precomp.cpp
    tor_crypto.cpp
    tor_provider.cpp)
set_target_properties(gosling_cpp_bindings_test_target
    PROPERTIES OUTPUT_NAME gosling_cpp_bindings_test)
target_precompile_headers(gosling_cpp_bindings_test_target PRIVATE precomp.hpp)

target_include_directories(gosling_cpp_bindings_test_target PRIVATE ${Boost_INCLUDE_DIRS})

target_link_libraries(gosling_cpp_bindings_test_target PRIVATE gosling_cpp_shared_bindings)
target_link_libraries(gosling_cpp_bindings_test_target PRIVATE Catch2::Catch2WithMain)

if(WINDOWS)
    target_link_libraries(gosling_cpp_bindings_test_target PRIVATE ws2_32)
endif()

target_compile_features(gosling_cpp_bindings_test_target PRIVATE cxx_std_17)


# create soft-link to dependent cgosling.dll on Windows
if(WINDOWS)
    add_custom_command(TARGET gosling_cpp_bindings_test_target POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE:gosling_c_shared_bindings> $<TARGET_FILE_NAME:gosling_c_shared_bindings>
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()

add_test(NAME gosling_cpp_bindings_test_build
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --config $<CONFIG> --target gosling_cpp_bindings_test_target
)
set_tests_properties(gosling_cpp_bindings_test_build PROPERTIES FIXTURES_SETUP gosling_cpp_bindings_test_fixture)
add_test(NAME gosling_cpp_bindings_test
    COMMAND gosling_cpp_bindings_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(gosling_cpp_bindings_test PROPERTIES FIXTURES_REQUIRED gosling_cpp_bindings_test_fixture)

if (ENABLE_FORMATTING)
    add_format_target(format_unit_target ${CMAKE_CURRENT_SOURCE_DIR})
endif()

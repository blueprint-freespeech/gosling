add_executable(gosling_unit EXCLUDE_FROM_ALL
    precomp.cpp
    test.cpp)
target_precompile_headers(gosling_unit PRIVATE precomp.hpp)

target_link_libraries(gosling_unit PRIVATE gosling_cpp_shared_bindings)
target_link_libraries(gosling_unit PRIVATE Catch2::Catch2WithMain)

add_custom_target(gosling_unit_test_target
    COMMAND ${CMAKE_COMMAND} -E copy
            $<TARGET_FILE:gosling_c_shared_bindings>
            ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND gosling_unit
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
add_dependencies(gosling_unit_test_target gosling_unit)
add_dependencies(test_target gosling_unit_test_target)
add_dependencies(test_offline_target gosling_unit_test_target)

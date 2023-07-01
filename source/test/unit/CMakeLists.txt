add_executable(gosling_unit
    precomp.cpp
    test.cpp)
target_precompile_headers(gosling_unit PRIVATE precomp.hpp)

target_link_libraries(gosling_unit PRIVATE gosling_ffi)
target_link_libraries(gosling_unit PRIVATE Catch2::Catch2WithMain)

add_custom_target(gosling_unit_test
    COMMAND ./gosling_unit
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
add_dependencies(gosling_unit_test gosling_unit)

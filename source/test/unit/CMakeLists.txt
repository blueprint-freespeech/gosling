
add_executable(gosling_unit_test
    precomp.cpp
    test.cpp)
target_precompile_headers(gosling_unit_test PRIVATE precomp.hpp)

target_link_libraries(gosling_unit_test PRIVATE gosling_ffi)
target_link_libraries(gosling_unit_test PRIVATE Catch2::Catch2WithMain)

add_test(NAME unit_test
    COMMAND ./gosling_unit_test
)
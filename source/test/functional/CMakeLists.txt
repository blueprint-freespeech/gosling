
add_executable(gosling_functional_test
    precomp.cpp
    test.cpp)
target_precompile_headers(gosling_functional_test PRIVATE precomp.hpp)

target_link_libraries(gosling_functional_test PRIVATE gosling)
target_link_libraries(gosling_functional_test PRIVATE Catch2::Catch2WithMain)

add_test(NAME functional_test
    COMMAND ./gosling_functional_test
)
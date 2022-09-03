find_package(Boost 1.66.0 REQUIRED)

add_executable(gosling_functional_test
    precomp.cpp
    test.cpp)
target_precompile_headers(gosling_functional_test PRIVATE precomp.hpp)

target_include_directories(gosling_functional_test PRIVATE ${Boost_INCLUDE_DIRS})

target_link_libraries(gosling_functional_test PRIVATE gosling)
target_link_libraries(gosling_functional_test PRIVATE Catch2::Catch2WithMain)

target_compile_features(gosling_functional_test PRIVATE cxx_std_17)

add_test(NAME functional_test
    COMMAND ./gosling_functional_test
)
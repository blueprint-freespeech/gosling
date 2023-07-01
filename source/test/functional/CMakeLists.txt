find_package(Boost 1.66.0 REQUIRED)

add_executable(gosling_functional
    precomp.cpp
    test.cpp)
target_precompile_headers(gosling_functional PRIVATE precomp.hpp)

target_include_directories(gosling_functional PRIVATE ${Boost_INCLUDE_DIRS})

target_link_libraries(gosling_functional PRIVATE gosling_ffi)
target_link_libraries(gosling_functional PRIVATE Catch2::Catch2WithMain)

target_compile_features(gosling_functional PRIVATE cxx_std_17)

add_custom_target(gosling_functional_test
    COMMAND ./gosling_functional
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
add_dependencies(gosling_functional_test gosling_functional)

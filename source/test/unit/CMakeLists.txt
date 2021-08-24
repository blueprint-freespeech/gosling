add_executable(gosling_unit_test
    test.cpp)

# add_dependencies(gosling_unit_test gosling)

target_link_libraries(gosling_unit_test gosling)


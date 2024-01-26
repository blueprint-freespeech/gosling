find_package(Boost 1.66.0)

if (NOT Boost_FOUND)
    message(WARNING "Boost 1.66 or newer not found; will not build gosling_functional_test")
else()
    add_executable(gosling_functional EXCLUDE_FROM_ALL
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

    add_custom_target(gosling_functional_test
        COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE:gosling_c_shared_bindings>
                ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND gosling_functional
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    add_dependencies(gosling_functional_test gosling_functional)

endif()
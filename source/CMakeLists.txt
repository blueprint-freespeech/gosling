cmake_minimum_required(VERSION 3.16.6)

# cmake variables reference: https://cmake.org/cmake/help/v3.21/manual/cmake-variables.7.html

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()

# enable tests
enable_testing()
list(APPEND CMAKE_CTEST_ARGUMENTS "--output-on-failure")

project(gosling)

# toggle to enable debug spew
set(CMAKE_VERBOSE_MAKEFILE on)

add_subdirectory(tor_crypto)
add_subdirectory(gosling)
add_subdirectory(Catch2)
add_subdirectory(test)


cmake_minimum_required(VERSION 3.17)

# cmake variables reference: https://cmake.org/cmake/help/v3.21/manual/cmake-variables.7.html

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()

if(UNIX AND APPLE)
    set(MACOS TRUE)
endif()

if(WIN32)
    set(WINDOWS TRUE)
endif()

project(gosling)

# toggle to enable debug spew
set(CMAKE_VERBOSE_MAKEFILE on)
# enable link-time optimization
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

add_subdirectory(gosling)
add_subdirectory(Catch2)
add_subdirectory(test)
add_subdirectory(pages)


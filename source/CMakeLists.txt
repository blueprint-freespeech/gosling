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

# translate our cmake build type to a cargo profile and build flags
if((DEFINED CMAKE_BUILD_TYPE))
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CARGO_PROFILE debug)
    elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CARGO_PROFILE release)
        set(CARGO_FLAGS --release)
        set(RUSTFLAGS "-C strip=symbols")
    elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        set(CARGO_PROFILE release)
        set(CARGO_FLAGS --release)
        set(RUSTFLAGS "-g")
    elseif(CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
        set(CARGO_PROFILE release)
        set(CARGO_FLAGS --release)
        set(RUSTFLAGS "-C opt-level=z -C strip=symbols")
    endif()
else()
    set(CARGO_PROFILE debug)
endif()

set(CARGO_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/gosling)

add_subdirectory(gosling)
add_subdirectory(Catch2)
add_subdirectory(test)
add_subdirectory(pages)
add_subdirectory(bindings)

include(GNUInstallDirs)

# translate our cmake build type to a cargo profile and build flags
if(CMAKE_BUILD_TYPE)
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
    else()
        message(FATAL_ERROR "CMAKE_BUILD_TYPE not defined")
    endif()
else()
    message(FATAL_ERROR "CMAKE_BUILD_TYPE not defined")
endif()

set(CARGO_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/gosling)


# # main build target needed for install
# add_custom_target(build_target)
# # runs all tests (requires internet access)
# add_custom_target(test_target)
# # runs the offline tests using mock tor provider
# add_custom_target(test_offline_target)
# # builds the documentation website
# add_custom_target(website_target)

add_subdirectory(gosling)
add_subdirectory(extern)
add_subdirectory(test)
add_subdirectory(pages)
add_subdirectory(bindings)
add_subdirectory(examples)
add_subdirectory(packages)

# translate our cmake build type to a cargo profile
if((DEFINED CMAKE_BUILD_TYPE))
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CARGO_PROFILE debug)
    elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CARGO_PROFILE release)
        set(CARGO_FLAGS --release)
    elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        set(CARGO_PROFILE release)
        set(CARGO_FLAGS --release)
        set(RUSTFLAGS "-g")
    elseif(CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
        set(CARGO_PROFILE release)
        set(CARGO_FLAGS --release)
        set(RUSTFLAGS "-C opt-level=z")
    endif()
else()
    set(CARGO_PROFILE debug)
endif()

add_subdirectory(honk-rpc)
add_subdirectory(tor-interface)
add_subdirectory(gosling)
add_subdirectory(gosling-ffi)

add_custom_target(gosling_cargo_doc
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo doc --no-deps --workspace --exclude gosling-ffi
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS
)


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

# invokes cargo build
add_custom_target(gosling_target
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${CARGO_PROFILE} ${CMAKE_CURRENT_BINARY_DIR}/include
)

# create gosling library target
add_library(gosling STATIC IMPORTED GLOBAL)
# which depends on the above command target
add_dependencies(gosling gosling_target)

# create include directory ahead of time or else cmake falls over
set(GOSLING_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
file(MAKE_DIRECTORY ${GOSLING_INCLUDE_DIR})
# define our binary directory
set(GOSLING_LIBRARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/${CARGO_PROFILE})

# specify goslings link target for consumers
set_target_properties(gosling PROPERTIES
    IMPORTED_LOCATION ${GOSLING_LIBRARY_DIR}/libgosling.a
)

# include location of our cbindgen headers
target_include_directories(gosling INTERFACE ${GOSLING_INCLUDE_DIR})

# Linux targets needed by rust runtime
if(LINUX)
    target_link_libraries(gosling INTERFACE pthread)
    target_link_libraries(gosling INTERFACE dl)
endif()

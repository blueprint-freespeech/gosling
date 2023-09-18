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

set(CARGO_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(crates)

#
# code coverage
#
add_custom_command(
    OUTPUT ${CARGO_TARGET_DIR}/tarpaulin/tarpaulin-report.html
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out html --output-dir ${CARGO_TARGET_DIR}/tarpaulin --timeout 600
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(gosling_cargo_tarpaulin
    DEPENDS ${CARGO_TARGET_DIR}/tarpaulin/tarpaulin-report.html
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

install(FILES ${CARGO_TARGET_DIR}/tarpaulin/tarpaulin-report.html
    DESTINATION pages
    RENAME coverage.html)

#
# offline code coverage
#
add_custom_command(
    OUTPUT ${CARGO_TARGET_DIR}/tarpaulin-offline/tarpaulin-report.html
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo tarpaulin --out html --output-dir ${CARGO_TARGET_DIR}/tarpaulin-offline --features tor-interface/offline-test gosling/offline-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(gosling_cargo_tarpaulin_offline
    DEPENDS ${CARGO_TARGET_DIR}/tarpaulin-offline/tarpaulin-report.html
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# crate linting
#
add_custom_target(gosling_cargo_clippy
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo clippy
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

#
# crate documentation
#
add_custom_command(
    OUTPUT ${CARGO_TARGET_DIR}/doc
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo doc --no-deps --workspace --exclude gosling-ffi
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/crates)

add_custom_target(gosling_cargo_doc
    DEPENDS ${CARGO_TARGET_DIR}/doc)

install(DIRECTORY ${CARGO_TARGET_DIR}/doc/
    DESTINATION pages/crates)

set(CGOSLING_MAJOR_VERSION "0" CACHE STRING "SemVer major version of cgosling library" FORCE)
set(CGOSLING_MINOR_VERSION "2" CACHE STRING "SemVer minor version of cgosling library" FORCE)
set(CGOSLING_PATCH_VERSION "2" CACHE STRING "SemVer patch version of cgosling library" FORCE)
set(CGOSLING_VERSION "${CGOSLING_MAJOR_VERSION}.${CGOSLING_MINOR_VERSION}.${CGOSLING_PATCH_VERSION}" CACHE STRING "SemVer of the cgosling library" FORCE)

# generate Cargo.toml file
set(CARGO_TOML_IN ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml.in)
set(CARGO_TOML_OUT ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml)
configure_file(${CARGO_TOML_IN} ${CARGO_TOML_OUT} @ONLY)

set(cgosling_sources
    build.rs
    Cargo.toml
    cbindgen.toml
    src/callbacks.rs
    src/context.rs
    src/crypto.rs
    src/error.rs
    src/ffi.rs
    src/lib.rs
    src/object_registry.rs
    src/tor_provider.rs
    src/utils.rs)

# The name of the static library built by rust
set(CGOSLING_SRC_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}cgosling${CMAKE_STATIC_LIBRARY_SUFFIX}" CACHE STRING "cgosling static library filename" FORCE)
# The name we use for the static cgosling bindings
set(CGOSLING_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}cgosling_static${CMAKE_STATIC_LIBRARY_SUFFIX}" CACHE STRING "cgosling static library filename" FORCE)
# The naem we use for the _impl suffixed version of the static cgosling bindings
set(CGOSLING_IMPL_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}cgosling_impl${CMAKE_STATIC_LIBRARY_SUFFIX}" CACHE STRING "cgosling static impl library filename" FORCE)

set(cgosling_static_outputs
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.h
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.json
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_STATIC}
)

set(cgosling_impl_outputs
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_IMPL_STATIC}
)

#
# cgosling crate feature flags
#
set(CGOSLING_FEATURES_LIST)
if (ENABLE_MOCK_TOR_PROVIDER)
    list(APPEND CGOSLING_FEATURES_LIST "mock-tor-provider")
endif()
if (ENABLE_LEGACY_TOR_PROVIDER)
    list(APPEND CGOSLING_FEATURES_LIST "legacy-tor-provider")
endif()

list(JOIN CGOSLING_FEATURES_LIST "," CGOSLING_FEATURES)
if (CGOSLING_FEATURES)
    set(CGOSLING_FEATURES "--features" "${CGOSLING_FEATURES}")
endif()

#
# build cgosling static lib target
#
add_custom_command(
    DEPENDS ${cgosling_sources}
    OUTPUT ${cgosling_static_outputs}
    COMMAND ${CMAKE_COMMAND} -E touch ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.h
    COMMAND ${CMAKE_COMMAND} -E touch ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.json
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS} ${CGOSLING_FEATURES}
    COMMAND ${CMAKE_COMMAND} -E rename ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SRC_STATIC} ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_STATIC}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# cargo test target
#
if (ENABLE_TESTS)
    add_test(NAME cgosling_cargo_test
        COMMAND env TEB_PATH=${TEB_PATH} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS} ${CGOSLING_FEATURES} -- --nocapture
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    if (ENABLE_TOR_EXPERT_BUNDLE)
        set_tests_properties(cgosling_cargo_test PROPERTIES FIXTURES_REQUIRED tor_expert_bundle_target_fixture)
    endif()
endif()

#
# fuzz targets
#
if (ENABLE_FUZZ_TESTS)
    add_test(NAME cgosling_cargo_fuzz_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_cgosling -- -max_total_time=${FUZZ_TEST_MAX_TOTAL_TIME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

#
# build cgosling impl lib target
#
list(APPEND CGOSLING_FEATURES_LIST "impl-lib")
list(JOIN CGOSLING_FEATURES_LIST "," CGOSLING_FEATURES)
set(CGOSLING_FEATURES "--features" "\"${CGOSLING_FEATURES}\"")

add_custom_command(
    DEPENDS ${cgosling_static_outputs} ${cgosling_sources}
    OUTPUT ${cgosling_impl_outputs}
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS} ${CGOSLING_FEATURES}
    COMMAND ${CMAKE_COMMAND} -E rename ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SRC_STATIC} ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_IMPL_STATIC}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(cgosling_target
    DEPENDS ${cgosling_static_outputs} ${cgosling_impl_outputs})
add_dependencies(cgosling_target gosling_target)

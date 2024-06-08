include(CheckLinkerFlag)

#
# Generate cgosling.h
#

set(gosling_c_header_sources
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.json
    build_c_bindings.rs
    Cargo.toml
    cgosling.h.handlebars)

add_custom_command(
    DEPENDS ${gosling_c_header_sources}
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cgosling.h
    # generate c header
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo run ${CARGO_FLAGS} --bin build_c_bindings ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.json cgosling.h.handlebars ${CMAKE_CURRENT_BINARY_DIR}/cgosling.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target(gosling_c_header_target
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cgosling.h)
add_dependencies(gosling_c_header_target cgosling_target)
if (ENABLE_LINTING)
    add_dependencies(cppcheck_target gosling_c_header_target)
endif()

#
# Static Library
#

add_custom_command(
    DEPENDS ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_STATIC}
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${CGOSLING_STATIC}
    # copy cargo-built static lib to current directory
    COMMAND ${CMAKE_COMMAND} -E copy ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_STATIC} ${CMAKE_CURRENT_BINARY_DIR}/${CGOSLING_STATIC}
)
add_custom_target(gosling_c_static_lib_target
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${CGOSLING_STATIC})
add_dependencies(gosling_c_static_lib_target cgosling_target)

add_library(gosling_c_static_bindings STATIC IMPORTED GLOBAL)
add_dependencies(gosling_c_static_bindings gosling_c_header_target)
add_dependencies(gosling_c_static_bindings gosling_c_static_lib_target)

target_include_directories(gosling_c_static_bindings INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
set_target_properties(gosling_c_static_bindings PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${CGOSLING_STATIC}
)

if(WINDOWS)
    target_link_libraries(gosling_c_static_bindings INTERFACE ws2_32)
    target_link_libraries(gosling_c_static_bindings INTERFACE userenv)
    target_link_libraries(gosling_c_static_bindings INTERFACE bcrypt)
    target_link_libraries(gosling_c_static_bindings INTERFACE ntdll)
endif()

add_custom_target(gosling_c_static_bindings_target ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cgosling.h ${CMAKE_CURRENT_BINARY_DIR}/${CGOSLING_STATIC})
add_dependencies(gosling_c_static_bindings_target gosling_c_static_bindings)

#
# Shared Library
#

# generate cgosling.c
set(gosling_c_shared_bindings_sources
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.json
    build_c_bindings.rs
    Cargo.toml
    cgosling.c.handlebars)

# cgosling.c forwards the various public gosling calls to the _impl versions
add_custom_command(
    DEPENDS ${gosling_c_shared_bindings_sources}
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cgosling.c
    # generate c source
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo run ${CARGO_FLAGS} --bin build_c_bindings ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.json cgosling.c.handlebars ${CMAKE_CURRENT_BINARY_DIR}/cgosling.c
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target(gosling_c_shared_sources_target ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cgosling.c)
add_dependencies(gosling_c_shared_sources_target cgosling_target)

# build our shared library
add_library(gosling_c_shared_bindings SHARED ${CMAKE_CURRENT_BINARY_DIR}/cgosling.c)
add_dependencies(gosling_c_shared_bindings gosling_c_header_target gosling_c_shared_sources_target)
set_target_properties(gosling_c_shared_bindings
    PROPERTIES
    OUTPUT_NAME cgosling
    VERSION ${CGOSLING_VERSION}
    SOVERSION ${CGOSLING_MAJOR_VERSION})
target_link_libraries(gosling_c_shared_bindings PRIVATE ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_IMPL_STATIC})
if(WINDOWS)
    target_link_libraries(gosling_c_shared_bindings PRIVATE ws2_32)
    target_link_libraries(gosling_c_shared_bindings PRIVATE userenv)
    target_link_libraries(gosling_c_shared_bindings PRIVATE bcrypt)
    target_link_libraries(gosling_c_shared_bindings PRIVATE ntdll)
endif()

# check if the --exclude-libs flag is supported by the linker
check_linker_flag(C "-Wl,--exclude-libs,ALL" LINKER_SUPPORTS_EXCLUDE_LIBS)

if(LINKER_SUPPORTS_EXCLUDE_LIBS)
    # prevents the result .so from re-exporting all of the static libs symbols out of the shared library
    target_link_options(gosling_c_shared_bindings PRIVATE "-Wl,--exclude-libs,ALL")
endif()

target_include_directories(gosling_c_shared_bindings PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

add_custom_target(gosling_c_shared_bindings_target ALL)
add_dependencies(gosling_c_shared_bindings_target gosling_c_shared_bindings)

if (ENABLE_LINTING)
    add_dependencies(cppcheck_target gosling_c_shared_bindings_target)
endif()

#
# Install
#

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cgosling.h
    TYPE INCLUDE)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${CGOSLING_STATIC}
    TYPE LIB)
install(TARGETS gosling_c_shared_bindings)

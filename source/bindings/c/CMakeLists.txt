include(CheckLinkerFlag)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)

set(gosling_c_bindings_sources
    ${CARGO_TARGET_DIR}/include/cgosling.h
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_STATIC}
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_IMPL_STATIC}
)

set(gosling_c_bindings_outputs
    ${CMAKE_CURRENT_BINARY_DIR}/include/cgosling.h
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_STATIC}
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_IMPL_STATIC}
)

#
# Just copy header and libs from the cgosling crate build outputs
#
foreach(src dest IN ZIP_LISTS gosling_c_bindings_sources gosling_c_bindings_outputs)
    add_custom_command(
        DEPENDS ${src} cgosling_target
        OUTPUT ${dest}
        COMMAND  cp -P ${src} ${dest})
endforeach()

add_custom_target(gosling_c_bindings_target
    DEPENDS ${gosling_c_bindings_outputs})
add_dependencies(gosling_c_bindings_target cgosling_target)
if (ENABLE_LINTING)
    add_dependencies(linting gosling_c_bindings_target)
endif()

#
# Static Library
#

add_library(gosling_c_static_bindings STATIC IMPORTED GLOBAL)
add_dependencies(gosling_c_static_bindings gosling_c_bindings_target)

target_include_directories(gosling_c_static_bindings INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/include)
set_target_properties(gosling_c_static_bindings PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_STATIC}
)

if(WINDOWS)
    target_link_libraries(gosling_c_static_bindings INTERFACE ws2_32)
    target_link_libraries(gosling_c_static_bindings INTERFACE userenv)
    target_link_libraries(gosling_c_static_bindings INTERFACE bcrypt)
    target_link_libraries(gosling_c_static_bindings INTERFACE ntdll)
endif()

add_custom_target(gosling_c_static_bindings_target ALL)
add_dependencies(gosling_c_static_bindings_target gosling_c_static_bindings)

#
# Shared Library
#

# generate cgosling.c
set(gosling_c_shared_bindings_sources
    build_c_shared_bindings.rs
    Cargo.toml
    cgosling.c.handlebars)

# cgosling.c basically forwards the various gosling calls in the public header
# to the _impl methods
add_custom_command(
    DEPENDS ${gosling_c_shared_bindings_sources} gosling_c_bindings_target
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cgosling.c
    # generate c source
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo run ${CARGO_FLAGS} --bin build_c_shared_bindings ${CARGO_TARGET_DIR}/cgosling.json cgosling.c.handlebars ${CMAKE_CURRENT_BINARY_DIR}/cgosling.c
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# build our shared library
add_library(gosling_c_shared_bindings SHARED ${CMAKE_CURRENT_BINARY_DIR}/cgosling.c)
set_target_properties(gosling_c_shared_bindings
    PROPERTIES
    OUTPUT_NAME cgosling
    VERSION ${CGOSLING_VERSION}
    SOVERSION ${CGOSLING_MAJOR_VERSION})
target_include_directories(gosling_c_shared_bindings PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(gosling_c_shared_bindings PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_IMPL_STATIC})
if(WINDOWS)
    target_link_libraries(gosling_c_shared_bindings PRIVATE ws2_32)
    target_link_libraries(gosling_c_shared_bindings PRIVATE userenv)
    target_link_libraries(gosling_c_shared_bindings PRIVATE bcrypt)
    target_link_libraries(gosling_c_shared_bindings PRIVATE ntdll)
endif()

# check if the --exclude-libs flag is supported by the linker
check_linker_flag(C "-Wl,--exclude-libs,ALL" LINKER_SUPPORTS_EXCLUDE_LIBS)

if(LINKER_SUPPORTS_EXCLUDE_LIBS)
    # prevents the result so from re-exporting all of the static libs symbols out of the shared library
    target_link_options(gosling_c_shared_bindings PRIVATE "-Wl,--exclude-libs,ALL")
endif()

target_include_directories(gosling_c_shared_bindings PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)

add_custom_target(gosling_c_shared_bindings_target ALL)
add_dependencies(gosling_c_shared_bindings_target gosling_c_shared_bindings)

#
# Install
#

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/cgosling.h
    TYPE INCLUDE)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_STATIC}
    TYPE LIB)
install(TARGETS gosling_c_shared_bindings)

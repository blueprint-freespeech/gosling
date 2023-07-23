set(gosling_ffi_sources
    src/ffi.rs
    src/lib.rs
    src/object_registry.rs
    build.rs
    Cargo.toml
    cbindgen.toml
    libgosling.hpp)

set(gosling_ffi_outputs
    ${CARGO_TARGET_DIR}/include/libgosling.h
    ${CARGO_TARGET_DIR}/include/libgosling.hpp
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libgoslingffi.a)
#
# gosling_ffi build target
#
add_custom_command(
    OUTPUT ${gosling_ffi_outputs}
    DEPENDS ${gosling_ffi_sources} gosling_target
    # cargo test of this same project will also run build.rs, so we need to touch build.rs
    # to force cargo to re-run it and generate cbindgen headers (cmake seems to delete the first output file)
    COMMAND touch ${CMAKE_CURRENT_SOURCE_DIR}/build.rs
    COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(gosling_ffi_target
    DEPENDS ${gosling_ffi_outputs})

# create gosling library target
add_library(gosling_ffi STATIC IMPORTED GLOBAL)
# which depends on the above command target
add_dependencies(gosling_ffi gosling_ffi_target)

#
# libgoslingffi linker + include setup
#

# create include directory ahead of time or else cmake falls over
set(GOSLING_INCLUDE_DIR ${CARGO_TARGET_DIR}/include)
file(MAKE_DIRECTORY ${GOSLING_INCLUDE_DIR})
# define our binary directory
set(GOSLING_LIBRARY_DIR ${CARGO_TARGET_DIR}/${CARGO_PROFILE})

# specify goslings link target for consumers
set_target_properties(gosling_ffi PROPERTIES
    IMPORTED_LOCATION ${GOSLING_LIBRARY_DIR}/libgoslingffi.a
)

# include location of our cbindgen headers
target_include_directories(gosling_ffi INTERFACE ${GOSLING_INCLUDE_DIR})

# Linux targets needed by rust runtime
if(LINUX)
    target_link_libraries(gosling_ffi INTERFACE pthread)
    target_link_libraries(gosling_ffi INTERFACE dl)
endif()

if(WINDOWS)
    target_link_libraries(gosling_ffi INTERFACE ws2_32)
    target_link_libraries(gosling_ffi INTERFACE userenv)
    target_link_libraries(gosling_ffi INTERFACE bcrypt)
    target_link_libraries(gosling_ffi INTERFACE ntdll)
endif()

install(FILES ${GOSLING_INCLUDE_DIR}/libgosling.h ${GOSLING_INCLUDE_DIR}/libgosling.hpp
    DESTINATION include)
install(FILES ${GOSLING_LIBRARY_DIR}/libgoslingffi.a
    DESTINATION lib)

#
# libgoslingffi documentation
#
set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
set(DOXYGEN_OUT ${CARGO_TARGET_DIR}/Doxyfile)
configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
# doxygen command
add_custom_command(
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${GOSLING_INCLUDE_DIR}/libgosling.h ${GOSLING_INCLUDE_DIR}/libgosling.hpp
    OUTPUT ${CARGO_TARGET_DIR}/html
    COMMAND doxygen ${DOXYGEN_OUT}
    WORKING_DIRECTORY ${CARGO_TARGET_DIR})
# make target
add_custom_target(gosling_ffi_doxygen
    DEPENDS ${CARGO_TARGET_DIR}/html)
add_dependencies(gosling_ffi_doxygen gosling_ffi_target)
# install
install(DIRECTORY ${CARGO_TARGET_DIR}/html/
    DESTINATION pages/libgoslingffi)

#
# cargo test target
#
add_custom_target(gosling_ffi_cargo_test
    COMMAND RUSTFLAGS=${RUSTFLAGS} CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# invokes cargo build
add_custom_target(gosling_ffi_target
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${CARGO_PROFILE} ${CMAKE_CURRENT_BINARY_DIR}/include
)

# create gosling library target
add_library(gosling_ffi STATIC IMPORTED GLOBAL)
# which depends on the above command target
add_dependencies(gosling_ffi gosling_ffi_target)

# create include directory ahead of time or else cmake falls over
set(GOSLING_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
file(MAKE_DIRECTORY ${GOSLING_INCLUDE_DIR})
# define our binary directory
set(GOSLING_LIBRARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/${CARGO_PROFILE})

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
    target_link_libraries(gosling_ffi INTERFACE bcrypt)
    target_link_libraries(gosling_ffi INTERFACE userenv)
endif()

# test target
add_test(NAME gosling_ffi_test
    COMMAND cargo test ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
set_tests_properties(gosling_ffi_test
    PROPERTIES ENVIRONMENT "RUSTFLAGS=${RUSTFLAGS};CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR};RUST_BACKTRACE=full"
)

# doxygen target
set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)

add_custom_target(gosling_ffi_doxygen
    COMMAND doxygen ${DOXYGEN_OUT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
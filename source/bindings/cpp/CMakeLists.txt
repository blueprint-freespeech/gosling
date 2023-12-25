set(GOSLING_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)

file(MAKE_DIRECTORY ${GOSLING_INCLUDE_DIR})

set(gosling_cpp_bindings_sources
    build_cpp_bindings.rs
    Cargo.toml
    cgosling.hpp.handlebars
    ${CARGO_TARGET_DIR}/cgosling.json)

set(gosling_cpp_bindings_outputs
    ${GOSLING_INCLUDE_DIR}/cgosling.hpp)

#
# generate cgosling.hpp using handlebars
#
add_custom_command(
    DEPENDS ${gosling_cpp_bindings_sources}
    OUTPUT ${gosling_cpp_bindings_outputs}
    COMMAND RUSTFLAGS=${RUSTFLAGS} cargo run --bin build_cpp_bindings ${CARGO_TARGET_DIR}/cgosling.json cgosling.hpp.handlebars ${GOSLING_INCLUDE_DIR}/cgosling.hpp
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target(gosling_cpp_bindings_target
    DEPENDS ${gosling_cpp_bindings_outputs} gosling_c_bindings_target)

#
# Static Library
#

add_library(gosling_cpp_static_bindings INTERFACE)
add_dependencies(gosling_cpp_static_bindings gosling_cpp_bindings_target)

target_include_directories(gosling_cpp_static_bindings INTERFACE ${GOSLING_INCLUDE_DIR})
target_link_libraries(gosling_cpp_static_bindings INTERFACE gosling_c_static_bindings)

#
# Shared Library
#

add_library(gosling_cpp_shared_bindings INTERFACE)
add_dependencies(gosling_cpp_shared_bindings gosling_cpp_bindings_target)

target_include_directories(gosling_cpp_shared_bindings INTERFACE ${GOSLING_INCLUDE_DIR})
target_link_libraries(gosling_cpp_shared_bindings INTERFACE gosling_c_shared_bindings)

#
# Install
#

install(FILES ${GOSLING_INCLUDE_DIR}/cgosling.hpp
    DESTINATION include)

#
# cgosling documentation
#
set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
set(DOXYFILE ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
configure_file(${DOXYFILE_IN} ${DOXYFILE} @ONLY)
set(doxygen_depends
    ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
    ${CMAKE_CURRENT_BINARY_DIR}/../c/include/cgosling.h
    ${GOSLING_INCLUDE_DIR}/cgosling.hpp)
set(doxygen_output
    ${CMAKE_CURRENT_BINARY_DIR}/html)

# doxygen command
add_custom_command(
    DEPENDS ${doxygen_depends}
    OUTPUT ${doxygen_output}
    COMMAND doxygen ${DOXYFILE})
# make target
add_custom_target(gosling_cpp_doxygen
    DEPENDS ${doxygen_output})
add_dependencies(gosling_cpp_doxygen gosling_cpp_bindings_target)
# install
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html/
    DESTINATION pages/libgoslingffi)

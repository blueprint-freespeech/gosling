file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)

set(gosling_cpp_bindings_sources
    build_cpp_bindings.rs
    Cargo.toml
    cgosling.hpp.handlebars)

set(gosling_cpp_bindings_outputs
    ${CMAKE_CURRENT_BINARY_DIR}/include/cgosling.hpp)

#
# generate cgosling.hpp using handlebars
#
add_custom_command(
    DEPENDS ${gosling_cpp_bindings_sources} cgosling_target
    OUTPUT ${gosling_cpp_bindings_outputs}
    COMMAND  env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo run ${CARGO_FLAGS} --bin build_cpp_bindings ${CARGO_TARGET_DIR}/cgosling.json cgosling.hpp.handlebars ${CMAKE_CURRENT_BINARY_DIR}/include/cgosling.hpp
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target(gosling_cpp_bindings_target
    DEPENDS ${gosling_cpp_bindings_outputs})
if (ENABLE_LINTING)
    add_dependencies(linting gosling_cpp_bindings_target)
endif()

#
# Static Library
#

add_library(gosling_cpp_static_bindings INTERFACE)
add_dependencies(gosling_cpp_static_bindings gosling_cpp_bindings_target)

target_include_directories(gosling_cpp_static_bindings INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(gosling_cpp_static_bindings INTERFACE gosling_c_static_bindings)

add_custom_target(gosling_cpp_static_bindings_target ALL)
add_dependencies(gosling_cpp_static_bindings_target gosling_cpp_static_bindings)

#
# Shared Library
#

add_library(gosling_cpp_shared_bindings INTERFACE)
add_dependencies(gosling_cpp_shared_bindings gosling_cpp_bindings_target)

target_include_directories(gosling_cpp_shared_bindings INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(gosling_cpp_shared_bindings INTERFACE gosling_c_shared_bindings)

add_custom_target(gosling_cpp_shared_bindings_target ALL)
add_dependencies(gosling_cpp_shared_bindings_target gosling_cpp_shared_bindings)

#
# Install C++ Header
#

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/cgosling.hpp
    TYPE INCLUDE)

if (BUILD_PAGES)
    #
    # cgosling documentation
    #
    find_program(DOXYGEN_EXECUTABLE NAMES doxygen)

    if (NOT DOXYGEN_EXECUTABLE)
        message(FATAL_ERROR "doxygen not found; required to generate C/C++ documentation")
    else()
        set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
        set(DOXYFILE ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
        configure_file(${DOXYFILE_IN} ${DOXYFILE} @ONLY)
        set(doxygen_depends
            ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
            ${CMAKE_CURRENT_BINARY_DIR}/../c/include/cgosling.h
            ${CMAKE_CURRENT_BINARY_DIR}/include/cgosling.hpp)
        set(doxygen_output
            ${CMAKE_CURRENT_BINARY_DIR}/cgosling)

        # doxygen command
        add_custom_command(
            DEPENDS ${doxygen_depends}
            OUTPUT ${doxygen_output}
            COMMAND doxygen ${DOXYFILE}
            )
        # make target
        add_custom_target(gosling_cpp_doxygen_target ALL
            DEPENDS ${doxygen_output})
        add_dependencies(gosling_cpp_doxygen_target gosling_cpp_bindings_target)

        #
        # Install
        #
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/cgosling
            DESTINATION ${CMAKE_INSTALL_DOCDIR})

    endif()
endif()

find_program(PATCHELF_EXECUTABLE NAMES patchelf)

if (NOT PATCHELF_EXECUTABLE AND LINUX)
    message(FATAL_ERROR "Could not find patchelf executable; required for linux shared library generation")
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)

set(gosling_c_bindings_sources
    ${CARGO_TARGET_DIR}/include/cgosling.h
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_STATIC}
)

set(gosling_c_bindings_outputs
    ${CMAKE_CURRENT_BINARY_DIR}/include/cgosling.h
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_STATIC}
)

# add Shared library import library
if (WINDOWS)
    list(APPEND gosling_c_bindings_sources ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_IMPORT})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_IMPORT})
endif()

#
# Just copy header and libs from the cgosling crate build outputs
#
foreach(src dest IN ZIP_LISTS gosling_c_bindings_sources gosling_c_bindings_outputs)
    add_custom_command(
        DEPENDS ${src} cgosling_target
        OUTPUT ${dest}
        COMMAND  cp -P ${src} ${dest})
endforeach()

# Shared Library + Symlinks
if (LINUX)
    add_custom_command(
        DEPENDS ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_VERSION}
            ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION}
            ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}
        # copy shared library and set soname
        COMMAND ${CMAKE_COMMAND} -E copy ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED} ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_VERSION}
        COMMAND patchelf --set-soname libcgosling.so.${CGOSLING_MAJOR_VERSION} ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_VERSION}
        # create symlinks
        COMMAND ${CMAKE_COMMAND} -E create_symlink ${CGOSLING_SHARED}.${CGOSLING_VERSION} ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION}
        COMMAND ${CMAKE_COMMAND} -E create_symlink ${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION} ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_VERSION})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED})
elseif(MACOS)
    add_custom_command(
        DEPENDS ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/lib/libcgosling.${CGOSLING_VERSION}.dylib
            ${CMAKE_CURRENT_BINARY_DIR}/lib/libcgosling.${CGOSLING_MAJOR_VERSION}.dylib
            ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}
        # copy shared library
        COMMAND ${CMAKE_COMMAND} -E copy ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED} ${CMAKE_CURRENT_BINARY_DIR}/lib/libcgosling.${CGOSLING_VERSION}.dylib
        # create symlinks
        COMMAND ${CMAKE_COMMAND} -E create_symlink libcgosling.${CGOSLING_VERSION}.dylib ${CMAKE_CURRENT_BINARY_DIR}/lib/libcgosling.${CGOSLING_MAJOR_VERSION}.dylib
        COMMAND ${CMAKE_COMMAND} -E create_symlink libcgosling.${CGOSLING_MAJOR_VERSION}.dylib ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/libcgosling.${CGOSLING_VERSION}.dylib)
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/libcgosling.${CGOSLING_MAJOR_VERSION}.dylib)
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED})
else()
    add_custom_command(
        DEPENDS ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}
        COMMAND ${CMAKE_COMMAND} -E copy ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED} ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED})
endif()

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

# Linux targets needed by rust runtime
if(LINUX)
    target_link_libraries(gosling_c_static_bindings INTERFACE pthread)
    target_link_libraries(gosling_c_static_bindings INTERFACE dl)
endif()

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

add_library(gosling_c_shared_bindings SHARED IMPORTED GLOBAL)
add_dependencies(gosling_c_shared_bindings gosling_c_bindings_target)

target_include_directories(gosling_c_shared_bindings INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/include)
set_target_properties(gosling_c_shared_bindings PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}
)
if (WINDOWS)
    set_target_properties(gosling_c_shared_bindings PROPERTIES
        IMPORTED_IMPLIB ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_IMPORT}
    )
endif()

add_custom_target(gosling_c_shared_bindings_target ALL)
add_dependencies(gosling_c_shared_bindings_target gosling_c_shared_bindings)

#
# Install
#

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/cgosling.h
    TYPE INCLUDE)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_STATIC}
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}
    TYPE LIB)
if (WINDOWS)
    # .a + .dll.a goes to lib
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_STATIC}
        ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_IMPORT}
        TYPE LIB)
    # .dll goes to bin
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}
        TYPE BIN)
elseif (LINUX)
    # .so and .a go to lib
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_STATIC}
        ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}
        TYPE LIB)
    # versioned symlinks go to lib
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION}
        ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_VERSION}
        TYPE LIB)
elseif (MACOS)
    # .dylib and .a go to lib
    install(FILES
            ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_STATIC}
            ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}
            TYPE LIB)
    # versioned symlinks go to lib
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/lib/libcgosling.${CGOSLING_MAJOR_VERSION}.dylib
        ${CMAKE_CURRENT_BINARY_DIR}/lib/libcgosling.${CGOSLING_VERSION}.dylib
        TYPE LIB)
else()
    install(FILES
            ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_STATIC}
            ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}
            TYPE LIB)
endif()


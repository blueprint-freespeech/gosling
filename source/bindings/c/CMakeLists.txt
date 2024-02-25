set(GOSLING_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
set(GOSLING_LIBRARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/lib)

file(MAKE_DIRECTORY ${GOSLING_INCLUDE_DIR})
file(MAKE_DIRECTORY ${GOSLING_LIBRARY_DIR})

set(gosling_c_bindings_sources
    ${CARGO_TARGET_DIR}/include/cgosling.h
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_STATIC}
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}
)

set(gosling_c_bindings_outputs
    ${CMAKE_CURRENT_BINARY_DIR}/include/cgosling.h
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_STATIC}
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}
)

# add shared library import library if platform supports it
if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    list(APPEND gosling_c_bindings_sources ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_IMPORT})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_IMPORT})
endif()

# Linux also needs to copy over the symlinks
if (LINUX)
    list(APPEND gosling_c_bindings_sources ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION})
    list(APPEND gosling_c_bindings_sources ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}.${CGOSLING_VERSION})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CGOSLING_SHARED}.${CGOSLING_VERSION})
endif()

#
# Just copy header and lib from the cgosling crate build outputs
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

#
# Static Library
#

add_library(gosling_c_static_bindings STATIC IMPORTED GLOBAL)
add_dependencies(gosling_c_static_bindings gosling_c_bindings_target)

target_include_directories(gosling_c_static_bindings INTERFACE ${GOSLING_INCLUDE_DIR})
set_target_properties(gosling_c_static_bindings PROPERTIES
    IMPORTED_LOCATION ${GOSLING_LIBRARY_DIR}/${CGOSLING_STATIC}
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

add_custom_target(gosling_c_static_bindings_target)
add_dependencies(gosling_c_static_bindings_target gosling_c_static_bindings)
add_dependencies(build_target gosling_c_static_bindings_target)

#
# Shared Library
#

add_library(gosling_c_shared_bindings SHARED IMPORTED GLOBAL)
add_dependencies(gosling_c_shared_bindings gosling_c_bindings_target)

target_include_directories(gosling_c_shared_bindings INTERFACE ${GOSLING_INCLUDE_DIR})
set_target_properties(gosling_c_shared_bindings PROPERTIES
    IMPORTED_LOCATION ${GOSLING_LIBRARY_DIR}/${CGOSLING_SHARED}
)
if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    set_target_properties(gosling_c_shared_bindings PROPERTIES
        IMPORTED_IMPLIB ${GOSLING_LIBRARY_DIR}/${CGOSLING_IMPORT}
    )
endif()

add_custom_target(gosling_c_shared_bindings_target)
add_dependencies(gosling_c_shared_bindings_target gosling_c_shared_bindings)
add_dependencies(build_target gosling_c_shared_bindings_target)

#
# Install
#

install(FILES ${GOSLING_INCLUDE_DIR}/cgosling.h
    DESTINATION include)
install(FILES
    ${GOSLING_LIBRARY_DIR}/${CGOSLING_STATIC}
    ${GOSLING_LIBRARY_DIR}/${CGOSLING_SHARED}
    DESTINATION lib)
if (LINUX)
    install(FILES
        ${GOSLING_LIBRARY_DIR}/${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION}
        ${GOSLING_LIBRARY_DIR}/${CGOSLING_SHARED}.${CGOSLING_VERSION}
        DESTINATION lib)
endif()
if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    install(FILES ${GOSLING_LIBRARY_DIR}/${CGOSLING_IMPORT}
        DESTINATION lib)
endif()

set(GOSLING_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
set(GOSLING_LIBRARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/lib)

file(MAKE_DIRECTORY ${GOSLING_INCLUDE_DIR})
file(MAKE_DIRECTORY ${GOSLING_LIBRARY_DIR})

set(GOSLING_STATIC ${CMAKE_STATIC_LIBRARY_PREFIX}cgosling${CMAKE_STATIC_LIBRARY_SUFFIX})
# MINGW Rust doesn't geneate dll files with the right prefix (missing lib) so we need custom logic
if (MINGW)
    set(GOSLING_SHARED cgosling${CMAKE_SHARED_LIBRARY_SUFFIX})
else()
    set(GOSLING_SHARED ${CMAKE_SHARED_LIBRARY_PREFIX}cgosling${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()
set(GOSLING_IMPORT ${CMAKE_IMPORT_LIBRARY_PREFIX}cgosling${CMAKE_IMPORT_LIBRARY_SUFFIX})

set(gosling_c_bindings_sources
    ${CARGO_TARGET_DIR}/include/cgosling.h
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${GOSLING_STATIC}
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${GOSLING_SHARED}
)

set(gosling_c_bindings_outputs
    ${CMAKE_CURRENT_BINARY_DIR}/include/cgosling.h
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${GOSLING_STATIC}
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${GOSLING_SHARED}
)

if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    list(APPEND gosling_c_bindings_sources ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${GOSLING_IMPORT})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${GOSLING_IMPORT})
endif()

#
# Just copy header and lib from the cgosling crate build outputs
#
foreach(src dest IN ZIP_LISTS gosling_c_bindings_sources gosling_c_bindings_outputs)
    add_custom_command(
        DEPENDS ${src} cgosling_target
        OUTPUT ${dest}
        COMMAND cp ${src} ${dest})
endforeach()

add_custom_target(gosling_c_bindings_target
    DEPENDS ${gosling_c_bindings_outputs} cgosling_target)

#
# Static Library
#

add_library(gosling_c_static_bindings STATIC IMPORTED GLOBAL)
add_dependencies(gosling_c_static_bindings gosling_c_bindings_target)

target_include_directories(gosling_c_static_bindings INTERFACE ${GOSLING_INCLUDE_DIR})
set_target_properties(gosling_c_static_bindings PROPERTIES
    IMPORTED_LOCATION ${GOSLING_LIBRARY_DIR}/${GOSLING_STATIC}
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

#
# Shared Library
#

add_library(gosling_c_shared_bindings SHARED IMPORTED GLOBAL)
add_dependencies(gosling_c_shared_bindings gosling_c_bindings_target)

target_include_directories(gosling_c_shared_bindings INTERFACE ${GOSLING_INCLUDE_DIR})
set_target_properties(gosling_c_shared_bindings PROPERTIES
    IMPORTED_LOCATION ${GOSLING_LIBRARY_DIR}/${GOSLING_SHARED}
)
if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    set_target_properties(gosling_c_shared_bindings PROPERTIES
        IMPORTED_IMPLIB ${GOSLING_LIBRARY_DIR}/${GOSLING_IMPORT}
    )
endif()

#
# Install
#

install(FILES ${GOSLING_INCLUDE_DIR}/cgosling.h
    DESTINATION include)
install(FILES ${GOSLING_LIBRARY_DIR}/${GOSLING_STATIC} ${GOSLING_LIBRARY_DIR}/${GOSLING_SHARED}
    DESTINATION lib)
if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    install(FILES ${GOSLING_LIBRARY_DIR}/${GOSLING_IMPORT}
        DESTINATION lib)
endif()

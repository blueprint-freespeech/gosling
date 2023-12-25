set(GOSLING_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
set(GOSLING_LIBRARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/lib)

file(MAKE_DIRECTORY ${GOSLING_INCLUDE_DIR})
file(MAKE_DIRECTORY ${GOSLING_LIBRARY_DIR})

set(gosling_c_bindings_sources
    ${CARGO_TARGET_DIR}/include/libgosling.h
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_STATIC_LIBRARY_PREFIX}cgosling${CMAKE_STATIC_LIBRARY_SUFFIX}
)

set(gosling_c_bindings_outputs
    ${CMAKE_CURRENT_BINARY_DIR}/include/libgosling.h
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}cgosling${CMAKE_STATIC_LIBRARY_SUFFIX}
)


# MINGW Rust doesn't geneate dll files with the right prefix (missing lib) so we need custom logic
# to handle this
if (MINGW)
    list(APPEND gosling_c_bindings_sources ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling${CMAKE_SHARED_LIBRARY_SUFFIX})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/cgosling${CMAKE_SHARED_LIBRARY_SUFFIX})
else()
    list(APPEND gosling_c_bindings_sources ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_SHARED_LIBRARY_PREFIX}cgosling${CMAKE_SHARED_LIBRARY_SUFFIX})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}cgosling${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    list(APPEND gosling_c_bindings_sources ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CMAKE_IMPORT_LIBRARY_PREFIX}cgosling${CMAKE_IMPORT_LIBRARY_SUFFIX})
    list(APPEND gosling_c_bindings_outputs ${CMAKE_CURRENT_BINARY_DIR}/lib/${CMAKE_IMPORT_LIBRARY_PREFIX}cgosling${CMAKE_IMPORT_LIBRARY_SUFFIX})
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
    IMPORTED_LOCATION ${GOSLING_LIBRARY_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}cgosling${CMAKE_STATIC_LIBRARY_SUFFIX}
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
### This needs a mingw-specific block >:[
if(MINGW)
    set_target_properties(gosling_c_shared_bindings PROPERTIES
        IMPORTED_LOCATION ${GOSLING_LIBRARY_DIR}/cgosling${CMAKE_SHARED_LIBRARY_SUFFIX}
    )
else()
    set_target_properties(gosling_c_shared_bindings PROPERTIES
        IMPORTED_LOCATION ${GOSLING_LIBRARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}cgosling${CMAKE_SHARED_LIBRARY_SUFFIX}
    )
endif()

if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
    set_target_properties(gosling_c_shared_bindings PROPERTIES
        IMPORTED_IMPLIB ${GOSLING_LIBRARY_DIR}/${CMAKE_IMPORT_LIBRARY_PREFIX}cgosling${CMAKE_IMPORT_LIBRARY_SUFFIX}
    )
endif()

#
# Install
#

install(FILES ${GOSLING_INCLUDE_DIR}/libgosling.h
    DESTINATION include)
install(FILES ${GOSLING_LIBRARY_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}cgosling${CMAKE_STATIC_LIBRARY_SUFFIX}
    DESTINATION lib)
if (MINGW)
    install(FILES ${GOSLING_LIBRARY_DIR}/cgoslinng${CMAKE_SHARED_LIBRARY_SUFFIX}
        DESTINATION lib)
else()
    install(FILES ${GOSLING_LIBRARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}cgosling${CMAKE_SHARED_LIBRARY_SUFFIX}
        DESTINATION lib)
endif()

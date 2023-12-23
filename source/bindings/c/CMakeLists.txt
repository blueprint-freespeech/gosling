set(GOSLING_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
set(GOSLING_LIBRARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/lib)

file(MAKE_DIRECTORY ${GOSLING_INCLUDE_DIR})
file(MAKE_DIRECTORY ${GOSLING_LIBRARY_DIR})

set(gosling_c_bindings_sources
    ${CARGO_TARGET_DIR}/include/libgosling.h
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libgoslingffi.a)

set(gosling_c_bindings_outputs
    ${CMAKE_CURRENT_BINARY_DIR}/include/libgosling.h
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libgosling.a)

#
# Just copy header and lib from the gosling-ffi crate build outputs
#
add_custom_command(
    OUTPUT ${gosling_c_bindings_outputs}
    DEPENDS ${gosling_c_bindings_sources}
    COMMAND cp ${CARGO_TARGET_DIR}/include/libgosling.h ${CMAKE_CURRENT_BINARY_DIR}/include/libgosling.h
    COMMAND cp ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libgoslingffi.a ${CMAKE_CURRENT_BINARY_DIR}/lib/libgosling.a
)
add_custom_target(gosling_c_bindings_target
    DEPENDS ${gosling_c_bindings_outputs} gosling_ffi_target)

add_library(gosling_c_bindings STATIC IMPORTED GLOBAL)
add_dependencies(gosling_c_bindings gosling_c_bindings_target)

target_include_directories(gosling_c_bindings INTERFACE ${GOSLING_INCLUDE_DIR})
set_target_properties(gosling_c_bindings PROPERTIES
    IMPORTED_LOCATION ${GOSLING_LIBRARY_DIR}/libgosling.a
)

# Linux targets needed by rust runtime
if(LINUX)
    target_link_libraries(gosling_c_bindings INTERFACE pthread)
    target_link_libraries(gosling_c_bindings INTERFACE dl)
endif()

if(WINDOWS)
    target_link_libraries(gosling_c_bindings INTERFACE ws2_32)
    target_link_libraries(gosling_c_bindings INTERFACE userenv)
    target_link_libraries(gosling_c_bindings INTERFACE bcrypt)
    target_link_libraries(gosling_c_bindings INTERFACE ntdll)
endif()

install(FILES ${GOSLING_INCLUDE_DIR}/libgosling.h
    DESTINATION include)
install(FILES ${GOSLING_LIBRARY_DIR}/libgosling.a
    DESTINATION lib)

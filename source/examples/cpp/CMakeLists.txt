set(CURSES_NEED_NCURSES TRUE)
find_package(Curses)
find_package(Boost 1.66.0)

if (NOT CURSES_FOUND)
    message(WARNING "curses or ncurses not found; will not build C++ example")
elseif(NOT Boost_FOUND)
    message(WARNING "Boost 1.66 or newer not found; will not build C++ example")
else()
    add_executable(hello_world_cpp EXCLUDE_FROM_ALL
        precomp.cpp
        terminal.cpp
        identity_server_callbacks.cpp
        identity_client_callbacks.cpp
        endpoint_server_callbacks.cpp
        endpoint_client_callbacks.cpp
        commands.cpp
        main.cpp)
    target_precompile_headers(hello_world_cpp PRIVATE precomp.hpp)

    foreach(h
        CURSES_HAVE_NCURSES_H
        CURSES_HAVE_NCURSES_NCURSES_H)
        if (${h})
            target_compile_definitions(hello_world_cpp PRIVATE ${h})
        endif()
    endforeach()

    if (MINGW)
        target_compile_definitions(hello_world_cpp PRIVATE NCURSES_STATIC)
    endif()

    target_include_directories(hello_world_cpp PRIVATE ${CURSES_INCLUDE_DIRS})
    target_include_directories(hello_world_cpp PRIVATE ${Boost_INCLUDE_DIRS})

    target_link_libraries(hello_world_cpp PRIVATE gosling_cpp_static_bindings)
    target_link_libraries(hello_world_cpp PRIVATE ${CURSES_LIBRARIES})
    target_link_libraries(hello_world_cpp PRIVATE nlohmann_json::nlohmann_json)

    target_compile_features(hello_world_cpp PRIVATE cxx_std_17)

    add_custom_target(install_hello_world_cpp
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/hello_world_cpp${CMAKE_EXECUTABLE_SUFFIX}
        COMMAND mkdir -p ${CMAKE_INSTALL_PREFIX}/examples
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/hello_world_cpp${CMAKE_EXECUTABLE_SUFFIX} ${CMAKE_INSTALL_PREFIX}/examples/
    )
endif()
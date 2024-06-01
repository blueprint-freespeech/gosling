if (BUILD_EXAMPLES AND ENABLE_LEGACY_TOR_PROVIDER)
    set(CURSES_NEED_NCURSES TRUE)
    find_package(Curses)
    find_package(Boost 1.66.0)

    if (NOT CURSES_FOUND)
        message(FATAL_ERROR "curses or ncurses not found; needed for C++ example")
    elseif(NOT Boost_FOUND)
        message(FATAL_ERROR "Boost 1.66 or newer not found; needed for C++ example")
    elseif (NOT TARGET nlohmann_json::nlohmann_json)
        message(FATAL_ERROR "nlohmann_json not found; needed for C++ example")
    endif()

    add_executable(hello_world_cpp
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

    add_custom_target(hello_world_cpp_target ALL)
    add_dependencies(hello_world_cpp_target hello_world_cpp)

    if (ENABLE_FORMATTING)
        add_format_target(format_cpp_example_target ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    #
    # Install hello world example binary
    #

    install(TARGETS hello_world_cpp
        RUNTIME)
endif()

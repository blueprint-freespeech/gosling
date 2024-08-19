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

    add_executable(example_chat_cpp
        precomp.cpp
        terminal.cpp
        identity_server_callbacks.cpp
        identity_client_callbacks.cpp
        endpoint_server_callbacks.cpp
        endpoint_client_callbacks.cpp
        commands.cpp
        main.cpp)
    target_precompile_headers(example_chat_cpp PRIVATE precomp.hpp)

    foreach(h
        CURSES_HAVE_NCURSES_H
        CURSES_HAVE_NCURSES_NCURSES_H)
        if (${h})
            target_compile_definitions(example_chat_cpp PRIVATE ${h})
        endif()
    endforeach()

    if (MINGW)
        target_compile_definitions(example_chat_cpp PRIVATE NCURSES_STATIC)
    endif()

    target_include_directories(example_chat_cpp PRIVATE ${CURSES_INCLUDE_DIRS})
    target_include_directories(example_chat_cpp PRIVATE ${Boost_INCLUDE_DIRS})

    target_link_libraries(example_chat_cpp PRIVATE gosling_cpp_static_bindings)
    target_link_libraries(example_chat_cpp PRIVATE ${CURSES_LIBRARIES})
    target_link_libraries(example_chat_cpp PRIVATE nlohmann_json::nlohmann_json)

    target_compile_features(example_chat_cpp PRIVATE cxx_std_17)

    add_custom_target(example_chat_cpp_target ALL)
    add_dependencies(example_chat_cpp_target example_chat_cpp)

    if (ENABLE_FORMATTING)
        add_format_target(format_cpp_example_target ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    #
    # Install hello world example binary
    #

    install(TARGETS example_chat_cpp
        RUNTIME)
endif()

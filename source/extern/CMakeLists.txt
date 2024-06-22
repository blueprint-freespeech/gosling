if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/Catch2/CMakeLists.txt)
    if (ENABLE_TESTS)
        add_subdirectory(Catch2)
    endif()
endif()

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/json/CMakeLists.txt)
    set(JSON_Install OFF CACHE INTERNAL "")
    add_subdirectory(json)
endif()

if (ENABLE_TOR_EXPERT_BUNDLE)
    add_subdirectory(tor-expert-bundle)
endif()
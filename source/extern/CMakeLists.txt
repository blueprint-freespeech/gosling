if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/Catch2/CMakeLists.txt)
    add_subdirectory(Catch2)
endif()

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/json/CMakeLists.txt)
    set(JSON_Install OFF CACHE INTERNAL "")
    add_subdirectory(json)
endif()

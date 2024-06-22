cmake_minimum_required(VERSION 3.17)

project(gosling)

# cmake variables reference: https://cmake.org/cmake/help/v3.17/manual/cmake-variables.7.html
# define per-platform flags
if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
elseif(UNIX AND APPLE)
    set(MACOS TRUE)
elseif(WIN32)
    set(WINDOWS TRUE)
endif()

# Feature flags
option(ENABLE_MOCK_TOR_PROVIDER "Enable mocked tor support for tests" ON)
option(ENABLE_LEGACY_TOR_PROVIDER "Enable legacy c-tor daemon support" ON)
option(ENABLE_ARTI_CLIENT_TOR_PROVIDER "Enable experimental arti-client tor support" OFF)

# Test options
option(ENABLE_TESTS "Enable tests" OFF)
option(ENABLE_FUZZ_TESTS "Enable fuzz tests" OFF)

if (ENABLE_FUZZ_TESTS)
    if (NOT FUZZ_TEST_MAX_TOTAL_TIME)
        set(FUZZ_TEST_MAX_TOTAL_TIME 600)
    endif()
endif()

if (ENABLE_TESTS OR ENABLE_FUZZ_TESTS)
    enable_testing()
endif()

#
# Addditional Tools
#

# Run rust's clippy for Rust targets and cppcheck for C++ targets
option(ENABLE_LINTING "Enable lint make target" OFF)
if (ENABLE_LINTING)
    find_program(JQ_EXECUTABLE NAMES jq)
    find_program(CPPCHECK_EXECUTABLE NAMES cppcheck)

    if (NOT JQ_EXECUTABLE)
        message(FATAL_ERROR "jq not found; required for linting")
    elseif(NOT CPPCHECK_EXECUTABLE)
        message(FATAL_ERROR "cppcheck not found; required for linting")
    endif()

    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

    add_custom_target(linting)
    add_custom_command(
        DEPENDS ${CMAKE_BINARY_DIR}/compile_commands.json
        OUTPUT ${CMAKE_BINARY_DIR}/compile_commands.sans-catch2.json
        COMMAND jq "'del(.[]|select(.directory|test(\"Catch2/src$$\")))'" ${CMAKE_BINARY_DIR}/compile_commands.json > ${CMAKE_BINARY_DIR}/compile_commands.sans-catch2.json
    )
    add_custom_target(cppcheck_target
        DEPENDS
            ${CMAKE_BINARY_DIR}/compile_commands.sans-catch2.json
        COMMAND cppcheck --enable=all --inline-suppr --suppress=missingIncludeSystem --suppress=*:*Catch2* --project="${CMAKE_BINARY_DIR}/compile_commands.sans-catch2.json"
    )
    add_dependencies(linting cppcheck_target)
endif()

#
option(ENABLE_FORMATTING "Enable format make target" OFF)
if (ENABLE_FORMATTING)
    find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format)
    if (NOT CLANG_FORMAT_EXECUTABLE)
        message(FATAL_ERROR "clang-format not found; required for formatting")
    endif()

    function(add_format_target target_name source_directory)
        add_custom_target(${target_name}
            COMMAND clang-format -i *.cpp *.hpp
            WORKING_DIRECTORY ${source_directory}
        )
        add_dependencies(format ${target_name})
    endfunction()
    add_custom_target(format)
endif()


option(ENABLE_TOR_EXPERT_BUNDLE "Enable and fetch tor-expert-bundle" OFF)
if (ENABLE_TOR_EXPERT_BUNDLE)
    cmake_path(CONVERT ${CMAKE_BINARY_DIR}/source/extern/tor-expert-bundle TO_NATIVE_PATH_LIST TEB_PATH NORMALIZE)
    message("TEB_PATH: ${TEB_PATH}")
endif()

# Bindings options
option(BUILD_PYTHON_BINDINGS "Build cpython.py Python bindings" OFF)
option(BUILD_JAVA_BINDINGS "Build JNI and jar Java bindings" OFF)

# Example project options
option(BUILD_EXAMPLES "Build example targets" OFF)

# Packages options
option(BUILD_DEBIAN_SOURCE_PACKAGE "Build debian cgosling source package" OFF)
option(BUILD_HOMEBREW_FORMULA "Build homebrew flask formula" OFF)
option(BUILD_MSYS2_PKGBUILD "Build msys2 pkgbuild script" OFF)

# Documentation options
option(BUILD_PAGES "Build webpages" OFF)

add_subdirectory(source)

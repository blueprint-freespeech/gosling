# TEB shorthand for tor-expert-bundle
if (NOT TEB_VERSION)
    set(TEB_VERSION 14.0.6)
endif()

# Guess if TEB_TARGET not manually specified
if (NOT TEB_TARGET)
    # get the CPU arch we are building for
    if (WINDOWS)
        set(TEB_OS "windows")
        if (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
            set(TEB_ARCH "x86_64")
        elseif( CMAKE_SYSTEM_PROCESSOR STREQUAL "X86")
            set(TEB_ARCH "i686")
        else()
            message(FATAL_ERROR "Unsupported Windows cpu architecture: ${CMAKE_SYSTEM_PROCESSOR}")
        endif()
    elseif(MACOS)
        set(TEB_OS "macos")
        if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
            set(TEB_ARCH "x86_64")
        elseif( CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
            set(TEB_ARCH "aarch64")
        else()
            message(FATAL_ERROR "Unsupported macOS cpu architecture: ${CMAKE_SYSTEM_PROCESSOR}")
        endif()
    elseif(LINUX)
        set(TEB_OS "linux")
        if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
            set(TEB_ARCH "x86_64")
        elseif( CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
            set(TEB_ARCH "i686")
        else()
            message(FATAL_ERROR "Unsupported Linux cpu architecture: ${CMAKE_SYSTEM_PROCESSOR}")
        endif()
    else()
        message(FATAL_ERROR "Unsupported operating system")
    endif()

    set(TEB_TARGET "${TEB_OS}-${TEB_ARCH}")
    message(WARNING
        "User did not define TEB_TARGET, supported values:\n"
        " - windows-i686\n"
        " - windows-x86_64\n"
        " - macos-x86_64\n"
        " - macos-aarch64\n"
        " - linux-i686\n"
        " - linux-x86_64\n"
        "Guessing ${TEB_TARGET}"
    )
endif()

set(TEB_ARCHIVE "tor-expert-bundle-${TEB_TARGET}-${TEB_VERSION}.tar.gz")
set(TEB_ARCHIVE_URL "https://archive.torproject.org/tor-package-archive/torbrowser/${TEB_VERSION}/${TEB_ARCHIVE}")

if (NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${TEB_ARCHIVE})
    message(STATUS "Downloading ${TEB_ARCHIVE_URL}")
    file(DOWNLOAD "${TEB_ARCHIVE_URL}" "${CMAKE_CURRENT_BINARY_DIR}/${TEB_ARCHIVE}" SHOW_PROGRESS)
    # TODO: verify gpg signature
else()
    message(STATUS "tor-expert-bundle exists: ${CMAKE_CURRENT_BINARY_DIR}/${TEB_ARCHIVE}")
endif()

set(pluggable_transport_binaries
    ${CMAKE_CURRENT_BINARY_DIR}/lyrebird${CMAKE_EXECUTABLE_SUFFIX}
    ${CMAKE_CURRENT_BINARY_DIR}/snowflake-client${CMAKE_EXECUTABLE_SUFFIX}
    ${CMAKE_CURRENT_BINARY_DIR}/conjure-client${CMAKE_EXECUTABLE_SUFFIX}
)

add_custom_command(
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${TEB_ARCHIVE}
    OUTPUT ${pluggable_transport_binaries}
    # extract tor expert bundle
    COMMAND ${CMAKE_COMMAND} -E make_directory tor-expert-bundle
    COMMAND ${CMAKE_COMMAND} -E chdir tor-expert-bundle ${CMAKE_COMMAND} -E tar xvf ${CMAKE_CURRENT_BINARY_DIR}/${TEB_ARCHIVE}
    # copy each pt
    COMMAND ${CMAKE_COMMAND} -E copy tor-expert-bundle/tor/pluggable_transports/lyrebird${CMAKE_EXECUTABLE_SUFFIX} .
    COMMAND ${CMAKE_COMMAND} -E copy tor-expert-bundle/tor/pluggable_transports/snowflake-client${CMAKE_EXECUTABLE_SUFFIX} .
    COMMAND ${CMAKE_COMMAND} -E copy tor-expert-bundle/tor/pluggable_transports/conjure-client${CMAKE_EXECUTABLE_SUFFIX} .
    # cleanup exttra stuff
    COMMAND ${CMAKE_COMMAND} -E rm -rf tor-expert-bundle
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
add_custom_target(tor_expert_bundle_target
    DEPENDS ${pluggable_transport_binaries})

# create a test fixture which builds tor_expert_bundle_target for tests which depend on
# the tor-expert-bundle binaries
if (ENABLE_TESTS)
    add_test(NAME tor_expert_bundle_target_build
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --config $<CONFIG> --target tor_expert_bundle_target)
    set_tests_properties(tor_expert_bundle_target_build PROPERTIES FIXTURES_SETUP
                tor_expert_bundle_target_fixture)
endif()
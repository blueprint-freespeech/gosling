set(TOR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tor)
set(TOR_SRC_DIR ${TOR_ROOT_DIR}/src)

#generate tor's configure scripts
add_custom_command(
    OUTPUT ${TOR_ROOT_DIR}/configure
    COMMAND sh autogen.sh
    WORKING_DIRECTORY ${TOR_ROOT_DIR}
)
add_custom_target(tor_configure DEPENDS ${TOR_ROOT_DIR}/configure)

# generate tor's orconfig.h header
add_custom_command(
    OUTPUT ${TOR_ROOT_DIR}/orconfig.h
    COMMAND ./configure --disable-asciidoc
    WORKING_DIRECTORY ${TOR_ROOT_DIR}
)
add_custom_target(tor_orconfig DEPENDS ${TOR_ROOT_DIR}/orconfig.h)
add_dependencies(tor_orconfig tor_configure)
# tor code may not be compiled with NDEBUG defined
add_definitions(-UNDEBUG)

add_library(tor_crypto STATIC
    precomp.c
    ${TOR_SRC_DIR}/ext/ed25519/donna/ed25519_tor.c
    tor_stubs.c)
target_precompile_headers(tor_crypto PRIVATE precomp.h)

add_dependencies(tor_crypto tor_orconfig)

# add the private tor includes
include_directories(${TOR_ROOT_DIR})
include_directories(${TOR_ROOT_DIR}/src)
include_directories(${TOR_ROOT_DIR}/src/ext)


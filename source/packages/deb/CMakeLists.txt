find_program(TAR_EXECUTABLE NAMES tar)
find_program(DPKG_SOURCE_EXECUTABLE NAMES dpkg-source)

if (NOT TAR_EXECUTABLE)
    message(WARNING "tar not found; will not build debian source package")
elseif (NOT DPKG_SOURCE_EXECUTABLE)
    message(WARNING "dpkg-source not found; will not build debian source package")
else()

    # generate debian/rules file
    set(RULES_IN ${CMAKE_CURRENT_SOURCE_DIR}/debian/rules.in)
    set(RULES_OUT ${CMAKE_CURRENT_SOURCE_DIR}/debian/rules)
    configure_file(${RULES_IN} ${RULES_OUT} @ONLY)

    # generate debian/control file
    set(CONTROL_IN ${CMAKE_CURRENT_SOURCE_DIR}/debian/control.in)
    set(CONTROL_OUT ${CMAKE_CURRENT_SOURCE_DIR}/debian/control)
    configure_file(${CONTROL_IN} ${CONTROL_OUT} @ONLY)

    # Copy Rust source files and Cargo toml files into source tarball
    set(GOSLING_SOURCE "${CMAKE_SOURCE_DIR}/..")
    set(GOSLING_TARBALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/gosling-${CGOSLING_VERSION}")
    set(GOSLING_TARBALL "${CMAKE_CURRENT_BINARY_DIR}/gosling_${CGOSLING_VERSION}.orig.tar.gz")
    add_custom_command(
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/debian
        OUTPUT
            ${GOSLING_TARBALL}
            ${CMAKE_CURRENT_BINARY_DIR}/gosling_${CGOSLING_VERSION}.debian.tar.xz
            ${CMAKE_CURRENT_BINARY_DIR}/gosling_${CGOSLING_VERSION}.dsc
        # build source tree
        COMMAND ${CMAKE_COMMAND} -E rm -rf ${GOSLING_TARBALL_DIR}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${GOSLING_TARBALL_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR} ${GOSLING_TARBALL_DIR}/source
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/../LICENSE.md ${GOSLING_TARBALL_DIR}/.
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/../README.md ${GOSLING_TARBALL_DIR}/.
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/../Makefile ${GOSLING_TARBALL_DIR}/.
        # delete optional submodules
        COMMAND ${CMAKE_COMMAND} -E rm -rf ${GOSLING_TARBALL_DIR}/source/extern/Catch2
        COMMAND ${CMAKE_COMMAND} -E rm -rf ${GOSLING_TARBALL_DIR}/source/extern/json

        # create source tar
        COMMAND tar -czf gosling_${CGOSLING_VERSION}.orig.tar.gz gosling-${CGOSLING_VERSION}
        # copy debian directory
        COMMAND cp -aP ${CMAKE_CURRENT_SOURCE_DIR}/debian ${GOSLING_TARBALL_DIR}/debian
        COMMAND ${CMAKE_COMMAND} -E rm ${GOSLING_TARBALL_DIR}/debian/*.in

        # build source package
        COMMAND dpkg-source -b ${GOSLING_TARBALL_DIR}
    )

    add_custom_target(cgosling_debian_source_package_target ALL
        DEPENDS
            ${GOSLING_TARBALL}
            ${CMAKE_CURRENT_BINARY_DIR}/gosling_${CGOSLING_VERSION}.debian.tar.xz
            ${CMAKE_CURRENT_BINARY_DIR}/gosling_${CGOSLING_VERSION}.dsc
    )
endif()

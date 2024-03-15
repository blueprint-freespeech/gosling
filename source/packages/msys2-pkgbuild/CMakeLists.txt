if (BUILD_MSYS2_PKGBUILD)
    # generate msys2 PKGBUILD build script
    set(PKGBUILD_IN ${CMAKE_CURRENT_SOURCE_DIR}/PKGBUILD.in)
    set(PKGBUILD_OUT ${CMAKE_CURRENT_BINARY_DIR}/PKGBUILD)
    configure_file(${PKGBUILD_IN} ${PKGBUILD_OUT} @ONLY)

    install(FILES ${PKGBUILD_OUT}
        DESTINATION ${CMAKE_INSTALL_DATADIR}/gosling/packages/msys2-pkgbuild)
endif()

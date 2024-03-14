if (BUILD_HOMEBREW_FORMULA)
    # generate homebrew formula .rb file
    set(LIBCGOSLING_RB_IN ${CMAKE_CURRENT_SOURCE_DIR}/libcgosling.rb.in)
    set(LIBCGOSLING_RB_OUT ${CMAKE_CURRENT_BINARY_DIR}/libcgosling.rb)
    configure_file(${LIBCGOSLING_RB_IN} ${LIBCGOSLING_RB_OUT} @ONLY)

    install(FILES ${LIBCGOSLING_RB_OUT}
        DESTINATION ${CMAKE_INSTALL_DATADIR}/gosling/packages/homebrew-formula)
endif()

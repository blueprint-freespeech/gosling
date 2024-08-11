# list of build output filenames
set(build_outputs)

# files which we will just copy directly
set(copy_sources
    "report_ngir-blueprintforfreespeech 1.1.pdf")

foreach(file ${copy_sources})
    add_custom_command(
        OUTPUT ${file}
        DEPENDS ${file}
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/${file}" ${file})
    list(APPEND build_outputs ${file})
endforeach()

add_custom_target(gosling_pages_pdfs_target ALL
    DEPENDS ${build_outputs}
)

#
# Install website pdfs
#
foreach(file ${build_outputs})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${file} DESTINATION ${CMAKE_INSTALL_DOCDIR}/pdfs)
endforeach()

# list of build output filenames
set(build_outputs)

# files which we will just copy directly
set(copy_sources
    "2022-11-16 - state-of-the-onion.pdf"
    "2022-11-18 - radically-open-security.pdf"
    "2023-12-06 - state-of-the-onion.pdf"
    "2024-05-02 - ripe-community-projects-fund.pdf"
    "2024-11-12 - radically-open-security.pdf"
    "2024-11-20 - state-of-the-onion.pdf"
    "2025-08-09 - why2025-slides.pdf"
    "2026-02-01 - fosdem2026-slides.pdf")

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

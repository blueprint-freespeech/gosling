if (BUILD_PAGES)

    find_program(PANDOC_EXECUTABLE NAMES pandoc)
    find_program(MUSTACHE_EXECUTABLE NAMES mustache)
    find_program(PLANTUML_EXECUTABLE NAMES plantuml)
    find_program(TIDY_EXECUTABLE NAMES tidy)

    if (NOT PANDOC_EXECUTABLE)
        message(FATAL_ERROR "pandoc not found; required to build pages")
    elseif(NOT MUSTACHE_EXECUTABLE)
        message(FATAL_ERROR "mustache not found; required to build pages")
    elseif(NOT PLANTUML_EXECUTABLE)
        message(FATAL_ERROR "plantuml not found; required to build pages")
    elseif(NOT TIDY_EXECUTABLE)
        message(FATAL_ERROR "tidy not found; required to build pages")
    endif()

    #
    # convert our markdown to html
    #

    add_subdirectory(images)
    add_subdirectory(pdfs)

    # list of build output filenames
    set(build_outputs)
    # list of final installed files
    set(deploy_outputs)

    # our source markdown files
    set(page_sources
        design-doc.md
        gosling-spec.md
        honk-rpc-spec.md
        index.md
        news.md
        security-reviews.md)

    # page titles for each
    set(page_titles
        Main
        News
        "Honk-RPC Specification"
        "Gosling Specification")

    # get current year for copyright notice
    string(TIMESTAMP year "%Y")

    # generate xhtml from page.mustache template and markdown
    foreach(file_md title IN ZIP_LISTS page_sources page_titles)
        get_filename_component(file ${file_md} NAME_WE)
        # generate .inc.xhtml from markdown sources
        set(file_inc_xhtml "${file}.inc.xhtml")
        add_custom_command(
            OUTPUT ${file_inc_xhtml}
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/content/${file_md}
            COMMAND pandoc -f markdown -t html5 ${CMAKE_CURRENT_SOURCE_DIR}/content/${file_md} -o ${file_inc_xhtml})
        # create .yml file for title
        set(file_yml "${file}.yml")
        add_custom_command(
            OUTPUT ${file_yml}
            COMMAND echo "title: ${title}" > ${file_yml}
            COMMAND echo "year: ${year}" >> ${file_yml})
        # generate .xhtml from template and sources
        set(file_xhtml "${file}.xhtml")
        add_custom_command(
            OUTPUT ${file_xhtml}
            DEPENDS ${file_inc_xhtml} ${file_yml} ${CMAKE_CURRENT_SOURCE_DIR}/templates/page.mustache
            COMMAND ${CMAKE_COMMAND} -E copy ${file_inc_xhtml} content.mustache
            COMMAND mustache ${file_yml} ${CMAKE_CURRENT_SOURCE_DIR}/templates/page.mustache > ${file_xhtml}
            COMMAND rm content.mustache)

        list(APPEND build_outputs ${file_xhtml})
    endforeach()

    # files which we will just copy directly
    set(copy_sources
        style.css)

    foreach(file ${copy_sources})
        add_custom_command(
            OUTPUT ${file}
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${file}
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${file})

        list(APPEND build_outputs ${file})
    endforeach()

    add_custom_target(gosling_pages_target ALL
        DEPENDS ${build_outputs} gosling_pages_images_target gosling_pages_pdfs_target
    )

    #
    # Install gosling website pages
    #
    foreach(file ${build_outputs})
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${file} DESTINATION ${CMAKE_INSTALL_DOCDIR})
    endforeach()
endif()

if (BUILD_PAGES)

    find_program(PANDOC_EXECUTABLE NAMES pandoc)
    find_program(MUSTACHE_EXECUTABLE NAMES mustache)
    find_program(PLANTUML_EXECUTABLE NAMES plantuml)
    find_program(TIDY_EXECUTABLE NAMES tidy)
    find_program(GIT_EXECUTABLE NAMES git)

    if (NOT PANDOC_EXECUTABLE)
        message(FATAL_ERROR "pandoc not found; required to build pages")
    else()
        message(STATUS "Found pandoc: ${PANDOC_EXECUTABLE}")
    endif()

    if(NOT MUSTACHE_EXECUTABLE)
        message(FATAL_ERROR "mustache not found; required to build pages")
    else()
        message(STATUS "Found mustache: ${MUSTACHE_EXECUTABLE}")
    endif()

    if(NOT PLANTUML_EXECUTABLE)
        message(FATAL_ERROR "plantuml not found; required to build pages")
    else()
        message(STATUS "Found plantuml: ${PLANTUML_EXECUTABLE}")
    endif()

    if(NOT TIDY_EXECUTABLE)
        message(FATAL_ERROR "tidy not found; required to build pages")
    else()
        message(STATUS: "Found tidy: ${TIDY_EXECUTABLE}")
    endif()

    if(GIT_EXECUTABLE)
        message(STATUS: "Found git: ${GIT_EXECUTABLE}")
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
        presentations.md
        security-reviews.md
        usage-guide.md)
    list(LENGTH page_sources page_sources_count)

    # page titles for each
    set(page_titles
        "Design Document"
        "Gosling Protocol Specification"
        "Honk-RPC Protocol Specification"
        "Main"
        "News"
        "Presentations"
        "Security Review"
        "Usage Guide")
    list(LENGTH page_titles page_titles_count)

    # ensure we are not missing titles or pages
    if(NOT page_sources_count EQUAL page_titles_count)
        message(FATAL_ERROR "mismatch in number of page sources and page titles")
    endif()

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
        if  (GIT_EXECUTABLE)
            execute_process(COMMAND git log -1 --pretty=format:%cs ${CMAKE_CURRENT_SOURCE_DIR}/content/${file_md} OUTPUT_VARIABLE modified_date)
        else ()
            set(modified_date "unknown")
        endif()

        add_custom_command(
            OUTPUT ${file_yml}
            COMMAND echo "title: ${title}" > ${file_yml}
            COMMAND echo "year: ${year}" >> ${file_yml}
            COMMAND echo "modified-date: ${modified_date}" >> ${file_yml})

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

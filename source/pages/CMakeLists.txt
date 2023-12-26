#
# convert our markdown to html
#

add_subdirectory(images)

# list of build output filenames
set(build_outputs)
# list of final installed files
set(install_outputs)

# our source markdown files
set(page_sources
    index.md
    news.md
    honk-rpc-spec.md
    gosling-spec.md)

# page titles for each
set(page_titles
    Main
    News
    "Honk-RPC Specification"
    "Gosling Specification")

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
        COMMAND echo "title: ${title}" > ${file_yml})
    # generate .xhtml from template and sources
    set(file_xhtml "${file}.xhtml")
    add_custom_command(
        OUTPUT ${file_xhtml}
        DEPENDS ${file_inc_xhtml} ${file_yml} ${CMAKE_CURRENT_SOURCE_DIR}/templates/page.mustache
        COMMAND cp ${file_inc_xhtml} content.mustache
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
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${file})

    list(APPEND build_outputs ${file})
endforeach()

add_custom_target(gosling_pages_target
    DEPENDS ${build_outputs} gosling_pages_images
)

#
# Install website pages
#

add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/website
    COMMAND mkdir -p ${CMAKE_INSTALL_PREFIX}/website
)
foreach(file ${build_outputs})
    add_custom_command(
        OUTPUT ${CMAKE_INSTALL_PREFIX}/website/${file}
        DEPENDS ${CMAKE_INSTALL_PREFIX}/website ${CMAKE_CURRENT_BINARY_DIR}/${file}
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/${file} ${CMAKE_INSTALL_PREFIX}/website/${file}
    )
    list(APPEND install_outputs ${CMAKE_INSTALL_PREFIX}/website/${file})
endforeach()

add_custom_target(install_pages
    DEPENDS ${install_outputs} install_gosling_pages_images
)

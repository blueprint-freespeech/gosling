#
# convert our markdown to html
#

# list of files to install
set(install_output)

# our source markdown files
set(page_sources
    index.md
    news.md)

# page titles for each
set(page_titles
    Gosling
    News)

# generate xhtml from page.mustache template and markdown
set(xhtml_output)
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
        OUTPUT ${file_xhtml} "${file}.content.mustache"
        DEPENDS ${file_inc_xhtml} ${file_yml} ${CMAKE_CURRENT_SOURCE_DIR}/templates/page.mustache
        COMMAND cp ${file_inc_xhtml} content.mustache
        COMMAND mustache ${file_yml} ${CMAKE_CURRENT_SOURCE_DIR}/templates/page.mustache > ${file_xhtml}
        COMMAND mv content.mustache "${file}.content.mustache")

    list(APPEND xhtml_output ${file_xhtml})
    list(APPEND install_output ${CMAKE_CURRENT_BINARY_DIR}/${file_xhtml})
endforeach()

# files which we will just copy directly
set(copy_sources
    style.css)

set(copy_output)
foreach(file ${copy_sources})
    add_custom_command(
        OUTPUT ${file}
        COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${file})

    list(APPEND copy_output ${file})
    list(APPEND install_output ${CMAKE_CURRENT_BINARY_DIR}/${file})
endforeach()

add_custom_target(gosling_pages
    DEPENDS ${xhtml_output} ${copy_output} gosling_pages_images
)

add_subdirectory(images)

install(FILES ${install_output}
    DESTINATION pages)
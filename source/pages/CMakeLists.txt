#
# convert our markdown to html
#

# our source markdown files
set(page_sources
    index.md
    example.md)

# page titles for each
set(page_titles
    Gosling
    Example)

# generate xhtml from page.mustache template and markdown
set(xhtml_output)
foreach(file_md title IN ZIP_LISTS page_sources page_titles)
    get_filename_component(file ${file_md} NAME_WE)
    # generate .inc.xhtml from markdown sources
    set(file_inc_xhtml "${file}.inc.xhtml")
    add_custom_command(
        OUTPUT ${file_inc_xhtml}
        COMMAND markdown ${CMAKE_CURRENT_SOURCE_DIR}/content/${file_md} > ${file_inc_xhtml}
        COMMAND cp ${file_inc_xhtml} content.mustache)
    # create .yml file for title
    set(file_yml "${file}.yml")
    add_custom_command(
        OUTPUT ${file_yml}
        COMMAND echo "title: ${title}" > ${file_yml})
    # generate .xhtml from template and sources
    set(file_xhtml "${file}.xhtml")
    add_custom_command(
        OUTPUT ${file_xhtml}
        DEPENDS ${file_inc_xhtml} ${file_yml}
        COMMAND mustache ${file_yml} ${CMAKE_CURRENT_SOURCE_DIR}/templates/page.mustache > ${file_xhtml}
        COMMAND mv content.mustache "${file}.content.mustache")

    list(APPEND xhtml_output ${file_xhtml})
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
endforeach()

add_custom_target(gosling_pages
    DEPENDS ${xhtml_output} ${copy_output} gosling_pages_images
)

add_subdirectory(images)

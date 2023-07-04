# files which we will just copy directly
set(copy_sources
    icon.png)

set(copy_output)
foreach(file ${copy_sources})
    add_custom_command(
        OUTPUT ${file}
        DEPENDS ${file}
        COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${file})
    list(APPEND copy_output ${file})
endforeach()

add_custom_target(gosling_pages_images
    DEPENDS ${copy_output}
)


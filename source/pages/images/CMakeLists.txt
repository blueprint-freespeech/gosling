# list of files to install
set(install_output)

# files which we will just copy directly
set(copy_sources
    favicon.png
    gosling-square-small-opt.svg)

set(copy_output)
foreach(file ${copy_sources})
    add_custom_command(
        OUTPUT ${file}
        DEPENDS ${file}
        COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${file})
    list(APPEND copy_output ${file})
    list(APPEND install_output ${CMAKE_CURRENT_BINARY_DIR}/${file})
endforeach()

add_custom_target(gosling_pages_images
    DEPENDS ${copy_output}
)

install(FILES ${install_output}
    DESTINATION pages/images)
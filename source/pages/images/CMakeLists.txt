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

# files which we need to generate via plantuml
set(plantuml_sources
    client_auth_signature.uml
    endpoint_handshake.uml
    identity_handshake.uml)

set(plantuml_output)
foreach(file_uml ${plantuml_sources})
    get_filename_component(file ${file_uml} NAME_WE)
    set(file_svg "${file}.svg")
    add_custom_command(
        OUTPUT ${file_svg}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${file_uml}
        COMMAND plantuml -tsvg ${CMAKE_CURRENT_SOURCE_DIR}/${file_uml} -output ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND tidy -xml -indent --hide-comments 1 --write-back 1 ${file_svg})
    list(APPEND plantuml_output ${file_svg})
    list(APPEND install_output ${CMAKE_CURRENT_BINARY_DIR}/${file_svg})
endforeach()

add_custom_target(gosling_pages_images
    DEPENDS ${copy_output} ${plantuml_output}
)

install(FILES ${install_output}
    DESTINATION pages/images)
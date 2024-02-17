# list of build output filenames
set(build_outputs)
# list of final installed files
set(deploy_outputs)

# files which we will just copy directly
set(copy_sources
    favicon.png
    gosling-square-small-opt.svg)

foreach(file ${copy_sources})
    add_custom_command(
        OUTPUT ${file}
        DEPENDS ${file}
        COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${file})
    list(APPEND build_outputs ${file})
    list(APPEND deploy_outputs ${CMAKE_CURRENT_BINARY_DIR}/${file})
endforeach()

# files which we need to generate via plantuml
set(plantuml_sources
    client_auth_signature.uml
    endpoint_handshake.uml
    identity_handshake.uml)

foreach(file_uml ${plantuml_sources})
    get_filename_component(file ${file_uml} NAME_WE)
    set(file_svg "${file}.svg")
    add_custom_command(
        OUTPUT ${file_svg}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${file_uml}
        COMMAND plantuml -tsvg ${CMAKE_CURRENT_SOURCE_DIR}/${file_uml} -output ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND tidy -xml -indent --hide-comments 1 --write-back 1 ${file_svg})
    list(APPEND build_outputs ${file_svg})
    list(APPEND deploy_outputs ${CMAKE_CURRENT_BINARY_DIR}/${file_svg})
endforeach()

add_custom_target(gosling_pages_images_target
    DEPENDS ${build_outputs}
)

#
# Install website images
#

add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/website/images
    COMMAND mkdir -p ${CMAKE_INSTALL_PREFIX}/website/images
)
foreach(file ${build_outputs})
    add_custom_command(
        OUTPUT ${CMAKE_INSTALL_PREFIX}/website/images/${file}
        DEPENDS ${CMAKE_INSTALL_PREFIX}/website/images ${CMAKE_CURRENT_BINARY_DIR}/${file}
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/${file} ${CMAKE_INSTALL_PREFIX}/website/images/${file}
    )
    list(APPEND deploy_outputs ${CMAKE_INSTALL_PREFIX}/website/images/${file})
endforeach()
add_custom_target(deploy_gosling_pages_images_website_target
    DEPENDS ${deploy_outputs} gosling_pages_images_target
)

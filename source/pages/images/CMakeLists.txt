# list of build output filenames
set(build_outputs)

# files which we will just copy directly
set(copy_sources
    favicon.png
    gosling-square-small-opt.svg)

foreach(file ${copy_sources})
    add_custom_command(
        OUTPUT ${file}
        DEPENDS ${file}
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${file})
    list(APPEND build_outputs ${file})
endforeach()

# files which we need to generate via plantuml
set(plantuml_sources
    client_auth_signature.uml
    client_auth_signature_verification.uml
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
endforeach()

add_custom_target(gosling_pages_images_target ALL
    DEPENDS ${build_outputs}
)

#
# Install website images
#
foreach(file ${build_outputs})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${file} DESTINATION ${CMAKE_INSTALL_DOCDIR}/images)
endforeach()

set(gosling_java_bindings_test_target_sources
    GoslingTest.java
)

set(gosling_java_bindings_test_target_depends
    $<TARGET_FILE_DIR:goslingjni>/Gosling.jar
    $<TARGET_FILE:goslingjni>
    ${gosling_java_bindings_test_target_sources}
)

set(gosling_java_bindings_test_target_outputs
    ${CMAKE_CURRENT_BINARY_DIR}/GoslingTest.class
)

#
# Build Java test
#
add_custom_command(
    DEPENDS ${gosling_java_bindings_test_target_depends}
    OUTPUT ${gosling_java_bindings_test_target_outputs}
    COMMAND javac -cp $<TARGET_FILE_DIR:goslingjni>/Gosling.jar ${gosling_java_bindings_test_target_sources} -d ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(gosling_java_bindings_test_target ALL
    DEPENDS ${gosling_java_bindings_test_target_outputs})
add_dependencies(gosling_java_bindings_test_target goslingjni)

#
# Run Java Test
#
add_test(NAME gosling_java_bindings_test_build
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --config $<CONFIG> --target gosling_java_bindings_test_target
)
set_tests_properties(gosling_java_bindings_test_build PROPERTIES FIXTURES_SETUP gosling_java_bindings_test_fixture)

if (WINDOWS)
    set(classes_separator "\;")
else()
    set(classes_separator ":")
endif()

add_test(NAME gosling_java_bindings_test
    COMMAND java -cp .${classes_separator}$<TARGET_FILE_DIR:goslingjni>/Gosling.jar -Djava.library.path=$<TARGET_FILE_DIR:goslingjni> GoslingTest
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(gosling_java_bindings_test PROPERTIES FIXTURES_REQUIRED gosling_java_bindings_test_fixture)

if (BUILD_JAVA_BINDINGS)
    find_package(Boost 1.66.0)
    include(FindJNI)

    if (NOT Boost_FOUND)
        message(FATAL_ERROR "Boost 1.66 or newer not found; will not generate Java bindings")
    elseif(NOT JNI_FOUND)
        message(FATAL_ERROR "Java JNI not found; will not generate Java bindings")
    endif()
    set(gosling_java_bindings_sources
        ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.json
        build_java_bindings.rs
        Cargo.toml
        Gosling.java.handlebars
        GoslingJNI.cpp.handlebars)
    set(gosling_java_bindings_outputs
        ${CMAKE_CURRENT_BINARY_DIR}/src/net/blueprintforfreespeech/gosling/Gosling.java
        ${CMAKE_CURRENT_BINARY_DIR}/Gosling.jar
        ${CMAKE_CURRENT_BINARY_DIR}/GoslingJNI.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/GoslingJNI.h)

    #
    # Generate Gosling.java, Gosling.jar, GoslingJNI.h, and GoslingJNI.cpp
    #

    # explicitly prepend the library prefix if it exists on Windows
    # required for mingw deployments which follow the Unix convention of prepending 'lib' (e.g. libopenssl) but Java's System.loadLibrary() expects no prefix on Windows regardless
    set (gosling_jni_library_name "goslingjni")
    if (WINDOWS)
        # no-op for MSVC
        set (gosling_jni_library_name "${CMAKE_SHARED_LIBRARY_PREFIX}${gosling_jni_library_name}")
    endif()

    add_custom_command(
        DEPENDS ${gosling_java_bindings_sources}
        OUTPUT ${gosling_java_bindings_outputs}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/src/net/blueprintforfreespeech/gosling
        # generate java source
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo run ${CARGO_FLAGS} --bin build_java_bindings ${gosling_jni_library_name} ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.json Gosling.java.handlebars ${CMAKE_CURRENT_BINARY_DIR}/src/net/blueprintforfreespeech/gosling/Gosling.java
        # build java classes and generate jni header
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/jar
        COMMAND javac -h ${CMAKE_CURRENT_BINARY_DIR} -d ${CMAKE_CURRENT_BINARY_DIR}/jar ${CMAKE_CURRENT_BINARY_DIR}/src/net/blueprintforfreespeech/gosling/Gosling.java
        # build java jar archive fomr built classes
        COMMAND jar -cvf ${CMAKE_CURRENT_BINARY_DIR}/Gosling.jar -C ${CMAKE_CURRENT_BINARY_DIR}/jar/ .
        # build jni shared library sources
        COMMAND ${CMAKE_COMMAND} -E rename ${CMAKE_CURRENT_BINARY_DIR}/net_blueprintforfreespeech_gosling_Gosling.h ${CMAKE_CURRENT_BINARY_DIR}/GoslingJNI.h
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo run ${CARGO_FLAGS} --bin build_java_bindings ${gosling_jni_library_name} ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/cgosling.json GoslingJNI.cpp.handlebars ${CMAKE_CURRENT_BINARY_DIR}/GoslingJNI.cpp
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    set(gosling_jni_sources
        ${CMAKE_CURRENT_BINARY_DIR}/GoslingJNI.cpp
    )

    # Create the JNI library
    add_library(goslingjni SHARED ${gosling_jni_sources})
    add_dependencies(goslingjni cgosling_target)
    target_include_directories(goslingjni PRIVATE ${JNI_INCLUDE_DIRS})
    target_include_directories(goslingjni PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(goslingjni PRIVATE ${Java_JVM_LIBRARY})
    target_link_libraries(goslingjni PRIVATE gosling_cpp_static_bindings)
    target_compile_features(goslingjni PRIVATE cxx_std_17)
    set_target_properties(goslingjni
        PROPERTIES
        VERSION ${CGOSLING_VERSION}
        SOVERSION ${CGOSLING_MAJOR_VERSION})

    add_custom_target(gosling_java_bindings_target)
    add_dependencies(gosling_java_bindings_target goslingjni)

    #
    # Install JNI library and Java jar archive
    #

    install(TARGETS goslingjni LIBRARY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Gosling.jar
        DESTINATION ${CMAKE_INSTALL_DATADIR}/gosling/bindings/java
    )

    if (ENABLE_LINTING)
        add_dependencies(linting goslingjni)
    endif()

    if (ENABLE_TESTS)
        add_subdirectory(test)
    endif()

    if (BUILD_PAGES)
        # Javadoc documentation
        find_program(javadoc_executable NAMES javadoc)

        if (NOT javadoc_executable)
            message(FATAL_ERROR "javadoc not found; required to generate Java documentation")
        else()
            set(javadoc_depends
                ${CMAKE_CURRENT_BINARY_DIR}/src/net/blueprintforfreespeech/gosling/Gosling.java)
            set(javadoc_output
                ${CMAKE_CURRENT_BINARY_DIR}/javadoc)

            # javadoc command
            add_custom_command(
                DEPENDS ${javadoc_depends}
                OUTPUT ${javadoc_output}
                COMMAND ${javadoc_executable} -d ${javadoc_output} ${javadoc_depends}
                )
            # make target
            add_custom_target(gosling_java_bindings_javadoc_target ALL
                DEPENDS ${javadoc_output})
            add_dependencies(gosling_java_bindings_javadoc_target gosling_java_bindings_target)

            # install
            install(DIRECTORY ${javadoc_output}/
                DESTINATION ${CMAKE_INSTALL_DOCDIR}/bindings/goslingjni)
        endif()
    endif()
endif()

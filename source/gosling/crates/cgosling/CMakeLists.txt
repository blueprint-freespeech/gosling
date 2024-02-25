find_program(PATCHELF_EXECUTABLE NAMES patchelf)

if (NOT PATCHELF_EXECUTABLE AND LINUX)
    message(FATAL_ERROR "Could not find patchelf executable; required for linux shared library generation")
else()
    set(CGOSLING_MAJOR_VERSION "0" CACHE STRING "SemVer major version of cgosling library" FORCE)
    set(CGOSLING_MINOR_VERSION "2" CACHE STRING "SemVer minor version of cgosling library" FORCE)
    set(CGOSLING_PATCH_VERSION "1" CACHE STRING "SemVer patch version of cgosling library" FORCE)
    set(CGOSLING_VERSION "${CGOSLING_MAJOR_VERSION}.${CGOSLING_MINOR_VERSION}.${CGOSLING_PATCH_VERSION}" CACHE STRING "SemVer of the cgosling library" FORCE)

    set(CARGO_TOML_IN ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml.in)
    set(CARGO_TOML_OUT ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml)
    configure_file(${CARGO_TOML_IN} ${CARGO_TOML_OUT} @ONLY)

    set(cgosling_sources
        build.rs
        Cargo.toml
        cbindgen.toml
        src/ffi.rs
        src/lib.rs
        src/object_registry.rs)

    set(CGOSLING_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}cgosling${CMAKE_STATIC_LIBRARY_SUFFIX}" CACHE STRING "cgosling static library filename" FORCE)
    if (MINGW)
        # Rust does not include the 'lib' prefix for mingw shared-library targets, so we need to handle that for mingw cmake to play nicely
        set(CGOSLING_SHARED "cgosling${CMAKE_SHARED_LIBRARY_SUFFIX}" CACHE STRING "cgosling shared library filename" FORCE)
    else()
        set(CGOSLING_SHARED "${CMAKE_SHARED_LIBRARY_PREFIX}cgosling${CMAKE_SHARED_LIBRARY_SUFFIX}" CACHE STRING "cgosling shared library filename" FORCE)
    endif()
    if ((DEFINED CMAKE_IMPORT_LIBRARY_SUFFIX))
        set(CGOSLING_IMPORT "${CMAKE_IMPORT_LIBRARY_PREFIX}cgosling${CMAKE_IMPORT_LIBRARY_SUFFIX}" CACHE STRING "cgosling import library filename" FORCE)
    endif()

    set(cgosling_outputs
        ${CARGO_TARGET_DIR}/include/cgosling.h
        ${CARGO_TARGET_DIR}/cgosling.json
        ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libcgosling.d
        ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/libcgosling.rlib
        ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_STATIC}
        ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}
    )

    # add shared library import library if platform supports it
    if ((DEFINED CGOSLING_IMPORT))
        list(APPEND cgosling_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_IMPORT})
    endif()

    #
    # build target
    #
    add_custom_command(
        DEPENDS ${cgosling_sources}
        OUTPUT ${cgosling_outputs}
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    # Cargo does not support populating soname elf field on Linux:
    # - https://github.com/rust-lang/cargo/issues/5045
    # populating soname manually with patchelf and rename output .so to include
    # the SemVer of the cgosling crate
    if (LINUX)
        # rename the generated .so and patch the soname
        add_custom_command(
            DEPENDS ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}
            OUTPUT ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}.${CGOSLING_VERSION}
            # rename our library to include the full SemVer
            COMMAND ${CMAKE_COMMAND} -E rename ${CGOSLING_SHARED} ${CGOSLING_SHARED}.${CGOSLING_VERSION}
            # update the soname of our library to include the SemVer mojor version
            COMMAND patchelf --set-soname libcgosling.so.${CGOSLING_MAJOR_VERSION} ${CGOSLING_SHARED}.${CGOSLING_VERSION}
            WORKING_DIRECTORY ${CARGO_TARGET_DIR}/${CARGO_PROFILE}
        )
        # generate symlinks
        add_custom_command(
            DEPENDS ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}.${CGOSLING_VERSION}
            OUTPUT
                ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION}
                ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}

            # create symlinks
            COMMAND ${CMAKE_COMMAND} -E create_symlink ${CGOSLING_SHARED}.${CGOSLING_VERSION} ${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION}
            COMMAND ${CMAKE_COMMAND} -E create_symlink ${CGOSLING_SHARED}.${CGOSLING_VERSION} ${CGOSLING_SHARED}
            WORKING_DIRECTORY ${CARGO_TARGET_DIR}/${CARGO_PROFILE}
        )
        # add symlinks to our cgosling_outputs list
        list(APPEND cgosling_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}.${CGOSLING_MAJOR_VERSION})
        list(APPEND cgosling_outputs ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${CGOSLING_SHARED}.${CGOSLING_VERSION})
    endif()
    add_custom_target(cgosling_target
        DEPENDS ${cgosling_outputs})
    add_dependencies(cgosling_target gosling_target)

    #
    # cargo test target
    #
    add_custom_target(cgosling_cargo_test_target
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_dependencies(test_target cgosling_cargo_test_target)

    #
    # cargo test (offline) target
    #
    add_custom_target(cgosling_cargo_test_offline_target
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS} --features offline-test
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_dependencies(test_offline_target cgosling_cargo_test_offline_target)

    #
    # fuzz targets
    #
    add_custom_target(gosling_cargo_fuzz_cgosling
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo fuzz run fuzz_cgosling ${CARGO_FLAGS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

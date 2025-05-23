
if("dynamic" STREQUAL "static" AND NOT WIN32)
    include(CMakeFindDependencyMacro)
    find_dependency(Threads)
endif()

if(NOT TARGET unofficial-sodium::sodium)
    add_library(unofficial-sodium::sodium UNKNOWN IMPORTED)

    set_target_properties(unofficial-sodium::sodium PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include"
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
    )

    if("dynamic" STREQUAL "static" AND NOT WIN32)
        set_target_properties(unofficial-sodium::sodium PROPERTIES
            INTERFACE_LINK_LIBRARIES Threads::Threads
        )
    endif()

    find_library(VCPKG_SODIUM_LIBRARY_RELEASE NAMES sodium libsodium PATHS "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib" NO_DEFAULT_PATH)
    if(EXISTS "${VCPKG_SODIUM_LIBRARY_RELEASE}")
        set_property(TARGET unofficial-sodium::sodium APPEND PROPERTY IMPORTED_CONFIGURATIONS "Release")
        set_target_properties(unofficial-sodium::sodium PROPERTIES IMPORTED_LOCATION_RELEASE "${VCPKG_SODIUM_LIBRARY_RELEASE}")
    endif()

    find_library(VCPKG_SODIUM_LIBRARY_DEBUG NAMES sodium libsodium PATHS "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/lib" NO_DEFAULT_PATH)
    if(EXISTS "${VCPKG_SODIUM_LIBRARY_DEBUG}")
        set_property(TARGET unofficial-sodium::sodium APPEND PROPERTY IMPORTED_CONFIGURATIONS "Debug")
        set_target_properties(unofficial-sodium::sodium PROPERTIES IMPORTED_LOCATION_DEBUG "${VCPKG_SODIUM_LIBRARY_DEBUG}")
    endif()
endif()

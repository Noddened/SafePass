cmake_minimum_required(VERSION 3.16)

project(sfps01 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SODIUM_ROOT "${CMAKE_SOURCE_DIR}/lib/sodium")
set(SODIUM_INCLUDE_DIR "${SODIUM_ROOT}/include")
set(SODIUM_LIB_DIR "${SODIUM_ROOT}/bin")

set(SQLITE_ROOT "${CMAKE_SOURCE_DIR}/lib/sqlite")

set(CPP_SOURCES
    src/cpp/main.cpp
)

add_executable(sfps01
    ${CPP_SOURCES}
)

target_include_directories(sfps01 PRIVATE
    ${SODIUM_INCLUDE_DIR}
    ${SQLITE_ROOT}
)

target_link_directories(sfps01 PRIVATE ${SODIUM_LIB_DIR})
target_link_libraries(sfps01 PRIVATE libsodium.dll)

target_link_directories(sfps01 PRIVATE ${SQLITE_ROOT})
target_link_libraries(sfps01 PRIVATE sqlite3.dll)

add_custom_command(TARGET sfps01 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
    "${SODIUM_LIB_DIR}/libsodium.dll"
    $<TARGET_FILE_DIR:sfps01>
    COMMAND ${CMAKE_COMMAND} -E copy
    "${SQLITE_ROOT}/sqlite3.dll"
    $<TARGET_FILE_DIR:sfps01>
)


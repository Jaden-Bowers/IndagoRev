cmake_minimum_required(VERSION 3.25)
project(IndagoTUI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(NCURSESW IMPORTED_TARGET ncursesw)
endif()
if(NOT NCURSESW_FOUND)
    message(STATUS "ncursesw not found - skipping indago-tui build")
    return()
endif()

add_executable(indago-tui
    main.cpp
    app.cpp
    ui.cpp)

target_link_libraries(indago-tui PRIVATE indago_core PkgConfig::NCURSESW)
target_include_directories(indago-tui PRIVATE ${NCURSESW_INCLUDE_DIRS})
target_compile_definitions(indago-tui PRIVATE
    INDAGO_TUI_VERSION="${PROJECT_VERSION}")

if(MSVC)
    target_compile_options(indago-tui PRIVATE /W4 /permissive- /EHsc)
    target_compile_definitions(indago-tui PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(indago-tui PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS indago-tui RUNTIME DESTINATION bin)

if(INDAGO_BUILD_TESTS AND UNIX)
    add_executable(indago_tui_tests ${CMAKE_CURRENT_SOURCE_DIR}/../tests/tui_tests.cpp)
    target_link_libraries(indago_tui_tests PRIVATE indago_core)
    find_library(INDAGO_UTIL_LIBRARY util)
    if(INDAGO_UTIL_LIBRARY)
        target_link_libraries(indago_tui_tests PRIVATE ${INDAGO_UTIL_LIBRARY})
    endif()
    add_dependencies(indago_tui_tests indago-tui)
    add_test(NAME indago_tui COMMAND indago_tui_tests $<TARGET_FILE:indago-tui>)
    set_tests_properties(indago_tui PROPERTIES TIMEOUT 120)
endif()
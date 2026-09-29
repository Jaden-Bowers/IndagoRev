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
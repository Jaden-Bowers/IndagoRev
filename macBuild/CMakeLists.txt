cmake_minimum_required(VERSION 3.25)
project(IndagoMac LANGUAGES C CXX)
if(NOT APPLE)
  message(FATAL_ERROR "macBuild currently supports macOS only.")
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_OSX_ARCHITECTURES arm64)
set(CMAKE_OSX_DEPLOYMENT_TARGET 13.0)
add_library(indago_mac_core project.cpp file_io.cpp analysis.cpp)
target_include_directories(indago_mac_core PUBLIC . ../vendor/nlohmann)
get_filename_component(INDAGO_MAC_ROOT ".." ABSOLUTE)
target_compile_definitions(indago_mac_core PRIVATE INDAGO_MAC_ROOT="${INDAGO_MAC_ROOT}")
target_compile_options(indago_mac_core PRIVATE -Wall -Wextra -Wpedantic)
add_executable(indago-mac cli.cpp)
target_link_libraries(indago-mac PRIVATE indago_mac_core)
add_library(indago_mac_controller controller.cpp ../gui/mock_workbench.cpp)
target_link_libraries(indago_mac_controller PUBLIC indago_mac_core)

# Reuse both existing layouts and the Cocoa/Metal window adapter. Only this
# target enables live analysis; the original GUI targets retain their mock mode.
enable_language(OBJCXX)
set(CMAKE_OBJCXX_STANDARD 20)
set(IMGUI "${CMAKE_CURRENT_SOURCE_DIR}/../vendor/imgui")
set(IMGUI_CORE ${IMGUI}/imgui.cpp ${IMGUI}/imgui_draw.cpp
  ${IMGUI}/imgui_tables.cpp ${IMGUI}/imgui_widgets.cpp)
add_executable(indago-mac-gui MACOSX_BUNDLE desktop.mm ../gui/main_macos.mm
  ../gui/workbench.cpp ${IMGUI_CORE} ${IMGUI}/misc/cpp/imgui_stdlib.cpp
  ${IMGUI}/backends/imgui_impl_osx.mm ${IMGUI}/backends/imgui_impl_metal.mm)
target_include_directories(indago-mac-gui PRIVATE ../gui ${IMGUI} ${IMGUI}/backends ${IMGUI}/misc/cpp)
target_compile_definitions(indago-mac-gui PRIVATE INDAGO_MAC_LIVE INDAGO_MAC_ROOT="${INDAGO_MAC_ROOT}")
target_compile_options(indago-mac-gui PRIVATE "$<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>")
target_link_libraries(indago-mac-gui PRIVATE indago_mac_controller
  "-framework Cocoa" "-framework Metal" "-framework MetalKit"
  "-framework QuartzCore" "-framework GameController")
set_target_properties(indago-mac-gui PROPERTIES OUTPUT_NAME IndagoRev-ARM64
  MACOSX_BUNDLE_GUI_IDENTIFIER local.indagorev.arm64
  MACOSX_BUNDLE_BUNDLE_NAME "IndagoRev ARM64"
  MACOSX_BUNDLE_SHORT_VERSION_STRING "0.1.0"
  MACOSX_BUNDLE_BUNDLE_VERSION "1")
include(CTest)
if(BUILD_TESTING)
  add_executable(mac-analysis-fixture tests/fixture.c)
  add_executable(mac-project-tests tests/project_tests.cpp)
  target_link_libraries(mac-project-tests PRIVATE indago_mac_core)
  add_test(NAME mac-project COMMAND mac-project-tests)
  add_executable(mac-live-tests tests/live_workbench_tests.cpp
    ${IMGUI_CORE} ${IMGUI}/misc/cpp/imgui_stdlib.cpp)
  target_include_directories(mac-live-tests PRIVATE ${IMGUI} ${IMGUI}/misc/cpp)
  target_compile_definitions(mac-live-tests PRIVATE IMGUI_ENABLE_TEST_ENGINE)
  target_link_libraries(mac-live-tests PRIVATE indago_mac_controller)
  add_test(NAME mac-live-analysis-and-gui COMMAND mac-live-tests $<TARGET_FILE:mac-analysis-fixture>)
  set_tests_properties(mac-live-analysis-and-gui PROPERTIES TIMEOUT 240)
  add_executable(mac-large-file-tests tests/large_file_tests.cpp)
  target_link_libraries(mac-large-file-tests PRIVATE indago_mac_core)
  add_test(NAME mac-large-files COMMAND mac-large-file-tests $<TARGET_FILE:mac-analysis-fixture>)
  set_tests_properties(mac-large-files PROPERTIES TIMEOUT 300)
endif()

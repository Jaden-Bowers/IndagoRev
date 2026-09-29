cmake_minimum_required(VERSION 3.25)
project(IndagoWorkbench LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(IMGUI ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/imgui)
# Compile the checked-in ImGui sources; building requires no dependency download.
set(IMGUI_CORE ${IMGUI}/imgui.cpp ${IMGUI}/imgui_draw.cpp
  ${IMGUI}/imgui_tables.cpp ${IMGUI}/imgui_widgets.cpp)

if(APPLE)
  # OBJCXX enables .mm files. MACOSX_BUNDLE packages the executable as a clickable
  # .app; workbench.cpp remains ordinary C++ and contains the actual UI layout.
  enable_language(OBJCXX)
  set(CMAKE_OBJCXX_STANDARD 20)
  add_executable(indago-gui MACOSX_BUNDLE main_macos.mm workbench.cpp
    ${IMGUI_CORE}
    ${IMGUI}/backends/imgui_impl_osx.mm
    ${IMGUI}/backends/imgui_impl_metal.mm)
  # Apply automatic Objective-C memory management only to Objective-C++ files.
  target_compile_options(indago-gui PRIVATE "$<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>")
  # Link Apple's window/graphics frameworks, including those used by the official
  # ImGui backends. These are operating-system libraries, not analysis tools.
  target_link_libraries(indago-gui PRIVATE
    "-framework Cocoa" "-framework Metal" "-framework MetalKit"
    "-framework QuartzCore" "-framework GameController")
  set_target_properties(indago-gui PROPERTIES
    OUTPUT_NAME IndagoRev
    MACOSX_BUNDLE_GUI_IDENTIFIER local.indagorev.mock
    MACOSX_BUNDLE_BUNDLE_NAME IndagoRev)
  install(TARGETS indago-gui BUNDLE DESTINATION .)
elseif(WIN32)
  # Keep the existing Windows application and its tool integration unchanged.
  add_executable(indago-gui WIN32 main.cpp ${IMGUI_CORE}
    ${IMGUI}/backends/imgui_impl_win32.cpp
    ${IMGUI}/backends/imgui_impl_dx11.cpp
    ${IMGUI}/misc/cpp/imgui_stdlib.cpp)
  target_include_directories(indago-gui PRIVATE ${IMGUI}/misc/cpp ../vendor/nlohmann)
  target_compile_definitions(indago-gui PRIVATE UNICODE _UNICODE NOMINMAX)
  target_link_libraries(indago-gui PRIVATE d3d11 dxgi dwmapi shell32 ole32 uuid)
  install(TARGETS indago-gui RUNTIME DESTINATION .)
else()
  message(FATAL_ERROR "The desktop GUI currently supports macOS and Windows.")
endif()
# Tell the compiler where to find headers such as imgui.h and imgui_impl_metal.h.
target_include_directories(indago-gui PRIVATE ${IMGUI} ${IMGUI}/backends)

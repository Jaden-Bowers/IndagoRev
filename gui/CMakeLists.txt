cmake_minimum_required(VERSION 3.25)
project(IndagoWorkbench LANGUAGES CXX)
if(NOT WIN32)
  message(FATAL_ERROR "The first desktop platform backend is Windows (Win32/D3D11). The analysis CLI remains cross-platform.")
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(IMGUI ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/imgui)
add_executable(indago-gui WIN32 main.cpp
  ${IMGUI}/imgui.cpp ${IMGUI}/imgui_draw.cpp ${IMGUI}/imgui_tables.cpp ${IMGUI}/imgui_widgets.cpp
  ${IMGUI}/backends/imgui_impl_win32.cpp ${IMGUI}/backends/imgui_impl_dx11.cpp
  ${IMGUI}/misc/cpp/imgui_stdlib.cpp)
target_include_directories(indago-gui PRIVATE ${IMGUI} ${IMGUI}/backends ${IMGUI}/misc/cpp ../vendor/nlohmann)
target_compile_definitions(indago-gui PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(indago-gui PRIVATE d3d11 dxgi dwmapi shell32 ole32 uuid)
install(TARGETS indago-gui RUNTIME DESTINATION .)

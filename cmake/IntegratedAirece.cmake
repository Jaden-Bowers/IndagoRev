# Compile the existing proof-of-concept implementation into the platform.
# Keep its CLI entry as an internal worker mode of the same executable so
# process cancellation and memory isolation do not require a second binary.
add_subdirectory(xair/XAIR_SYM build-xair-sym)
set(_airece "${CMAKE_CURRENT_SOURCE_DIR}/components/airece")
set(AIRECE_BENCHMARK_FREEZE "indago-integrated-development")
foreach(_component XAIR XAIR_CFG XAIR_SYM)
    execute_process(COMMAND git -C "${CMAKE_CURRENT_SOURCE_DIR}/xair/${_component}" rev-parse HEAD
        OUTPUT_VARIABLE AIRECE_${_component}_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE)
endforeach()
set(AIRECE_ZYDIS_VERSION "5.0.0")
set(AIRECE_Z3_VERSION "5.0.0")
get_target_property(_z3_dir libz3 SOURCE_DIR)
execute_process(COMMAND git -C "${_z3_dir}/.." rev-parse HEAD
    OUTPUT_VARIABLE AIRECE_Z3_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(NOT AIRECE_Z3_REVISION)
    set(AIRECE_Z3_REVISION "source-build; revision unavailable")
endif()
if(MSVC)
    set(AIRECE_STATIC_RUNTIME_TEXT "yes")
else()
    set(AIRECE_STATIC_RUNTIME_TEXT "no")
endif()
configure_file("${_airece}/cmake/airece_build_config.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/airece_build_config.hpp" @ONLY)
add_library(indago_airece STATIC
    "${_airece}/src/emit/agent_json.cpp"
    "${_airece}/src/emit/semantic_json.cpp"
    "${_airece}/src/emit/semantic_text.cpp"
    "${_airece}/src/semantic/api_model.cpp"
    "${_airece}/src/semantic/compact_view.cpp"
    "${_airece}/src/semantic/control_view.cpp"
    "${_airece}/src/semantic/directed_flow.cpp"
    "${_airece}/src/semantic/enrichment.cpp"
    "${_airece}/src/semantic/expression_view.cpp"
    "${_airece}/src/semantic/variable_view.cpp"
    "${_airece}/src/session/analysis_session.cpp"
    "${_airece}/src/session/decode_cache.cpp"
    "${_airece}/src/version.cpp"
    "${_airece}/src/cli/main.cpp")
set_source_files_properties("${_airece}/src/cli/main.cpp" PROPERTIES COMPILE_DEFINITIONS "main=indago_airece_main")
target_include_directories(indago_airece PUBLIC "${_airece}/include" PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(indago_airece PRIVATE AIRECE_BUILD_CONFIG="$<CONFIG>")
target_link_libraries(indago_airece PUBLIC xair_sym)
target_link_libraries(indago_core PUBLIC indago_airece)

get_target_property(_z3_dir libz3 SOURCE_DIR)
set(_notices "# IndagoRev integrated analysis dependency notices\n\n")
foreach(_license IN ITEMS
    "${CMAKE_CURRENT_SOURCE_DIR}/components/airece/LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/xair/XAIR/LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/xair/XAIR_CFG/LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/xair/XAIR_SYM/LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/zydis/LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/zydis/dependencies/zycore/LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/nlohmann/LICENSE.MIT"
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/sqlite3/LICENSE.md"
    "${_z3_dir}/../LICENSE.txt")
    file(READ "${_license}" _text)
    string(APPEND _notices "\n## ${_license}\n\n${_text}\n")
endforeach()
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/THIRD_PARTY_NOTICES.md" CONTENT "${_notices}")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/THIRD_PARTY_NOTICES.md" DESTINATION share/indago)

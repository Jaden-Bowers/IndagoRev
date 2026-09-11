cmake_minimum_required(VERSION 3.25)
project(IndagoRev VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

option(INDAGO_ENABLE_XAIR "Link the checked-out XAIR and XAIR_CFG engines" ON)
option(INDAGO_BUILD_TESTS "Build IndagoRev verification tests" ON)
foreach(_contract action result evidence workbench)
    string(TOUPPER "${_contract}" _upper)
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/contracts/json/indago.${_contract}.v1.schema.json" ${_upper}_SCHEMA)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "contracts/json/indago.${_contract}.v1.schema.json")
endforeach()
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/contracts/json/indago.runtime-action.v1.schema.json" RUNTIME_ACTION_SCHEMA)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "contracts/json/indago.runtime-action.v1.schema.json")
configure_file(cmake/contracts_data.hpp.in generated/contracts_data.hpp @ONLY)

add_library(indago_sqlite STATIC vendor/sqlite3/sqlite3.c)
target_include_directories(indago_sqlite PUBLIC vendor/sqlite3)
target_compile_definitions(indago_sqlite PRIVATE SQLITE_THREADSAFE=1 SQLITE_DQS=0)

add_library(indago_core STATIC
    src/core.cpp
    src/workbench.cpp
    src/system_manifest.cpp
    src/harness.cpp
    src/model_provider.cpp
    src/model_http.cpp
    src/model_controller.cpp
    src/knowledge.cpp
    src/knowledge_graph.cpp
    src/knowledge_artifacts.cpp
    src/workbench_batch.cpp
    src/workbench_bundle.cpp
    src/sha256.cpp
    src/xair_backend.cpp
    src/ghidra_backend.cpp
    src/ilspy_backend.cpp
    src/enrichment_backend.cpp
    src/lief_backend.cpp
    src/lief_worker.cpp
    src/wireshark_backend.cpp
    src/airece_worker.cpp
    src/xair_query.cpp
    src/sym_backend.cpp
    src/service.cpp
    src/contracts.cpp
    src/static_index.cpp
    src/runtime.cpp
    src/runtime_rr.cpp
    src/runtime_capture.cpp
    src/runtime_image.cpp
    src/runtime_dbgeng.cpp
    src/runtime_payload.cpp
    src/runtime_gdb.cpp
    src/runtime_symbolic.cpp
)
target_include_directories(indago_core PUBLIC include vendor)
target_include_directories(indago_core PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(indago_core PUBLIC indago_sqlite)
include(cmake/IntegratedLief.cmake)
target_link_libraries(indago_core PUBLIC libzstd_static)
target_include_directories(indago_core PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/vendor/zstd/upstream/lib")
if(WIN32)
    target_link_libraries(indago_core PUBLIC winhttp)
else()
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL REQUIRED)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(INDAGO_OPENSSL REQUIRED openssl)
    set(_openssl_saved_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    foreach(_dependency IN LISTS INDAGO_OPENSSL_STATIC_LIBRARIES)
        string(REGEX REPLACE "^:" "" _dependency_name "${_dependency}")
        string(MAKE_C_IDENTIFIER "${_dependency_name}" _dependency_key)
        find_library(_openssl_static_${_dependency_key} NAMES "${_dependency_name}" HINTS ${INDAGO_OPENSSL_STATIC_LIBRARY_DIRS} REQUIRED)
        target_link_libraries(indago_core PUBLIC "${_openssl_static_${_dependency_key}}")
    endforeach()
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${_openssl_saved_suffixes}")
    target_include_directories(indago_core PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_options(indago_core INTERFACE ${INDAGO_OPENSSL_STATIC_LDFLAGS_OTHER})
endif()
target_compile_definitions(indago_core PUBLIC
    INDAGO_VERSION="${PROJECT_VERSION}"
    INDAGO_SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")

if(MSVC)
    target_compile_options(indago_core PRIVATE /W4 /permissive- /EHsc)
    target_compile_definitions(indago_core PUBLIC _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(indago_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(INDAGO_ENABLE_XAIR)
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(XAIR_BUILD_ALL OFF CACHE BOOL "" FORCE)
    set(XAIR_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(XAIR_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
    set(XAIR_BUILD_FUZZERS OFF CACHE BOOL "" FORCE)
    set(XAIR_USE_ZYDIS ON CACHE BOOL "" FORCE)
    set(XAIR_ENABLE_BOOTSTRAP_DECODER OFF CACHE BOOL "" FORCE)
    set(XAIR_ZYDIS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/vendor/zydis" CACHE PATH "" FORCE)
    set(XAIR_CFG_ENABLE_LEGACY_DECODERS OFF CACHE BOOL "" FORCE)
    add_subdirectory(xair/XAIR build-xair)
    add_subdirectory(xair/XAIR_CFG build-xair-cfg)
    target_link_libraries(indago_core PUBLIC xair xair_cfg)
    target_compile_definitions(indago_core PUBLIC INDAGO_HAS_XAIR=1)
    include(cmake/IntegratedAirece.cmake)
else()
    target_compile_definitions(indago_core PUBLIC INDAGO_HAS_XAIR=0)
endif()

# Z3 unconditionally creates an uninstall target; upstream Zstd checks for it.
# Include Zstd afterward to compose both unmodified upstream CMake projects.
include(cmake/IntegratedZstd.cmake)
add_executable(indago src/main.cpp)
target_link_libraries(indago PRIVATE indago_core)
include(cmake/BundledEngines.cmake)
add_executable(indago_runtime_fixture EXCLUDE_FROM_ALL tests/runtime_fixture.c)
add_executable(indago_telemetry_fixture EXCLUDE_FROM_ALL tests/telemetry_fixture.c)
if(MSVC)
    target_compile_options(indago_runtime_fixture PRIVATE /Od)
else()
    target_compile_options(indago_runtime_fixture PRIVATE -O0)
    target_link_options(indago_runtime_fixture PRIVATE -rdynamic)
endif()

enable_testing()
if(INDAGO_BUILD_TESTS)
    add_test(NAME indago_version COMMAND indago version)
    add_test(NAME indago_capabilities COMMAND indago capabilities)
    add_executable(indago_worker_tests tests/airece_worker_tests.cpp)
    target_link_libraries(indago_worker_tests PRIVATE indago_core)
    add_dependencies(indago_worker_tests indago)
    add_test(NAME indago_worker_process COMMAND indago_worker_tests)
    add_executable(indago_core_tests tests/core_tests.cpp)
    add_executable(indago_knowledge_tests tests/knowledge_tests.cpp)
    add_executable(indago_harness_tests tests/harness_tests.cpp)
    target_link_libraries(indago_harness_tests PRIVATE indago_core)
    add_test(NAME indago_harness COMMAND indago_harness_tests)
    add_executable(indago_io_fixture tests/io_fixture.c)
    add_dependencies(indago_harness_tests indago_io_fixture)
    add_executable(indago_model_tests tests/model_tests.cpp)
    target_link_libraries(indago_model_tests PRIVATE indago_core)
    add_dependencies(indago_model_tests indago)
    add_test(NAME indago_model_controller COMMAND indago_model_tests)
    add_executable(indago_model_http_tests tests/model_http_tests.cpp)
    target_link_libraries(indago_model_http_tests PRIVATE indago_core)
    if(WIN32)
        target_link_libraries(indago_model_http_tests PRIVATE ws2_32)
    endif()
    add_test(NAME indago_model_http COMMAND indago_model_http_tests)
    target_link_libraries(indago_knowledge_tests PRIVATE indago_core)
    add_test(NAME indago_knowledge_workbench COMMAND indago_knowledge_tests)
    add_executable(indago_runtime_path_tests tests/runtime_path_tests.cpp)
    target_link_libraries(indago_runtime_path_tests PRIVATE indago_core)
    add_test(NAME indago_runtime_path COMMAND indago_runtime_path_tests)
    target_link_libraries(indago_core_tests PRIVATE indago_core)
    add_test(NAME indago_core_contracts COMMAND indago_core_tests)
    add_executable(indago_static_model_tests tests/static_model_tests.cpp)
    target_link_libraries(indago_static_model_tests PRIVATE indago_core)
    add_test(NAME indago_static_model COMMAND indago_static_model_tests)
    if(INDAGO_ENABLE_XAIR)
        add_executable(indago_xair_tests tests/xair_query_tests.cpp)
        target_link_libraries(indago_xair_tests PRIVATE indago_core)
        add_dependencies(indago_xair_tests indago)
        add_test(NAME indago_xair_queries COMMAND indago_xair_tests "${CMAKE_CURRENT_SOURCE_DIR}/xair/XAIR/tests/corpus/phase3/control-flow.pe64")
        add_test(NAME indago_airece_operations COMMAND indago_worker_tests "${CMAKE_CURRENT_SOURCE_DIR}/xair/XAIR/tests/corpus/phase3/control-flow.pe64")
        if(WIN32)
            find_program(INDAGO_POWERSHELL NAMES pwsh powershell REQUIRED)
            add_test(NAME indago_single_binary COMMAND "${INDAGO_POWERSHELL}" -NoProfile -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/integrated_airece.ps1" -Executable "$<TARGET_FILE:indago>")
            add_test(NAME indago_job_lifecycle COMMAND "${INDAGO_POWERSHELL}" -NoProfile -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/job_lifecycle.ps1" -Executable "$<TARGET_FILE:indago>")
        endif()
    endif()
endif()

install(TARGETS indago RUNTIME DESTINATION bin)
install(DIRECTORY workers/ghidra/scripts DESTINATION workers/ghidra)

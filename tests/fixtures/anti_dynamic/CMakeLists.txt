cmake_minimum_required(VERSION 3.25)
project(IndagoAntiDynamicFixtures LANGUAGES C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "These anti-dynamic-analysis fixtures require Linux")
endif()

function(add_anti_dynamic_fixture name)
  add_executable(indago_anti_${name} ${name}.c)
  set_target_properties(indago_anti_${name} PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  target_compile_options(indago_anti_${name} PRIVATE
    -O0 -g -fno-inline -Wall -Wextra -Wpedantic -Werror)
endfunction()

add_anti_dynamic_fixture(ptrace_guard)
add_anti_dynamic_fixture(tracer_status)
add_anti_dynamic_fixture(encrypted_records)
add_anti_dynamic_fixture(timing_guard)
add_anti_dynamic_fixture(signal_guard)
add_anti_dynamic_fixture(encrypted_code)

include(CTest)
option(INDAGO_ANTI_ENABLE_GDB_TESTS "Register tests requiring ptrace and GDB" OFF)
if(BUILD_TESTING)
  find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
  set(harness "${CMAKE_CURRENT_SOURCE_DIR}/../../anti_dynamic_harness.py")
  add_test(NAME anti_dynamic_harness_unit
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../../anti_dynamic_harness_tests.py")
  add_test(NAME anti_dynamic_native
    COMMAND "${Python3_EXECUTABLE}" "${harness}" --no-build
      --build-dir "$<TARGET_FILE_DIR:indago_anti_ptrace_guard>")
  set_tests_properties(anti_dynamic_harness_unit PROPERTIES TIMEOUT 30)
  set_tests_properties(anti_dynamic_native PROPERTIES TIMEOUT 180)
  if(INDAGO_ANTI_ENABLE_GDB_TESTS)
    find_program(INDAGO_ANTI_GDB gdb REQUIRED)
    add_test(NAME anti_dynamic_gdb
      COMMAND "${Python3_EXECUTABLE}" "${harness}" --no-build --gdb --require-capabilities
        --build-dir "$<TARGET_FILE_DIR:indago_anti_ptrace_guard>")
    set_tests_properties(anti_dynamic_gdb PROPERTIES TIMEOUT 300)
  endif()
endif()

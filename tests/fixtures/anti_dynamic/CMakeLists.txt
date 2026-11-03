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

cmake_minimum_required(VERSION 3.25)
project(IndagoStringSniperFixtures LANGUAGES C)

# Compile-only analysis inputs. No test registrations or execution steps.
function(add_sniper_fixture name)
  add_executable(indago_sniper_${name} ${name}.c)
  set_target_properties(indago_sniper_${name} PROPERTIES
    C_STANDARD 99 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  if(MSVC)
    set_property(TARGET indago_sniper_${name} PROPERTY MSVC_RUNTIME_LIBRARY MultiThreaded)
    target_compile_options(indago_sniper_${name} PRIVATE /Od /Ob0 /GF- /W4)
    target_link_options(indago_sniper_${name} PRIVATE /OPT:NOREF /OPT:NOICF)
  else()
    target_compile_options(indago_sniper_${name} PRIVATE -O0 -fno-inline -fno-merge-constants -Wall -Wextra)
  endif()
endfunction()


add_sniper_fixture(network)

add_sniper_fixture(credentials)

add_sniper_fixture(paths)

option(INDAGO_REQUIRE_FULL_ANALYSIS "Reject incomplete full-analysis staging" OFF)
if(INDAGO_REQUIRE_FULL_ANALYSIS)
    if(NOT TARGET LIEF::LIEF)
        message(FATAL_ERROR "Full analysis requires the staged LIEF SDK; see docs/building.md")
    endif()
    foreach(_engine ghidra ilspy enrichment network frida dynamorio emulation)
        if(NOT IS_DIRECTORY "${INDAGO_RUNTIME_PAYLOAD_DIR}/${_engine}")
            message(FATAL_ERROR "Full analysis requires ${_engine} staging; see docs/building.md")
        endif()
    endforeach()
    if(NOT WIN32 AND NOT EXISTS "${INDAGO_RUNTIME_PAYLOAD_DIR}/gdb/bin/gdb")
        message(FATAL_ERROR "Full Linux analysis requires private GDB")
    endif()
    find_program(INDAGO_NODE_EXECUTABLE NAMES node REQUIRED)
    add_custom_command(TARGET indago POST_BUILD
        COMMAND "${INDAGO_NODE_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/check-build-capabilities.cjs"
            "$<TARGET_FILE:indago>" full "${CMAKE_CURRENT_BINARY_DIR}/capabilities.full.json"
        COMMENT "Verify full analysis capabilities and write a portable build manifest"
        VERBATIM)
endif()

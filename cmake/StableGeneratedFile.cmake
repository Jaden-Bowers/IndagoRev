# Preserve literal bytes (including template-like tokens and semicolons) and
# avoid touching build inputs when a configure run reproduces identical content.
# Payload discovery, hashing and dependency tracking remain in BundledEngines.
function(indago_write_if_different output content)
    if(EXISTS "${output}")
        file(READ "${output}" previous)
        if("${previous}" STREQUAL "${content}")
            return()
        endif()
    endif()
    file(WRITE "${output}" "${content}")
endfunction()

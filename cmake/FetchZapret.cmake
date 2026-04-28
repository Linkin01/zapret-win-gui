include(FetchContent)

message(STATUS "Fetching zapret-win-bundle from GitHub (shallow clone)...")
FetchContent_Declare(
    zapret_bundle
    GIT_REPOSITORY https://github.com/bol-van/zapret-win-bundle.git
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)
FetchContent_MakeAvailable(zapret_bundle)

# Pre-built binaries live in zapret-winws/ subdirectory of the bundle
set(ZAPRET_BUNDLE_DIR "${zapret_bundle_SOURCE_DIR}/zapret-winws")

# Copy binaries to res/ directory so resource.rc can find them
# (rc.exe resolves paths relative to the .rc file location)
set(ZAPRET_EMBED_DIR "${CMAKE_SOURCE_DIR}/res" CACHE INTERNAL "Path where zapret binaries are placed for embedding")

# Files we need to embed in the final exe (from zapret-winws/)
set(ZAPRET_EMBED_FILES
    "winws.exe"
    "cygwin1.dll"
    "WinDivert.dll"
    "WinDivert64.sys"
)

# Fake payload files from blockcheck/zapret/files/fake/
set(ZAPRET_FAKE_DIR "${zapret_bundle_SOURCE_DIR}/blockcheck/zapret/files/fake")
set(ZAPRET_FAKE_FILES
    "tls_clienthello_www_google_com.bin"
    "stun.bin"
)

# QUIC payload from zapret-winws/files/ (different subdirectory)
set(ZAPRET_WINWS_FILES_DIR "${zapret_bundle_SOURCE_DIR}/zapret-winws/files")
set(ZAPRET_WINWS_EXTRA_FILES
    "quic_initial_www_google_com.bin"
)

set(_all_found TRUE)
foreach(fname ${ZAPRET_EMBED_FILES})
    set(_src "${ZAPRET_BUNDLE_DIR}/${fname}")
    set(_dst "${ZAPRET_EMBED_DIR}/${fname}")

    if(EXISTS "${_src}")
        # Only copy if source is newer or dest doesn't exist
        file(COPY_FILE "${_src}" "${_dst}" ONLY_IF_DIFFERENT)
        file(SIZE "${_dst}" _fsize)
        message(STATUS "  Embedded: ${fname} (${_fsize} bytes)")
    else()
        message(WARNING "  NOT FOUND: ${_src}")
        set(_all_found FALSE)
    endif()
endforeach()

# Copy fake payload files from blockcheck subdirectory
foreach(fname ${ZAPRET_FAKE_FILES})
    set(_src "${ZAPRET_FAKE_DIR}/${fname}")
    set(_dst "${ZAPRET_EMBED_DIR}/${fname}")

    if(EXISTS "${_src}")
        file(COPY_FILE "${_src}" "${_dst}" ONLY_IF_DIFFERENT)
        file(SIZE "${_dst}" _fsize)
        message(STATUS "  Embedded: ${fname} (${_fsize} bytes) [fake payload]")
    else()
        message(WARNING "  NOT FOUND: ${_src}")
        set(_all_found FALSE)
    endif()
endforeach()

# Copy QUIC payload from zapret-winws/files/
foreach(fname ${ZAPRET_WINWS_EXTRA_FILES})
    set(_src "${ZAPRET_WINWS_FILES_DIR}/${fname}")
    set(_dst "${ZAPRET_EMBED_DIR}/${fname}")

    if(EXISTS "${_src}")
        file(COPY_FILE "${_src}" "${_dst}" ONLY_IF_DIFFERENT)
        file(SIZE "${_dst}" _fsize)
        message(STATUS "  Embedded: ${fname} (${_fsize} bytes) [quic payload]")
    else()
        message(WARNING "  NOT FOUND: ${_src}")
        set(_all_found FALSE)
    endif()
endforeach()

if(NOT _all_found)
    message(WARNING "Some zapret binary files were not found in the bundle. "
                    "The build may succeed but the exe will not work correctly at runtime.")
endif()

message(STATUS "Embed directory: ${ZAPRET_EMBED_DIR}")

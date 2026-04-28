cmake_minimum_required(VERSION 3.20)
project(zapret-gui VERSION 1.0.0 LANGUAGES C RC)

# Windows-only project
if(NOT WIN32)
    message(FATAL_ERROR "This project is Windows-only")
endif()

# Require x64
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Only x64 builds are supported")
endif()

# Unicode + secure CRT
add_definitions(-DUNICODE -D_UNICODE -D_CRT_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN)

# Fetch zapret-win-bundle from GitHub (pre-built binaries)
include(cmake/FetchZapret.cmake)

# Source files
set(SOURCES
    src/main.c
    src/gui.c
    src/service.c
    src/process.c
    src/config.c
    src/extractor.c
    src/dnsredir.c
    src/scanner.c
)

# Resource file
set(RESOURCES res/resource.rc)

# Create Windows GUI executable (WIN32 = no console subsystem)
add_executable(zapret-gui WIN32 ${SOURCES} ${RESOURCES})

# Link Windows system libraries
target_link_libraries(zapret-gui PRIVATE
    comctl32
    shell32
    advapi32
    user32
    gdi32
    shlwapi
    ws2_32
    winhttp
    comdlg32
    ole32
)

# Include directories
target_include_directories(zapret-gui PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/res
    ${CMAKE_SOURCE_DIR}/vendor/windivert/include
)

# Output naming
set_target_properties(zapret-gui PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "zapret-gui"
)

# MSVC-specific flags
if(MSVC)
    target_compile_options(zapret-gui PRIVATE /W3 /utf-8)
    # Disable MSVC auto-generated manifest (we embed our own via .rc)
    set_target_properties(zapret-gui PROPERTIES LINK_FLAGS "/MANIFEST:NO")
endif()

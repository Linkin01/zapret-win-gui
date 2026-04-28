#pragma once

#include <windows.h>
#include <stdbool.h>

/* ============================================================
 * RCDATA resource extraction
 *
 * Extracts winws.exe, cygwin1.dll, WinDivert.dll, WinDivert64.sys
 * from the embedded RCDATA resources to a target directory.
 * ============================================================ */

/* File names for embedded binaries */
#define ZAPRET_WINWS_EXE        L"winws.exe"
#define ZAPRET_CYGWIN1_DLL      L"cygwin1.dll"
#define ZAPRET_WINDIVERT_DLL    L"WinDivert.dll"
#define ZAPRET_WINDIVERT64_SYS  L"WinDivert64.sys"
#define ZAPRET_QUIC_INITIAL_BIN L"quic_initial_www_google_com.bin"
#define ZAPRET_TLS_CLIENTHELLO_BIN L"tls_clienthello_www_google_com.bin"
#define ZAPRET_STUN_BIN         L"stun.bin"

#define ZAPRET_TEMP_DIRNAME     L"zapret-gui"

/* Extract all embedded binaries to the given directory.
 * Creates the directory if it doesn't exist.
 * Skips files that already exist with the correct size. */
BOOL Extractor_ExtractAll(const wchar_t *targetDir);

/*
 * Deletes the extracted files and the temporary directory.
 */
void Extractor_CleanTempDir(LPCWSTR targetDir);

/* Extract a single RCDATA resource to a file path */
BOOL Extractor_ExtractResource(UINT resourceId, const wchar_t *outputPath);

/* Get %TEMP%\zapret-gui\ path (for child-process mode) */
void Extractor_GetTempDir(wchar_t *buf, DWORD bufLen);

/* Get %PROGRAMDATA%\zapret-gui\ path (for service mode) */
void Extractor_GetPermanentDir(wchar_t *buf, DWORD bufLen);

/* Check if all 4 required files exist in a directory */
BOOL Extractor_AreFilesPresent(const wchar_t *targetDir);

/* Delete all extracted files from a directory */
BOOL Extractor_Cleanup(const wchar_t *targetDir);

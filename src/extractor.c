#include "extractor.h"
#include "resource.h"
#include <stdio.h>
#include <shlobj.h>

/* ============================================================
 * Resource-to-file mapping
 * ============================================================ */

typedef struct {
    UINT    resourceId;
    const wchar_t *fileName;
} EmbeddedFile;

static const EmbeddedFile g_embeddedFiles[] = {
    { IDR_WINWS_EXE,            ZAPRET_WINWS_EXE },
    { IDR_CYGWIN1_DLL,          ZAPRET_CYGWIN1_DLL },
    { IDR_WINDIVERT_DLL,        ZAPRET_WINDIVERT_DLL },
    { IDR_WINDIVERT64_SYS,      ZAPRET_WINDIVERT64_SYS },
    { IDR_QUIC_INITIAL_BIN,     ZAPRET_QUIC_INITIAL_BIN },
    { IDR_TLS_CLIENTHELLO_BIN,  ZAPRET_TLS_CLIENTHELLO_BIN },
    { IDR_STUN_BIN,             ZAPRET_STUN_BIN },
};

#define EMBEDDED_FILE_COUNT (sizeof(g_embeddedFiles) / sizeof(g_embeddedFiles[0]))

/* ============================================================
 * Single resource extraction
 * ============================================================ */

BOOL Extractor_ExtractResource(UINT resourceId, const wchar_t *outputPath)
{
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!hRes) return FALSE;

    DWORD size = SizeofResource(NULL, hRes);
    if (size == 0) return FALSE;

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return FALSE;

    const void *pData = LockResource(hData);
    if (!pData) return FALSE;

    /* Check if file already exists with correct size — skip re-extraction */
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(outputPath, GetFileExInfoStandard, &fad)) {
        if (fad.nFileSizeHigh == 0 && fad.nFileSizeLow == size) {
            return TRUE; /* Already extracted, sizes match */
        }
    }

    /* Write resource data to file */
    HANDLE hFile = CreateFileW(outputPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, pData, size, &written, NULL);
    CloseHandle(hFile);

    if (!ok || written != size) {
        DeleteFileW(outputPath); /* Clean up partial write */
        return FALSE;
    }

    return TRUE;
}

/* ============================================================
 * Directory path helpers
 * ============================================================ */

void Extractor_GetTempDir(wchar_t *buf, DWORD bufLen)
{
    wchar_t temp[MAX_PATH];
    GetTempPathW(MAX_PATH, temp);
    _snwprintf_s(buf, bufLen, _TRUNCATE, L"%s%s", temp, ZAPRET_TEMP_DIRNAME);
}

void Extractor_GetPermanentDir(wchar_t *buf, DWORD bufLen)
{
    wchar_t progData[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, progData) == S_OK) {
        _snwprintf_s(buf, bufLen, _TRUNCATE, L"%s\\%s", progData, ZAPRET_TEMP_DIRNAME);
    } else {
        /* Fallback to temp */
        Extractor_GetTempDir(buf, bufLen);
    }
}

/* ============================================================
 * Extract all files
 * ============================================================ */

BOOL Extractor_ExtractAll(const wchar_t *targetDir)
{
    /* Create directory if needed */
    CreateDirectoryW(targetDir, NULL);

    BOOL allOk = TRUE;
    for (int i = 0; i < (int)EMBEDDED_FILE_COUNT; i++) {
        wchar_t path[MAX_PATH];
        _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\%s",
                     targetDir, g_embeddedFiles[i].fileName);

        if (!Extractor_ExtractResource(g_embeddedFiles[i].resourceId, path)) {
            allOk = FALSE;
        }
    }

    return allOk;
}

/* ============================================================
 * Check if files are present
 * ============================================================ */

BOOL Extractor_AreFilesPresent(const wchar_t *targetDir)
{
    for (int i = 0; i < (int)EMBEDDED_FILE_COUNT; i++) {
        wchar_t path[MAX_PATH];
        _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\%s",
                     targetDir, g_embeddedFiles[i].fileName);

        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
            return FALSE;
        }
    }
    return TRUE;
}

/* ============================================================
 * Cleanup
 * ============================================================ */

BOOL Extractor_Cleanup(const wchar_t *targetDir)
{
    BOOL allOk = TRUE;
    wchar_t searchPath[MAX_PATH];
    _snwprintf_s(searchPath, MAX_PATH, _TRUNCATE, L"%s\\*.*", targetDir);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
                wchar_t filePath[MAX_PATH];
                _snwprintf_s(filePath, MAX_PATH, _TRUNCATE, L"%s\\%s", targetDir, fd.cFileName);
                if (!DeleteFileW(filePath)) {
                    allOk = FALSE;
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    /* Try to remove directory (now empty) */
    if (!RemoveDirectoryW(targetDir)) {
        allOk = FALSE;
    }
    
    return allOk;
}

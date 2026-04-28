#include "config.h"
#include <shlwapi.h>
#include <shlobj.h>
#include <stdio.h>

/* ============================================================
 * INI path resolution
 * ============================================================ */

void Config_GetIniPath(wchar_t *buf, DWORD bufLen)
{
    /* Try: same directory as the executable */
    GetModuleFileNameW(NULL, buf, bufLen);
    /* Replace .exe with .ini */
    wchar_t *dot = wcsrchr(buf, L'.');
    if (dot) {
        wcscpy_s(dot, bufLen - (dot - buf), L".ini");
    } else {
        wcscat_s(buf, bufLen, L".ini");
    }

    /* Test if we can write there */
    HANDLE hTest = CreateFileW(buf, GENERIC_WRITE, 0, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTest != INVALID_HANDLE_VALUE) {
        CloseHandle(hTest);
        return; /* Writable, use this path */
    }

    /* Fallback: %APPDATA%\zapret-gui\zapret-gui.ini */
    wchar_t appdata[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdata) == S_OK) {
        _snwprintf_s(buf, bufLen, _TRUNCATE, L"%s\\zapret-gui", appdata);
        CreateDirectoryW(buf, NULL);
        _snwprintf_s(buf, bufLen, _TRUNCATE, L"%s\\zapret-gui\\%s", appdata, CONFIG_INI_NAME);
    }
}

/* ============================================================
 * Defaults
 * ============================================================ */

void Config_SetDefaults(AppConfig *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    wcscpy_s(cfg->winwsArgs, CONFIG_MAX_ARGS,
             L"--wf-tcp=80,443,27015-27030,27036-27037 "
             L"--wf-udp=19294-19344,27015-27030,27036,4380,50000-50100 "
             L"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun "
             L"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 "
             L"--new "
             L"--filter-tcp=443 --dpi-desync=fake,split2 --dpi-desync-split-pos=2 --dpi-desync-autottl=2:4 "
             L"--dpi-desync-fake-tls=tls_clienthello_www_google_com.bin --dpi-desync-any-protocol "
             L"--new "
             L"--filter-tcp=80 --dpi-desync=fake,split2 --dpi-desync-split-pos=2 --dpi-desync-any-protocol "
             L"--new "
             L"--filter-udp=27015-27030,27036,4380 --dpi-desync=fake --dpi-desync-repeats=8 --dpi-desync-any-protocol");
    wcscpy_s(cfg->presetName, CONFIG_MAX_NAME, L"General Purpose (recommended)");
    cfg->autoStart = TRUE;
    cfg->dontShowNotification = FALSE;
    wcscpy_s(cfg->serviceName, CONFIG_MAX_NAME, L"zapret-winws");
    
    cfg->scannerHostCount = 3;
    wcscpy_s(cfg->scannerHosts[0], 512, L"discord.com");
    wcscpy_s(cfg->scannerHosts[1], 512, L"web.telegram.org");
    wcscpy_s(cfg->scannerHosts[2], 512, L"x.com");
}

/* ============================================================
 * Load
 * ============================================================ */

void Config_Load(AppConfig *cfg)
{
    Config_SetDefaults(cfg);

    wchar_t iniPath[MAX_PATH];
    Config_GetIniPath(iniPath, MAX_PATH);

    /* Check if file exists */
    if (GetFileAttributesW(iniPath) == INVALID_FILE_ATTRIBUTES) {
        return; /* Use defaults */
    }

    GetPrivateProfileStringW(CONFIG_SECTION_GEN, L"WinwsArgs",
                             cfg->winwsArgs, cfg->winwsArgs,
                             CONFIG_MAX_ARGS, iniPath);

    GetPrivateProfileStringW(CONFIG_SECTION_GEN, L"LastPreset",
                             cfg->presetName, cfg->presetName,
                             CONFIG_MAX_NAME, iniPath);

    cfg->autoStart = GetPrivateProfileIntW(CONFIG_SECTION_GEN,
                                           L"AutoStart", cfg->autoStart, iniPath);

    cfg->dontShowNotification = GetPrivateProfileIntW(CONFIG_SECTION_GEN,
                                                      L"DontShowTrayNotification",
                                                      cfg->dontShowNotification, iniPath);

    GetPrivateProfileStringW(CONFIG_SECTION_SVC, L"ServiceName",
                             cfg->serviceName, cfg->serviceName,
                             CONFIG_MAX_NAME, iniPath);

    cfg->customPresetCount = GetPrivateProfileIntW(CONFIG_SECTION_CUSTOM, L"Count", 0, iniPath);
    if (cfg->customPresetCount > MAX_CUSTOM_PRESETS) cfg->customPresetCount = MAX_CUSTOM_PRESETS;
    
    for (int i = 0; i < cfg->customPresetCount; i++) {
        wchar_t keyName[32], keyArgs[32];
        _snwprintf_s(keyName, 32, _TRUNCATE, L"Name%d", i);
        _snwprintf_s(keyArgs, 32, _TRUNCATE, L"Args%d", i);
        
        GetPrivateProfileStringW(CONFIG_SECTION_CUSTOM, keyName, L"", cfg->customPresets[i].name, CONFIG_MAX_NAME, iniPath);
        GetPrivateProfileStringW(CONFIG_SECTION_CUSTOM, keyArgs, L"", cfg->customPresets[i].args, CONFIG_MAX_ARGS, iniPath);
    }
    
    int shCount = GetPrivateProfileIntW(L"ScannerHosts", L"Count", -1, iniPath);
    if (shCount != -1) {
        cfg->scannerHostCount = shCount;
        if (cfg->scannerHostCount > 20) cfg->scannerHostCount = 20;
        for (int i = 0; i < cfg->scannerHostCount; i++) {
            wchar_t keyHost[32];
            _snwprintf_s(keyHost, 32, _TRUNCATE, L"Host%d", i);
            GetPrivateProfileStringW(L"ScannerHosts", keyHost, L"", cfg->scannerHosts[i], 512, iniPath);
        }
    }
}

/* ============================================================
 * Save
 * ============================================================ */

void Config_Save(const AppConfig *cfg)
{
    wchar_t iniPath[MAX_PATH];
    Config_GetIniPath(iniPath, MAX_PATH);

    WritePrivateProfileStringW(CONFIG_SECTION_GEN, L"WinwsArgs",
                               cfg->winwsArgs, iniPath);

    WritePrivateProfileStringW(CONFIG_SECTION_GEN, L"LastPreset",
                               cfg->presetName, iniPath);

    wchar_t val[16];
    _snwprintf_s(val, 16, _TRUNCATE, L"%d", cfg->autoStart);
    WritePrivateProfileStringW(CONFIG_SECTION_GEN, L"AutoStart", val, iniPath);

    _snwprintf_s(val, 16, _TRUNCATE, L"%d", cfg->dontShowNotification);
    WritePrivateProfileStringW(CONFIG_SECTION_GEN, L"DontShowTrayNotification",
                               val, iniPath);

    WritePrivateProfileStringW(CONFIG_SECTION_SVC, L"ServiceName",
                               cfg->serviceName, iniPath);

    /* Save custom presets */
    WritePrivateProfileStringW(CONFIG_SECTION_CUSTOM, NULL, NULL, iniPath); /* Clear section */
    
    wchar_t valCount[16];
    _snwprintf_s(valCount, 16, _TRUNCATE, L"%d", cfg->customPresetCount);
    WritePrivateProfileStringW(CONFIG_SECTION_CUSTOM, L"Count", valCount, iniPath);
    
    for (int i = 0; i < cfg->customPresetCount; i++) {
        wchar_t keyName[32], keyArgs[32];
        _snwprintf_s(keyName, 32, _TRUNCATE, L"Name%d", i);
        _snwprintf_s(keyArgs, 32, _TRUNCATE, L"Args%d", i);
        
        WritePrivateProfileStringW(CONFIG_SECTION_CUSTOM, keyName, cfg->customPresets[i].name, iniPath);
        WritePrivateProfileStringW(CONFIG_SECTION_CUSTOM, keyArgs, cfg->customPresets[i].args, iniPath);
    }
    
    /* Save Scanner Hosts */
    WritePrivateProfileStringW(L"ScannerHosts", NULL, NULL, iniPath); /* Clear section */
    wchar_t valHostCount[16];
    _snwprintf_s(valHostCount, 16, _TRUNCATE, L"%d", cfg->scannerHostCount);
    WritePrivateProfileStringW(L"ScannerHosts", L"Count", valHostCount, iniPath);
    
    for (int i = 0; i < cfg->scannerHostCount; i++) {
        wchar_t keyHost[32];
        _snwprintf_s(keyHost, 32, _TRUNCATE, L"Host%d", i);
        WritePrivateProfileStringW(L"ScannerHosts", keyHost, cfg->scannerHosts[i], iniPath);
    }
}

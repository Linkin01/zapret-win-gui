#pragma once

#include <windows.h>
#include <stdbool.h>

/* ============================================================
 * Application configuration stored in INI file
 * ============================================================ */

#define CONFIG_MAX_ARGS     4096
#define CONFIG_MAX_NAME     64
#define CONFIG_INI_NAME     L"zapret-gui.ini"
#define CONFIG_SECTION_GEN  L"General"
#define CONFIG_SECTION_SVC  L"Service"
#define CONFIG_SECTION_CUSTOM L"CustomPresets"

#define MAX_CUSTOM_PRESETS 20

typedef struct {
    wchar_t name[CONFIG_MAX_NAME];
    wchar_t args[CONFIG_MAX_ARGS];
} CustomPreset;

typedef struct {
    wchar_t winwsArgs[CONFIG_MAX_ARGS];     /* winws command-line arguments */
    wchar_t presetName[CONFIG_MAX_NAME];    /* selected preset name */
    BOOL    autoStart;                       /* start winws on GUI launch */
    BOOL    dontShowNotification;            /* suppress tray balloon */
    wchar_t serviceName[CONFIG_MAX_NAME];   /* Windows service name */
    
    CustomPreset customPresets[MAX_CUSTOM_PRESETS];
    int customPresetCount;
    
    /* Scanner Targets */
    int scannerHostCount;
    wchar_t scannerHosts[20][512];
} AppConfig;

/* Load configuration from INI file (next to exe, or %APPDATA% fallback) */
void Config_Load(AppConfig *cfg);

/* Save configuration to INI file */
void Config_Save(const AppConfig *cfg);

/* Get the full path to the INI file */
void Config_GetIniPath(wchar_t *buf, DWORD bufLen);

/* Set defaults for a fresh config */
void Config_SetDefaults(AppConfig *cfg);

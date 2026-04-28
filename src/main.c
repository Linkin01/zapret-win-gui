/*
 * zapret-gui - Portable Windows GUI for zapret DPI bypass
 *
 * Single-exe application that:
 *  - Embeds winws.exe + dependencies as RCDATA resources
 *  - Extracts them to %TEMP% at runtime
 *  - Provides system tray icon with hide-to-tray behavior
 *  - Manages winws as a child process or Windows service
 *  - Stores config in a portable INI file
 */

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <objbase.h>
#include <commdlg.h>

#include "resource.h"
#include "config.h"
#include "extractor.h"
#include "process.h"
#include "service.h"
#include "gui.h"
#include "scanner.h"
#include "gui.h"
#include "dnsredir.h"

/* ============================================================
 * Globals
 * ============================================================ */

static HINSTANCE    g_hInstance     = NULL;
static HWND         g_hwndMain     = NULL;
static NOTIFYICONDATAW g_nid       = {0};
static AppConfig    g_config       = {0};
static wchar_t      g_extractDir[MAX_PATH]   = {0};  /* temp extract dir */
static wchar_t      g_permanentDir[MAX_PATH] = {0};  /* for service mode */
static BOOL         g_exitRequested = FALSE;

/* Crash Fallback State */
static BOOL         g_expectedRunning = FALSE;
static BOOL         g_hasFallenBack   = FALSE;



/* ============================================================
 * System tray
 * ============================================================ */

static void Tray_Add(HWND hwnd)
{
    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd   = hwnd;
    g_nid.uID    = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon  = LoadIconW(g_hInstance, MAKEINTRESOURCEW(IDI_APP_ICON));

    wcscpy_s(g_nid.szTip, 128, L"Zapret DPI Bypass");

    Shell_NotifyIconW(NIM_ADD, &g_nid);

    /* Use version 4 for better Win10/11 behavior */
    g_nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_nid);
}

static void Tray_Remove(void)
{
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

static void Tray_ShowBalloon(const wchar_t *title, const wchar_t *text)
{
    g_nid.uFlags = NIF_INFO;
    g_nid.dwInfoFlags = NIIF_INFO;
    wcscpy_s(g_nid.szInfoTitle, 64, title);
    wcscpy_s(g_nid.szInfo, 256, text);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void Tray_UpdateTip(BOOL running)
{
    g_nid.uFlags = NIF_TIP;
    if (running) {
        wcscpy_s(g_nid.szTip, 128, L"Zapret DPI Bypass - Running");
    } else {
        wcscpy_s(g_nid.szTip, 128, L"Zapret DPI Bypass - Stopped");
    }
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void Tray_ShowContextMenu(HWND hwnd)
{
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_SHOW, L"Show Window");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);

    /* Single Start/Stop toggle item */
    BOOL running = Process_IsRunning() || Service_IsRunning(g_config.serviceName);
    if (running) {
        AppendMenuW(hMenu, MF_STRING, IDM_TRAY_STOP, L"\x25A0 Stop");
    } else {
        AppendMenuW(hMenu, MF_STRING, IDM_TRAY_START, L"\x25B6 Start");
    }

    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_EXIT, L"Exit");

    /* Required for TrackPopupMenu to work correctly from tray */
    SetForegroundWindow(hwnd);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                   pt.x, pt.y, 0, hwnd, NULL);
    PostMessageW(hwnd, WM_NULL, 0, 0);

    DestroyMenu(hMenu);
}

/* ============================================================
 * Actions
 * ============================================================ */

static void DoStart(HWND hwnd)
{
    /* Read current args from the text box */
    Gui_ReadControls(hwnd, &g_config);

    g_expectedRunning = TRUE;
    g_hasFallenBack = FALSE;

    if (Process_IsRunning()) {
        Gui_SetLog(hwnd, L"winws is already running.");
        return;
    }

    /* Flush DNS cache to clear any ISP-poisoned entries */
    {
        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        wchar_t cmd[] = L"ipconfig /flushdns";
        if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    /* Make sure files are extracted */
    if (!Extractor_AreFilesPresent(g_extractDir)) {
        Gui_SetLog(hwnd, L"Extracting zapret binaries...");
        if (!Extractor_ExtractAll(g_extractDir)) {
            Gui_SetLog(hwnd, L"ERROR: Failed to extract binaries!");
            MessageBoxW(hwnd, L"Failed to extract embedded zapret binaries.\n"
                        L"Check if antivirus is blocking the operation.",
                        L"Extraction Error", MB_ICONERROR | MB_OK);
            return;
        }
    }

    if (Process_StartWinws(g_extractDir, g_config.winwsArgs)) {
        if (DnsRedir_Start(g_extractDir)) {
            Gui_SetLog(hwnd, L"DNS Hijacking started successfully.");
        } else {
            Gui_SetLog(hwnd, L"ERROR: DNS Hijacking failed to start! WinDivert handle failed.");
        }
        wchar_t msg[128];
        _snwprintf_s(msg, 128, _TRUNCATE, L"winws started (PID: %lu)",
                     Process_GetPid());
        Gui_SetLog(hwnd, msg);
        Gui_UpdateStatus(hwnd, TRUE, Process_GetPid());
        Tray_UpdateTip(TRUE);
    } else {
        DWORD err = GetLastError();
        wchar_t msg[256];
        _snwprintf_s(msg, 256, _TRUNCATE,
                     L"ERROR: Failed to start winws (error %lu)", err);
        Gui_SetLog(hwnd, msg);
        Gui_UpdateStatus(hwnd, FALSE, 0);
        g_expectedRunning = FALSE;
    }
}

static void DoStop(HWND hwnd)
{
    g_expectedRunning = FALSE;
    DnsRedir_Stop();
    if (Process_StopWinws()) {
        Gui_SetLog(hwnd, L"winws stopped.");
        Gui_UpdateStatus(hwnd, FALSE, 0);
        Tray_UpdateTip(FALSE);
    } else {
        Gui_SetLog(hwnd, L"ERROR: Failed to stop winws.");
    }
}

static void DoExportPresets(HWND hwnd)
{
    if (g_config.customPresetCount == 0) {
        MessageBoxW(hwnd, L"No custom presets to export.", L"Export Presets", MB_ICONINFORMATION);
        return;
    }
    
    wchar_t szFile[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"INI Files\0*.ini\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrDefExt = L"ini";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    
    if (GetSaveFileNameW(&ofn)) {
        /* Write [CustomPresets] section to selected file */
        WritePrivateProfileSectionW(CONFIG_SECTION_CUSTOM, L"", szFile); /* Clear existing */
        for (int i = 0; i < g_config.customPresetCount; i++) {
            wchar_t keyName[32];
            _snwprintf_s(keyName, 32, _TRUNCATE, L"preset_name_%d", i);
            WritePrivateProfileStringW(CONFIG_SECTION_CUSTOM, keyName, g_config.customPresets[i].name, szFile);
            _snwprintf_s(keyName, 32, _TRUNCATE, L"preset_args_%d", i);
            WritePrivateProfileStringW(CONFIG_SECTION_CUSTOM, keyName, g_config.customPresets[i].args, szFile);
        }
        wchar_t countStr[16];
        _snwprintf_s(countStr, 16, _TRUNCATE, L"%d", g_config.customPresetCount);
        WritePrivateProfileStringW(CONFIG_SECTION_CUSTOM, L"count", countStr, szFile);
        
        Gui_SetLog(hwnd, L"Custom presets exported successfully.");
    }
}

static void DoImportPresets(HWND hwnd)
{
    wchar_t szFile[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"INI Files\0*.ini\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    
    if (GetOpenFileNameW(&ofn)) {
        int count = GetPrivateProfileIntW(CONFIG_SECTION_CUSTOM, L"count", 0, szFile);
        if (count <= 0) {
            MessageBoxW(hwnd, L"No valid custom presets found in the selected file.", L"Import Presets", MB_ICONWARNING);
            return;
        }
        
        /* Allocate array for presets */
        ImportPresetItem *items = (ImportPresetItem *)malloc(sizeof(ImportPresetItem) * count);
        if (!items) return;
        
        int validCount = 0;
        for (int i = 0; i < count; i++) {
            wchar_t keyName[32];
            _snwprintf_s(keyName, 32, _TRUNCATE, L"preset_name_%d", i);
            GetPrivateProfileStringW(CONFIG_SECTION_CUSTOM, keyName, L"", items[validCount].name, CONFIG_MAX_NAME, szFile);
            
            _snwprintf_s(keyName, 32, _TRUNCATE, L"preset_args_%d", i);
            GetPrivateProfileStringW(CONFIG_SECTION_CUSTOM, keyName, L"", items[validCount].args, CONFIG_MAX_ARGS, szFile);
            
            if (items[validCount].name[0] && items[validCount].args[0]) {
                items[validCount].selected = TRUE; /* Default to selected */
                validCount++;
            }
        }
        
        if (validCount > 0) {
            if (Gui_ImportSelector(hwnd, items, validCount)) {
                int added = 0;
                for (int i = 0; i < validCount; i++) {
                    if (items[i].selected) {
                        if (g_config.customPresetCount >= MAX_CUSTOM_PRESETS) {
                            MessageBoxW(hwnd, L"Preset limit reached. Could not import all selected presets.", L"Import Presets", MB_ICONWARNING);
                            break;
                        }
                        if (Gui_AddCustomPreset(&g_config, items[i].name, items[i].args)) {
                            added++;
                        }
                    }
                }
                
                if (added > 0) {
                    Config_Save(&g_config);
                    Gui_SetControls(hwnd, &g_config);
                    wchar_t msg[128];
                    _snwprintf_s(msg, 128, _TRUNCATE, L"Successfully imported %d presets.", added);
                    Gui_SetLog(hwnd, msg);
                    MessageBoxW(hwnd, msg, L"Import Presets", MB_ICONINFORMATION);
                }
            }
        } else {
            MessageBoxW(hwnd, L"No valid custom presets found in the selected file.", L"Import Presets", MB_ICONWARNING);
        }
        
        free(items);
    }
}

static void DoSavePreset(HWND hwnd)
{
    Gui_ReadControls(hwnd, &g_config);
    
    wchar_t name[CONFIG_MAX_NAME] = {0};
    if (Gui_InputBox(hwnd, L"Save Custom Preset", L"Enter a name for your custom preset:", name, CONFIG_MAX_NAME)) {
        if (Gui_AddCustomPreset(&g_config, name, g_config.winwsArgs)) {
            /* Set the new preset as the active one */
            wcscpy_s(g_config.presetName, CONFIG_MAX_NAME, name);
            Config_Save(&g_config);
            
            /* Rebuild combo box cleanly, avoiding dangling <Custom> labels */
            Gui_SetControls(hwnd, &g_config);
            
            Gui_SetLog(hwnd, L"Custom preset saved.");
            
            /* Restart winws if it was running, to apply any new args instantly */
            if (Process_IsRunning() || Service_IsRunning(g_config.serviceName)) {
                DoStop(hwnd);
                DoStart(hwnd);
            }
        } else {
            MessageBoxW(hwnd, L"Failed to save preset. Maximum limit reached.", L"Error", MB_ICONERROR);
        }
    }
}

static void DoDelPreset(HWND hwnd)
{
    HWND hCombo = GetDlgItem(hwnd, IDC_PRESET_COMBO);
    int sel = (int)SendMessageW(hCombo, CB_GETCURSEL, 0, 0);
    
    if (sel >= Gui_GetPresetCount(NULL)) { /* It's a custom preset */
        if (MessageBoxW(hwnd, L"Are you sure you want to delete this custom preset?", L"Delete Preset", MB_ICONQUESTION | MB_YESNO) == IDYES) {
            if (Gui_RemoveCustomPreset(&g_config, sel)) {
                SendMessageW(hCombo, CB_DELETESTRING, sel, 0);
                SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
                Gui_ReadControls(hwnd, &g_config);
                Config_Save(&g_config);
                Gui_SetLog(hwnd, L"Custom preset deleted.");
            }
        }
    } else {
        MessageBoxW(hwnd, L"You cannot delete a built-in preset.", L"Error", MB_ICONWARNING);
    }
}

static void DoRenPreset(HWND hwnd)
{
    HWND hCombo = GetDlgItem(hwnd, IDC_PRESET_COMBO);
    int sel = (int)SendMessageW(hCombo, CB_GETCURSEL, 0, 0);
    
    if (sel >= Gui_GetPresetCount(NULL)) { /* It's a custom preset */
        wchar_t currentName[CONFIG_MAX_NAME] = {0};
        SendMessageW(hCombo, CB_GETLBTEXT, sel, (LPARAM)currentName);
        
        wchar_t newName[CONFIG_MAX_NAME] = {0};
        wcscpy_s(newName, CONFIG_MAX_NAME, currentName);
        
        if (Gui_InputBox(hwnd, L"Rename Preset", L"Enter a new name for the preset:", newName, CONFIG_MAX_NAME)) {
            if (Gui_RenameCustomPreset(&g_config, sel, newName)) {
                /* Update combobox item */
                SendMessageW(hCombo, CB_DELETESTRING, sel, 0);
                SendMessageW(hCombo, CB_INSERTSTRING, sel, (LPARAM)newName);
                SendMessageW(hCombo, CB_SETCURSEL, sel, 0);
                
                Gui_ReadControls(hwnd, &g_config);
                Config_Save(&g_config);
                Gui_SetLog(hwnd, L"Custom preset renamed.");
            }
        }
    } else {
        MessageBoxW(hwnd, L"You cannot rename a built-in preset.", L"Error", MB_ICONWARNING);
    }
}

static void DoServiceToggle(HWND hwnd)
{
    BOOL checked = (IsDlgButtonChecked(hwnd, IDC_CHK_SERVICE) == BST_CHECKED);
    Gui_ReadControls(hwnd, &g_config);

    if (checked) {
        /* Install as service */
        /* First, extract to permanent directory */
        if (!Extractor_ExtractAll(g_permanentDir)) {
            Gui_SetLog(hwnd, L"ERROR: Failed to extract binaries for service.");
            CheckDlgButton(hwnd, IDC_CHK_SERVICE, BST_UNCHECKED);
            return;
        }

        /* Stop child process if running (service will take over) */
        if (Process_IsRunning()) {
            Process_StopWinws();
        }

        wchar_t winwsPath[MAX_PATH];
        _snwprintf_s(winwsPath, MAX_PATH, _TRUNCATE, L"%s\\%s",
                     g_permanentDir, ZAPRET_WINWS_EXE);

        if (Service_Install(g_config.serviceName, winwsPath, g_config.winwsArgs)) {
            Service_Start(g_config.serviceName);
            Gui_SetLog(hwnd, L"Service installed and started.");
        } else {
            DWORD err = GetLastError();
            wchar_t msg[256];
            _snwprintf_s(msg, 256, _TRUNCATE,
                         L"ERROR: Failed to install service (error %lu). "
                         L"Already installed?", err);
            Gui_SetLog(hwnd, msg);
            CheckDlgButton(hwnd, IDC_CHK_SERVICE, BST_UNCHECKED);
        }
    } else {
        /* Uninstall service */
        int result = MessageBoxW(hwnd,
            L"Remove the Zapret Windows service?\n"
            L"DPI bypass will no longer auto-start with Windows.",
            L"Confirm Service Removal",
            MB_ICONQUESTION | MB_YESNO);

        if (result == IDYES) {
            if (Service_Uninstall(g_config.serviceName)) {
                Gui_SetLog(hwnd, L"Service removed.");
                Extractor_Cleanup(g_permanentDir);
            } else {
                Gui_SetLog(hwnd, L"ERROR: Failed to remove service.");
                CheckDlgButton(hwnd, IDC_CHK_SERVICE, BST_CHECKED);
            }
        } else {
            CheckDlgButton(hwnd, IDC_CHK_SERVICE, BST_CHECKED);
        }
    }
}

/* ============================================================
 * Window Procedure
 * ============================================================ */

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {

    case WM_CREATE:
        Gui_CreateControls(hwnd, g_hInstance, &g_config);
        Gui_SetControls(hwnd, &g_config);
        SetTimer(hwnd, TIMER_STATUS_POLL, TIMER_STATUS_INTERVAL, NULL);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_START:
            Gui_ReadControls(hwnd, &g_config);
            Config_Save(&g_config);
            DoStart(hwnd);
            break;

        case IDC_BTN_STOP:
            DoStop(hwnd);
            break;

        case IDC_BTN_SAVE_PRESET:
            DoSavePreset(hwnd);
            break;

        case IDC_BTN_DEL_PRESET:
            DoDelPreset(hwnd);
            break;

        case IDC_BTN_REN_PRESET:
            DoRenPreset(hwnd);
            break;

        case IDC_BTN_SCAN: {
            BOOL wasRunning = Process_IsRunning();
            if (wasRunning) {
                DoStop(hwnd);
            }

            if (Scanner_Run(hwnd, &g_config)) {
                /* User accepted a new preset from scanner. Update UI. */
                Gui_SetControls(hwnd, &g_config);
                DoStart(hwnd); /* auto start with the new args! */
            } else if (wasRunning) {
                /* Restore previous running state if scanner was cancelled */
                DoStart(hwnd);
            }
            break;
        }

        case IDM_FILE_IMPORT:
            DoImportPresets(hwnd);
            break;

        case IDM_FILE_EXPORT:
            DoExportPresets(hwnd);
            break;

        case IDM_FILE_CLEAN:
            if (MessageBoxW(hwnd, L"Are you sure you want to completely remove ALL your custom presets? This action cannot be undone unless you have exported them.", L"Clean Custom Presets", MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) == IDYES) {
                g_config.customPresetCount = 0;
                wcscpy_s(g_config.presetName, CONFIG_MAX_NAME, L"");
                Config_Save(&g_config);
                Gui_SetControls(hwnd, &g_config);
                Gui_SetLog(hwnd, L"All custom presets removed.");
            }
            break;

        case IDM_FILE_EXIT:
            g_exitRequested = TRUE;
            DestroyWindow(hwnd);
            break;

        case IDC_CHK_SERVICE:
            DoServiceToggle(hwnd);
            break;

        case IDC_ARGS_EDIT:
            if (HIWORD(wParam) == EN_CHANGE) {
                Gui_UpdatePresetSelectionForArgs(hwnd, &g_config);
            }
            break;

        case IDC_PRESET_COMBO:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                int sel = (int)SendDlgItemMessageW(hwnd, IDC_PRESET_COMBO,
                                                   CB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < Gui_GetPresetCount(&g_config)) {
                    /* Update args text box with preset args */
                    const wchar_t *args = Gui_GetPresetArgs(&g_config, sel);
                    if (args && args[0]) {
                        SetDlgItemTextW(hwnd, IDC_ARGS_EDIT, args);
                    }
                }
                
                /* Auto-save whenever a preset is selected */
                Gui_ReadControls(hwnd, &g_config);
                Config_Save(&g_config);
                
                /* Apply immediately if running */
                BOOL isService = (IsDlgButtonChecked(hwnd, IDC_CHK_SERVICE) == BST_CHECKED);
                if (isService && Service_IsRunning(g_config.serviceName)) {
                    Service_Stop(g_config.serviceName);
                    Service_Uninstall(g_config.serviceName);
                    Extractor_ExtractAll(g_permanentDir);
                    
                    wchar_t winwsPath[MAX_PATH];
                    _snwprintf_s(winwsPath, MAX_PATH, _TRUNCATE, L"%s\\%s",
                                 g_permanentDir, ZAPRET_WINWS_EXE);
                    Service_Install(g_config.serviceName, winwsPath, g_config.winwsArgs);
                    Service_Start(g_config.serviceName);
                    
                    Gui_SetLog(hwnd, L"Service restarted with new preset.");
                } else if (!isService && Process_IsRunning()) {
                    DoStop(hwnd);
                    DoStart(hwnd);
                    Gui_SetLog(hwnd, L"Process restarted with new preset.");
                }
            }
            break;

        /* Tray menu commands */
        case IDM_TRAY_SHOW:
            ShowWindow(hwnd, SW_SHOW);
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
            break;

        case IDM_TRAY_START:
            DoStart(hwnd);
            break;

        case IDM_TRAY_STOP:
            DoStop(hwnd);
            break;

        case IDM_TRAY_EXIT:
            g_exitRequested = TRUE;
            DestroyWindow(hwnd);
            break;
        }
        return 0;

    case WM_TRAYICON:
        switch (LOWORD(lParam)) {
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
        case NIN_BALLOONUSERCLICK:
            /* Show/toggle window (also handles balloon click) */
            if (LOWORD(lParam) == NIN_BALLOONUSERCLICK || !IsWindowVisible(hwnd)) {
                ShowWindow(hwnd, SW_SHOW);
                ShowWindow(hwnd, SW_RESTORE);
                SetForegroundWindow(hwnd);
            } else {
                ShowWindow(hwnd, SW_HIDE);
            }
            break;

        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            Tray_ShowContextMenu(hwnd);
            break;
        }
        return 0;

    case WM_TIMER:
        if (wParam == TIMER_STATUS_POLL) {
            BOOL running = Process_IsRunning();
            BOOL svcRunning = Service_IsRunning(g_config.serviceName);

            /* Show running if either child process or service is active */
            BOOL anyRunning = running || svcRunning;
            DWORD pid = Process_GetPid();

            /* Process Crash Fallback Logic */
            if (g_expectedRunning && !anyRunning) {
                if (!g_hasFallenBack) {
                    g_hasFallenBack = TRUE;
                    g_expectedRunning = FALSE; /* Stop expecting so we don't loop during prompt */

                    HWND hCombo = GetDlgItem(hwnd, IDC_PRESET_COMBO);
                    int sel = (int)SendMessageW(hCombo, CB_GETCURSEL, 0, 0);
                    BOOL isCustom = (sel >= Gui_GetPresetCount(NULL));

                    int res = Gui_CrashDialog(hwnd, isCustom);

                    if (res == ID_CRASH_EDIT) {
                        Gui_SetLog(hwnd, L"winws stopped for editing.");
                        SetFocus(GetDlgItem(hwnd, IDC_ARGS_EDIT));
                    } else if (res == ID_CRASH_DELETE || res == ID_CRASH_FALLBACK) {
                        if (isCustom && res == ID_CRASH_DELETE) {
                            Gui_RemoveCustomPreset(&g_config, sel);
                        }

                        Gui_SetLog(hwnd, L"Falling back to safe preset...");
                        
                        int fallbackIdx = 0;
                        /* If we are already on 0, try 1 */
                        wchar_t currentName[CONFIG_MAX_NAME] = {0};
                        SendMessageW(hCombo, CB_GETLBTEXT, 0, (LPARAM)currentName);
                        if (wcscmp(g_config.presetName, currentName) == 0) {
                            fallbackIdx = 1;
                        }
                        
                        const wchar_t *fbArgs = Gui_GetPresetArgs(NULL, fallbackIdx);
                        if (fbArgs && fbArgs[0]) {
                            SendMessageW(hCombo, CB_GETLBTEXT, fallbackIdx, (LPARAM)g_config.presetName);
                            wcscpy_s(g_config.winwsArgs, CONFIG_MAX_ARGS, fbArgs);
                            Config_Save(&g_config);
                            
                            /* Visually update UI */
                            Gui_SetControls(hwnd, &g_config);
                            
                            /* Auto-restart */
                            DoStart(hwnd);
                        }
                    }
                } else {
                    Gui_SetLog(hwnd, L"ERROR: Fallback preset also crashed. Stopping.");
                    g_expectedRunning = FALSE;
                }
            }

            Gui_UpdateStatus(hwnd, anyRunning, pid);
            Tray_UpdateTip(anyRunning);
        }
        return 0;

    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) {
            Gui_OnResize(hwnd);
        }
        return 0;

    case WM_CTLCOLORSTATIC: {
        /* Color the status dot green or red, fix background for all statics */
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        int id = GetDlgCtrlID(hCtrl);

        if (id == IDC_STATUS_DOT) {
            BOOL running = Process_IsRunning() ||
                           Service_IsRunning(g_config.serviceName);
            SetTextColor(hdc, running ? COLOR_RUNNING : COLOR_STOPPED);
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)GetStockObject(NULL_BRUSH);
        }

        /* For all other static controls, use the window background */
        SetBkColor(hdc, GetSysColor(COLOR_WINDOW));
        return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
    }

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lParam;
        mmi->ptMinTrackSize.x = GUI_MIN_WIDTH;
        mmi->ptMinTrackSize.y = GUI_MIN_HEIGHT;
        return 0;
    }

    case WM_CLOSE:
        /* Minimize to tray instead of closing */
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        Gui_ReadControls(hwnd, &g_config);
        Config_Save(&g_config);
        KillTimer(hwnd, TIMER_STATUS_POLL);
        Tray_Remove();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* ============================================================
 * WinMain entry point
 * ============================================================ */

static BOOL IsRunAsAdmin(void)
{
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
        CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin);
        FreeSid(pAdministratorsGroup);
    }
    return fIsRunAsAdmin;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                      LPWSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    /* Initialize COM for shell dialogs (GetOpenFileName) */
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    /* Enforce running as administrator */
    if (!IsRunAsAdmin()) {
        MessageBoxW(NULL,
                    L"Zapret GUI must be run as Administrator to modify network filters.",
                    L"Administrator Required", MB_ICONERROR | MB_OK);
        CoUninitialize();
        return 1;
    }

    g_hInstance = hInstance;

    /* Prevent multiple instances */
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\ZapretGuiMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(NULL, L"Zapret GUI is already running.\n"
                    L"Check the system tray.",
                    L"Zapret GUI", MB_ICONINFORMATION | MB_OK);
        return 0;
    }

    /* Initialize Common Controls for visual styles */
    INITCOMMONCONTROLSEX icc = {
        .dwSize = sizeof(icc),
        .dwICC  = ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES
    };
    InitCommonControlsEx(&icc);

    /* Compute extraction directories */
    Extractor_GetTempDir(g_extractDir, MAX_PATH);
    Extractor_GetPermanentDir(g_permanentDir, MAX_PATH);

    /* Aggressively clean up any orphaned Temp folder from a previous forced-kill session */
    Extractor_Cleanup(g_extractDir);

    /* Extract embedded binaries to temp */
    if (!Extractor_ExtractAll(g_extractDir)) {
        MessageBoxW(NULL,
            L"Failed to extract embedded zapret binaries.\n\n"
            L"Possible causes:\n"
            L"- Antivirus is blocking the extraction\n"
            L"- Temp directory is not writable\n\n"
            L"Try adding an exception for %TEMP%\\zapret-gui\\",
            L"Zapret GUI - Extraction Error",
            MB_ICONERROR | MB_OK);
        return 1;
    }

    /* Load configuration */
    Config_Load(&g_config);

    /* Important: Add extract dir to DLL search path so delay-loaded WinDivert.dll is found */
    SetDllDirectoryW(g_extractDir);

    /* Register window class and create window */
    if (!Gui_RegisterClass(hInstance)) {
        MessageBoxW(NULL, L"Failed to register window class.",
                    L"Error", MB_ICONERROR);
        return 1;
    }

    g_hwndMain = Gui_CreateWindow(hInstance, &g_config);
    if (!g_hwndMain) {
        MessageBoxW(NULL, L"Failed to create main window.",
                    L"Error", MB_ICONERROR);
        return 1;
    }

    /* Add system tray icon */
    Tray_Add(g_hwndMain);

    /* Show balloon notification (if not suppressed) */
    if (!g_config.dontShowNotification) {
        Tray_ShowBalloon(L"Zapret DPI Bypass",
                         L"Running in the system tray. Click the icon to open settings.");
    }

    /* Auto-start winws if configured */
    if (g_config.autoStart) {
        DoStart(g_hwndMain);
    } else {
        if (DnsRedir_Start(g_extractDir)) {
            Gui_SetLog(g_hwndMain, L"DNS Hijacking started successfully.");
        } else {
            Gui_SetLog(g_hwndMain, L"ERROR: DNS Hijacking failed to start! WinDivert handle failed.");
        }
    }

    /* Window starts hidden (tray only) — user clicks tray to open */
    /* Don't call ShowWindow here */

    /* Message loop */
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    /* Cleanup */
    Process_Cleanup();
    DnsRedir_Stop();
    Extractor_Cleanup(g_extractDir);

    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }

    CoUninitialize();
    return (int)msg.wParam;
}

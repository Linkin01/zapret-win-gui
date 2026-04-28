#pragma once

#include <windows.h>
#include "config.h"

/* ============================================================
 * GUI window creation and management
 * ============================================================ */

/* Window class name */
#define GUI_WNDCLASS    L"ZapretGuiWindow"
#define GUI_TITLE       L"Zapret DPI Bypass"

/* Window dimensions (logical, scaled by DPI) */
#define GUI_WIDTH       640
#define GUI_HEIGHT      550
#define GUI_MIN_WIDTH   460
#define GUI_MIN_HEIGHT  420

/* Status colors */
#define COLOR_RUNNING   RGB(0, 200, 80)
#define COLOR_STOPPED   RGB(220, 50, 50)
#define COLOR_STARTING  RGB(255, 180, 0)

/* Strategy presets */
typedef struct {
    const wchar_t *name;
    const wchar_t *args;
} StrategyPreset;

/* Create and register the main GUI window class */
BOOL Gui_RegisterClass(HINSTANCE hInstance);

/* Create the main window (initially hidden) */
HWND Gui_CreateWindow(HINSTANCE hInstance, AppConfig *cfg);

/* Create controls inside the window */
void Gui_CreateControls(HWND hwnd, HINSTANCE hInst, AppConfig *cfg);

/* Update all controls to reflect current config/state */
void Gui_UpdateStatus(HWND hwnd, BOOL running, DWORD pid);

const wchar_t *Gui_GetPresetArgs(const AppConfig *cfg, int index);
int Gui_GetPresetCount(const AppConfig *cfg);

/* Read current control values back into config */
void Gui_ReadControls(HWND hwnd, AppConfig *cfg);

/* Set controls from config */
void Gui_SetControls(HWND hwnd, const AppConfig *cfg);

/* Dynamically update combo box selection based on args edit box */
void Gui_UpdatePresetSelectionForArgs(HWND hwnd, AppConfig *cfg);

/* Custom preset handling */
BOOL Gui_AddCustomPreset(AppConfig *cfg, const wchar_t *name, const wchar_t *args);
BOOL Gui_RemoveCustomPreset(AppConfig *cfg, int index);
BOOL Gui_RenameCustomPreset(AppConfig *cfg, int index, const wchar_t *newName);
BOOL Gui_InputBox(HWND parent, const wchar_t *title, const wchar_t *prompt, wchar_t *buf, int bufLen);

/* Custom crash dialog with themed buttons */
#define ID_CRASH_EDIT      1001
#define ID_CRASH_DELETE    1002
#define ID_CRASH_FALLBACK  1003
int Gui_CrashDialog(HWND parent, BOOL isCustom);

/* Selective Import */
typedef struct {
    wchar_t name[CONFIG_MAX_NAME];
    wchar_t args[CONFIG_MAX_ARGS];
    BOOL selected;
} ImportPresetItem;
BOOL Gui_ImportSelector(HWND parent, ImportPresetItem *items, int count);

/* Append a log message to the status bar */
void Gui_SetLog(HWND hwnd, const wchar_t *msg);

/* Reposition all controls to fit current window size (responsive layout) */
void Gui_OnResize(HWND hwnd);

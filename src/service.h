#pragma once

#include <windows.h>
#include <stdbool.h>

/* ============================================================
 * Windows service management for winws
 * ============================================================ */

#define SERVICE_DISPLAY_NAME  L"Zapret DPI Bypass (winws)"

/* Install winws as a Windows service.
 * winwsPath: full path to winws.exe (in the permanent extract dir)
 * args: winws command-line arguments
 * serviceName: service name (e.g. "zapret-winws") */
BOOL Service_Install(const wchar_t *serviceName,
                     const wchar_t *winwsPath,
                     const wchar_t *args);

/* Uninstall the Windows service */
BOOL Service_Uninstall(const wchar_t *serviceName);

/* Start the service */
BOOL Service_Start(const wchar_t *serviceName);

/* Stop the service */
BOOL Service_Stop(const wchar_t *serviceName);

/* Check if the service is installed */
BOOL Service_IsInstalled(const wchar_t *serviceName);

/* Check if the service is currently running */
BOOL Service_IsRunning(const wchar_t *serviceName);

#include "service.h"
#include <stdio.h>

/* ============================================================
 * Install service
 * ============================================================ */

BOOL Service_Install(const wchar_t *serviceName,
                     const wchar_t *winwsPath,
                     const wchar_t *args)
{
    /* Build binary path: "C:\...\winws.exe" <args> */
    wchar_t binPath[8192];
    _snwprintf_s(binPath, 8192, _TRUNCATE, L"\"%s\" %s", winwsPath, args);

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) return FALSE;

    SC_HANDLE hService = CreateServiceW(
        hSCM,
        serviceName,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,         /* Start with Windows */
        SERVICE_ERROR_NORMAL,
        binPath,
        NULL, NULL, NULL, NULL, NULL
    );

    BOOL ok = (hService != NULL);

    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return ok;
}

/* ============================================================
 * Uninstall service
 * ============================================================ */

BOOL Service_Uninstall(const wchar_t *serviceName)
{
    /* Stop first if running */
    Service_Stop(serviceName);

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return FALSE;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, DELETE);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    BOOL ok = DeleteService(hService);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return ok;
}

/* ============================================================
 * Start service
 * ============================================================ */

BOOL Service_Start(const wchar_t *serviceName)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return FALSE;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_START);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    BOOL ok = StartServiceW(hService, 0, NULL);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return ok;
}

/* ============================================================
 * Stop service
 * ============================================================ */

BOOL Service_Stop(const wchar_t *serviceName)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return FALSE;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    SERVICE_STATUS status;
    BOOL ok = ControlService(hService, SERVICE_CONTROL_STOP, &status);

    if (ok) {
        /* Wait for service to stop (up to 10 seconds) */
        for (int i = 0; i < 20; i++) {
            if (QueryServiceStatus(hService, &status) &&
                status.dwCurrentState == SERVICE_STOPPED) {
                break;
            }
            Sleep(500);
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return ok;
}

/* ============================================================
 * Status queries
 * ============================================================ */

BOOL Service_IsInstalled(const wchar_t *serviceName)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return FALSE;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_STATUS);
    BOOL installed = (hService != NULL);

    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return installed;
}

BOOL Service_IsRunning(const wchar_t *serviceName)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return FALSE;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    SERVICE_STATUS status;
    BOOL running = FALSE;
    if (QueryServiceStatus(hService, &status)) {
        running = (status.dwCurrentState == SERVICE_RUNNING);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return running;
}

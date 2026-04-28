#pragma once

#include <windows.h>
#include <stdbool.h>

/* ============================================================
 * winws.exe child process management
 * ============================================================ */

/* Launch winws.exe from extractDir with the given arguments.
 * extractDir should contain winws.exe and its DLL dependencies. */
BOOL Process_StartWinws(const wchar_t *extractDir, const wchar_t *args);

/* Terminate the running winws child process */
BOOL Process_StopWinws(void);

/* Check if the winws child process is currently running */
BOOL Process_IsRunning(void);

/* Get the PID of the running winws process (0 if not running) */
DWORD Process_GetPid(void);

/* Get the HANDLE of the running process */
HANDLE Process_GetHandle(void);

/* Clean up process handles (call on app exit) */
void Process_Cleanup(void);

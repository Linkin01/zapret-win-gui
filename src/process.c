#include "process.h"
#include "extractor.h"
#include <stdio.h>

/* ============================================================
 * State
 * ============================================================ */

static PROCESS_INFORMATION g_procInfo = {0};
static BOOL g_running = FALSE;
static HANDLE g_hJob = NULL;  /* Job object for automatic child cleanup */

/* ============================================================
 * Ensure a Job Object exists with KILL_ON_JOB_CLOSE
 * ============================================================ */

static HANDLE Process_GetJobObject(void)
{
    if (!g_hJob) {
        g_hJob = CreateJobObjectW(NULL, NULL);
        if (g_hJob) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
            jeli.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(g_hJob,
                                    JobObjectExtendedLimitInformation,
                                    &jeli, sizeof(jeli));
        }
    }
    return g_hJob;
}

/* ============================================================
 * Start winws.exe
 * ============================================================ */

BOOL Process_StartWinws(const wchar_t *extractDir, const wchar_t *args)
{
    if (Process_IsRunning()) {
        return TRUE; /* Already running */
    }

    /* Build full command line: "extractDir\winws.exe" <args> */
    wchar_t cmdLine[8192];
    _snwprintf_s(cmdLine, 8192, _TRUNCATE,
                 L"\"%s\\%s\" %s", extractDir, ZAPRET_WINWS_EXE, args);

    /* Working directory = extraction directory (so winws can find DLLs) */
    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    memset(&g_procInfo, 0, sizeof(g_procInfo));

    BOOL ok = CreateProcessW(
        NULL,           /* lpApplicationName - NULL, use cmdLine */
        cmdLine,        /* lpCommandLine */
        NULL,           /* lpProcessAttributes */
        NULL,           /* lpThreadAttributes */
        FALSE,          /* bInheritHandles */
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
        NULL,           /* lpEnvironment */
        extractDir,     /* lpCurrentDirectory */
        &si,
        &g_procInfo
    );

    if (ok) {
        /* Assign to job object so winws dies if GUI crashes */
        HANDLE hJob = Process_GetJobObject();
        if (hJob) {
            AssignProcessToJobObject(hJob, g_procInfo.hProcess);
        }

        /* Resume the process now that it's in the job */
        ResumeThread(g_procInfo.hThread);

        g_running = TRUE;
        /* Close thread handle immediately, we only need the process handle */
        CloseHandle(g_procInfo.hThread);
        g_procInfo.hThread = NULL;
    } else {
        memset(&g_procInfo, 0, sizeof(g_procInfo));
    }

    return ok;
}

/* ============================================================
 * Stop winws.exe
 * ============================================================ */

BOOL Process_StopWinws(void)
{
    if (!g_procInfo.hProcess) {
        g_running = FALSE;
        return TRUE;
    }

    /* Terminate the process */
    TerminateProcess(g_procInfo.hProcess, 0);

    /* Wait up to 5 seconds for it to actually exit */
    WaitForSingleObject(g_procInfo.hProcess, 5000);

    CloseHandle(g_procInfo.hProcess);
    memset(&g_procInfo, 0, sizeof(g_procInfo));
    g_running = FALSE;

    return TRUE;
}

/* ============================================================
 * Status
 * ============================================================ */

BOOL Process_IsRunning(void)
{
    if (!g_procInfo.hProcess) {
        g_running = FALSE;
        return FALSE;
    }

    DWORD exitCode = 0;
    if (GetExitCodeProcess(g_procInfo.hProcess, &exitCode)) {
        if (exitCode == STILL_ACTIVE) {
            g_running = TRUE;
            return TRUE;
        }
    }

    /* Process has exited — clean up handle */
    CloseHandle(g_procInfo.hProcess);
    memset(&g_procInfo, 0, sizeof(g_procInfo));
    g_running = FALSE;
    return FALSE;
}

DWORD Process_GetPid(void)
{
    return g_running ? g_procInfo.dwProcessId : 0;
}

HANDLE Process_GetHandle(void)
{
    return g_running ? g_procInfo.hProcess : NULL;
}

void Process_Cleanup(void)
{
    Process_StopWinws();
    if (g_hJob) {
        CloseHandle(g_hJob);
        g_hJob = NULL;
    }
}

/* End of process.c */

#include "scanner.h"
#include "resource.h"
#include "process.h"
#include "extractor.h"
#include <commctrl.h>
#include <stdio.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#include "gui.h"

/* Smart Scanner Data Structures */
typedef struct {
    int tcp_desync; /* 0: fake, 1: fake,split2, 2: split2, 3: multisplit, 4: disorder2 */
    int split_pos;  /* 1 or 2 */
    int fooling;    /* 0: none, 1: badsum, 2: md5sig, 3: ts */
    int autottl;    /* 0: none, 1: 1:2, 2: 1:3, 3: 2:3 */
} SmartCombo;

static const wchar_t *g_desync_names[] = { L"fake", L"fake,split2", L"split2", L"multisplit", L"disorder2" };
static const wchar_t *g_fooling_names[] = { L"", L"badsum", L"md5sig", L"ts" };
static const wchar_t *g_autottl_names[] = { L"", L"1:2", L"1:3", L"2:3" };

#define MAX_COMBOS 200
static SmartCombo g_combos[MAX_COMBOS];
static int g_comboCount = 0;

static void GenerateCombos() {
    g_comboCount = 0;
    for (int t = 0; t <= 4; t++) {
        for (int p = 1; p <= 2; p++) {
            if (t == 0 && p == 2) continue; /* pure fake doesn't use split-pos */
            for (int f = 0; f <= 3; f++) {
                for (int a = 0; a <= 3; a++) {
                    if (a > 0 && t != 0 && t != 1) continue; /* autottl usually needs fake */
                    if (g_comboCount < MAX_COMBOS) {
                        g_combos[g_comboCount].tcp_desync = t;
                        g_combos[g_comboCount].split_pos = p;
                        g_combos[g_comboCount].fooling = f;
                        g_combos[g_comboCount].autottl = a;
                        g_comboCount++;
                    }
                }
            }
        }
    }
}

static void BuildArgs(SmartCombo c, wchar_t *argsOut, int maxLen, wchar_t *nameOut, int maxName) {
    const wchar_t *base = L"--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=quic_initial_www_google_com.bin --new --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 --new --filter-tcp=80,443";
    
    _snwprintf_s(argsOut, maxLen, _TRUNCATE, L"%s --dpi-desync=%s", base, g_desync_names[c.tcp_desync]);
    
    if (c.tcp_desync == 3) {
        wcscat_s(argsOut, maxLen, L" --dpi-desync-split-seqovl=568 --dpi-desync-split-seqovl-pattern=tls_clienthello_www_google_com.bin");
    }
    
    if (c.tcp_desync != 0) { /* If it uses split/disorder */
        wchar_t buf[32];
        _snwprintf_s(buf, 32, _TRUNCATE, L" --dpi-desync-split-pos=%d", c.split_pos);
        wcscat_s(argsOut, maxLen, buf);
    }
    
    if (c.autottl > 0) {
        wchar_t buf[32];
        _snwprintf_s(buf, 32, _TRUNCATE, L" --dpi-desync-autottl=%s", g_autottl_names[c.autottl]);
        wcscat_s(argsOut, maxLen, buf);
    }
    
    if (c.fooling > 0) {
        wchar_t buf[32];
        _snwprintf_s(buf, 32, _TRUNCATE, L" --dpi-desync-fooling=%s", g_fooling_names[c.fooling]);
        wcscat_s(argsOut, maxLen, buf);
    }
    
    /* Always add fake-tls if fake is involved */
    if (c.tcp_desync == 0 || c.tcp_desync == 1) {
        wcscat_s(argsOut, maxLen, L" --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin");
    }
    
    /* Generate name */
    wchar_t extras[128] = {0};
    if (c.tcp_desync != 0) {
        _snwprintf_s(extras, 128, _TRUNCATE, L"pos=%d", c.split_pos);
    }
    if (c.fooling > 0) {
        if (extras[0]) wcscat_s(extras, 128, L", ");
        wcscat_s(extras, 128, g_fooling_names[c.fooling]);
    }
    if (c.autottl > 0) {
        if (extras[0]) wcscat_s(extras, 128, L", ");
        wcscat_s(extras, 128, L"ttl=");
        wcscat_s(extras, 128, g_autottl_names[c.autottl]);
    }
    
    if (extras[0]) {
        _snwprintf_s(nameOut, maxName, _TRUNCATE, L"Custom: %s (%s)", g_desync_names[c.tcp_desync], extras);
    } else {
        _snwprintf_s(nameOut, maxName, _TRUNCATE, L"Custom: %s", g_desync_names[c.tcp_desync]);
    }
}

static const wchar_t *g_techniques[] = {
    /* GoodbyeDPI -5 equivalent (Fastest/Best) */
    L"--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=quic_initial_www_google_com.bin --new --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 --new --filter-tcp=80,443 --dpi-desync=fake,split2 --dpi-desync-split-pos=2 --dpi-desync-autottl=2:3 --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin --dpi-desync-any-protocol",
    
    /* Multisplit Legacy */
    L"--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=quic_initial_www_google_com.bin --new --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 --new --filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=tls_clienthello_www_google_com.bin --new --filter-tcp=80 --dpi-desync=fake,split2",
    
    /* Simple Fake (alt) */
    L"--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=quic_initial_www_google_com.bin --new --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 --new --filter-tcp=80,443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin",
    
    /* Fake + Badsum */
    L"--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=quic_initial_www_google_com.bin --new --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 --new --filter-tcp=80,443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=badsum --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin",
    
    /* Fake + AutoTTL */
    L"--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=quic_initial_www_google_com.bin --new --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 --new --filter-tcp=80,443 --dpi-desync=fake --dpi-desync-autottl --dpi-desync-fooling=badsum --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin"
};

#define NUM_TECHNIQUES (sizeof(g_techniques) / sizeof(g_techniques[0]))

static HWND g_hScannerWnd = NULL;
static AppConfig *g_cfg = NULL;
static BOOL g_bScanning = FALSE;
static BOOL g_bAbort = FALSE;
static HANDLE g_hThread = NULL;
static BOOL g_bSuccess = FALSE;

/* Result storage */
static wchar_t g_bestArgs[4096] = {0};
static wchar_t g_bestName[128] = {0};
static int g_bestBuiltinIndex = -1;

/* Macro for DPI scaling */
static int S(int value) {
    int dpi = 96;
    HDC hdc = GetDC(NULL);
    if (hdc) {
        dpi = GetDeviceCaps(hdc, LOGPIXELSX);
        ReleaseDC(NULL, hdc);
    }
    return MulDiv(value, dpi, 96);
}

#define SETFONT(h) SendMessageW(h, WM_SETFONT, (WPARAM)hFont, FALSE)

static void Scanner_Log(const wchar_t *msg) {
    if (!g_hScannerWnd) return;
    HWND hLog = GetDlgItem(g_hScannerWnd, IDC_LOG_SCANNER);
    int len = GetWindowTextLengthW(hLog);
    SendMessageW(hLog, EM_SETSEL, len, len);
    SendMessageW(hLog, EM_REPLACESEL, 0, (LPARAM)msg);
    SendMessageW(hLog, EM_REPLACESEL, 0, (LPARAM)L"\r\n");
}

static BOOL TestHost(const wchar_t *host) {
    HINTERNET hSession = WinHttpOpen(L"Zapret-Scanner/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return FALSE;
    
    WinHttpSetTimeouts(hSession, 4000, 4000, 4000, 4000); /* 4 seconds timeout */
    
    HINTERNET hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return FALSE; }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", NULL, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return FALSE; }
    
    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return bResults;
}

static DWORD WINAPI ScannerThread(LPVOID lpParam) {
    Scanner_Log(L"--- Scan Started ---");
    
    /* Fetch hosts from listbox */
    HWND hList = GetDlgItem(g_hScannerWnd, IDC_LIST_HOSTS);
    int hostCount = (int)SendMessageW(hList, LB_GETCOUNT, 0, 0);
    if (hostCount == 0) {
        Scanner_Log(L"ERROR: No target hosts defined. Add some hosts first.");
        goto L_End;
    }
    
    wchar_t tempDir[MAX_PATH];
    Extractor_GetTempDir(tempDir, MAX_PATH);
    if (!Extractor_ExtractAll(tempDir)) {
        Scanner_Log(L"ERROR: Failed to extract zapret binaries.");
        goto L_End;
    }
    
    BOOL bIncludeBuiltin = (IsDlgButtonChecked(g_hScannerWnd, IDC_CHK_BUILTIN) == BST_CHECKED);
    int totalBuiltin = bIncludeBuiltin ? Gui_GetPresetCount(NULL) : 0;
    
    GenerateCombos();
    int totalTechniques = totalBuiltin + g_comboCount;
    
    HWND hProg = GetDlgItem(g_hScannerWnd, IDC_PROG_SCANNER);
    SendMessageW(hProg, PBM_SETRANGE, 0, MAKELPARAM(0, totalTechniques));
    SendMessageW(hProg, PBM_SETPOS, 0, 0);

    for (int t = 0; t < totalTechniques; t++) {
        if (g_bAbort) {
            Scanner_Log(L"Scan aborted by user.");
            break;
        }
        
        wchar_t currentArgs[4096] = {0};
        wchar_t currentName[128] = {0};
        int builtinIndex = -1;
        
        if (t < totalBuiltin) {
            /* Try built-in preset */
            const wchar_t *args = Gui_GetPresetArgs(NULL, t);
            if (args) {
                wcscpy_s(currentArgs, 4096, args);
                builtinIndex = t;
                _snwprintf_s(currentName, 128, _TRUNCATE, L"Built-in #%d", t + 1);
            }
        } else {
            /* Try smart combo */
            int comboIndex = t - totalBuiltin;
            BuildArgs(g_combos[comboIndex], currentArgs, 4096, currentName, 128);
        }
        
        if (!currentArgs[0]) continue;
        
        wchar_t msg[512];
        _snwprintf_s(msg, 512, _TRUNCATE, L"\r\nTesting Technique %d/%d (%s)...", t + 1, totalTechniques, currentName);
        Scanner_Log(msg);
        
        /* Start winws */
        if (Process_IsRunning()) Process_StopWinws();
        
        if (!Process_StartWinws(tempDir, currentArgs)) {
            Scanner_Log(L"ERROR: Failed to start winws engine. Skipping...");
            continue;
        }
        
        Sleep(500); /* Wait for winws to bind and route */
        
        /* Process Stability Check */
        HANDLE hProcess = Process_GetHandle();
        if (hProcess && WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
            Scanner_Log(L"ERROR: winws crashed immediately after starting! Skipping...");
            continue;
        }
        
        BOOL allPassed = TRUE;
        for (int i = 0; i < hostCount; i++) {
            if (g_bAbort) break;
            
            wchar_t host[512];
            SendMessageW(hList, LB_GETTEXT, i, (LPARAM)host);
            
            _snwprintf_s(msg, 512, _TRUNCATE, L" -> HTTPS GET %s ...", host);
            Scanner_Log(msg);
            
            if (TestHost(host)) {
                Scanner_Log(L"    [SUCCESS] Connection established.");
            } else {
                Scanner_Log(L"    [FAILED] DPI blocked or timeout.");
                allPassed = FALSE;
                break; /* No need to test other hosts if one fails */
            }
        }
        
        if (allPassed && !g_bAbort) {
            Scanner_Log(L"\r\n*** SUCCESS! ***");
            _snwprintf_s(msg, 512, _TRUNCATE, L"Technique '%s' successfully bypassed DPI for all hosts!", currentName);
            Scanner_Log(msg);
            
            wcscpy_s(g_bestArgs, 4096, currentArgs);
            wcscpy_s(g_bestName, 128, currentName);
            g_bestBuiltinIndex = builtinIndex;
            g_bSuccess = TRUE;
            break;
        }
        
        SendMessageW(hProg, PBM_SETPOS, t + 1, 0);
    }
    
L_End:
    if (Process_IsRunning()) Process_StopWinws();
    if (!g_bSuccess && !g_bAbort) {
        Scanner_Log(L"\r\nScan complete. Unfortunately, no working technique was found.");
    }
    
    g_bScanning = FALSE;
    SetDlgItemTextW(g_hScannerWnd, IDC_BTN_START_SCAN, L"Start Scan");
    EnableWindow(GetDlgItem(g_hScannerWnd, IDC_BTN_START_SCAN), TRUE);
    
    if (g_bSuccess) {
        /* Ask user to apply */
        if (MessageBoxW(g_hScannerWnd, L"A working bypass technique was found!\n\nWould you like to apply it now?", L"Success", MB_ICONINFORMATION | MB_YESNO) == IDYES) {
            wcscpy_s(g_cfg->winwsArgs, CONFIG_MAX_ARGS, g_bestArgs);
            
            if (g_bestBuiltinIndex != -1) {
                /* It's a built-in preset, don't create a new one, just set it */
                /* Gui_SetControls handles mapping if we give it the exact args or index.
                 * Actually, we can just save it, and DoStart will run it.
                 * But to make the UI combobox update perfectly, we should probably set presetName
                 * to the built-in preset's actual name. */
                 /* We don't have direct access to its name string, but we can clear presetName
                  * and Gui_SetControls will auto-detect it by matching args. */
                wcscpy_s(g_cfg->presetName, CONFIG_MAX_NAME, L"");
            } else {
                /* It's a smart combo, save as Custom Auto-Detected */
                wcscpy_s(g_cfg->presetName, CONFIG_MAX_NAME, g_bestName);
            }
            
            Config_Save(g_cfg);
            SetWindowLongPtrW(g_hScannerWnd, DWLP_USER, IDYES);
            ShowWindow(g_hScannerWnd, SW_HIDE);
        }
    }
    return 0;
}

static void OnStartStop(HWND hwnd) {
    if (g_bScanning) {
        g_bAbort = TRUE;
        Scanner_Log(L"Aborting scan... Please wait.");
        EnableWindow(GetDlgItem(hwnd, IDC_BTN_START_SCAN), FALSE);
    } else {
        /* Save current list back to config before scanning */
        HWND hList = GetDlgItem(hwnd, IDC_LIST_HOSTS);
        g_cfg->scannerHostCount = (int)SendMessageW(hList, LB_GETCOUNT, 0, 0);
        for (int i = 0; i < g_cfg->scannerHostCount && i < 20; i++) {
            SendMessageW(hList, LB_GETTEXT, i, (LPARAM)g_cfg->scannerHosts[i]);
        }
        Config_Save(g_cfg);
        
        g_bScanning = TRUE;
        g_bAbort = FALSE;
        g_bSuccess = FALSE;
        g_bestBuiltinIndex = -1;
        SetDlgItemTextW(hwnd, IDC_BTN_START_SCAN, L"Stop Scan");
        SetDlgItemTextW(hwnd, IDC_LOG_SCANNER, L""); /* clear log */
        
        g_hThread = CreateThread(NULL, 0, ScannerThread, NULL, 0, NULL);
    }
}

static void OnAddHost(HWND hwnd) {
    wchar_t buf[512];
    GetDlgItemTextW(hwnd, IDC_EDIT_HOST, buf, 512);
    if (buf[0]) {
        HWND hList = GetDlgItem(hwnd, IDC_LIST_HOSTS);
        int count = (int)SendMessageW(hList, LB_GETCOUNT, 0, 0);
        if (count >= 20) {
            MessageBoxW(hwnd, L"Maximum 20 hosts allowed.", L"Limit Reached", MB_ICONWARNING);
            return;
        }
        SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)buf);
        SetDlgItemTextW(hwnd, IDC_EDIT_HOST, L"");
    }
}

static void OnDelHost(HWND hwnd) {
    HWND hList = GetDlgItem(hwnd, IDC_LIST_HOSTS);
    int sel = (int)SendMessageW(hList, LB_GETCURSEL, 0, 0);
    if (sel != LB_ERR) {
        SendMessageW(hList, LB_DELETESTRING, sel, 0);
    }
}

static LRESULT CALLBACK ScannerWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_INITDIALOG: {
        /* Populate list */
        HWND hList = GetDlgItem(hwnd, IDC_LIST_HOSTS);
        for (int i = 0; i < g_cfg->scannerHostCount; i++) {
            SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)g_cfg->scannerHosts[i]);
        }
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_BTN_START_SCAN:
            OnStartStop(hwnd);
            break;
        case IDC_BTN_ADD_HOST:
            OnAddHost(hwnd);
            break;
        case IDC_BTN_DEL_HOST:
            OnDelHost(hwnd);
            break;
        case IDCANCEL:
            if (g_bScanning) g_bAbort = TRUE;
            SetWindowLongPtrW(hwnd, DWLP_USER, IDCANCEL);
            ShowWindow(hwnd, SW_HIDE);
            break;
        }
        break;
    case WM_CLOSE:
        if (g_bScanning) g_bAbort = TRUE;
        SetWindowLongPtrW(hwnd, DWLP_USER, IDCANCEL);
        ShowWindow(hwnd, SW_HIDE);
        break;
    }
    return FALSE;
}

BOOL Scanner_Run(HWND hwndParent, AppConfig *cfg) {
    g_cfg = cfg;
    
    /* We don't have a dialog resource, so we build it dynamically in memory */
    
    /* Basic in-memory DLGTEMPLATE structure */
    #pragma pack(push, 1)
    struct {
        DLGTEMPLATE dlg;
        WORD menu;
        WORD _class;
        wchar_t title[32];
    } templ = {0};
    #pragma pack(pop)
    
    templ.dlg.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_CENTER;
    templ.dlg.cx = 320;
    templ.dlg.cy = 240;
    wcscpy_s(templ.title, 32, L"Find Best Preset");

    HWND hwnd = CreateDialogIndirectW(GetModuleHandleW(NULL), &templ.dlg, hwndParent, ScannerWndProc);
    g_hScannerWnd = hwnd;
    
    /* Create controls manually since we used an empty template */
    NONCLIENTMETRICSW ncm = { .cbSize = sizeof(ncm) };
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    HFONT hFont = CreateFontIndirectW(&ncm.lfMessageFont);
    
    HWND h;
    h = CreateWindowW(L"STATIC", L"Target Hosts (HTTPS)", WS_CHILD | WS_VISIBLE, S(10), S(10), S(150), S(20), hwnd, (HMENU)IDC_LBL_HOSTS, NULL, NULL); SETFONT(h);
    h = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY, S(10), S(30), S(180), S(100), hwnd, (HMENU)IDC_LIST_HOSTS, NULL, NULL); SETFONT(h);
    h = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, S(10), S(140), S(120), S(22), hwnd, (HMENU)IDC_EDIT_HOST, NULL, NULL); SETFONT(h);
    SendMessageW(h, EM_SETLIMITTEXT, 511, 0);
    h = CreateWindowW(L"BUTTON", L"Add", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, S(135), S(140), S(55), S(22), hwnd, (HMENU)IDC_BTN_ADD_HOST, NULL, NULL); SETFONT(h);
    h = CreateWindowW(L"BUTTON", L"Remove", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, S(200), S(30), S(60), S(22), hwnd, (HMENU)IDC_BTN_DEL_HOST, NULL, NULL); SETFONT(h);
    
    h = CreateWindowW(L"BUTTON", L"Include built-in presets", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, S(200), S(60), S(160), S(20), hwnd, (HMENU)IDC_CHK_BUILTIN, NULL, NULL); SETFONT(h);
    SendMessageW(h, BM_SETCHECK, BST_CHECKED, 0); /* Default checked */
    
    h = CreateWindowW(L"BUTTON", L"Start Scan", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, S(200), S(140), S(100), S(22), hwnd, (HMENU)IDC_BTN_START_SCAN, NULL, NULL); SETFONT(h);
    
    h = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, S(10), S(175), S(350), S(150), hwnd, (HMENU)IDC_LOG_SCANNER, NULL, NULL); SETFONT(h);
    
    h = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE, S(10), S(335), S(350), S(15), hwnd, (HMENU)IDC_PROG_SCANNER, NULL, NULL);
    
    /* Adjust main window size to fit everything we just spawned */
    RECT r = {0, 0, S(370), S(360)};
    AdjustWindowRect(&r, WS_POPUP | WS_CAPTION | WS_SYSMENU, FALSE);
    SetWindowPos(hwnd, NULL, 0, 0, r.right - r.left, r.bottom - r.top, SWP_NOMOVE | SWP_NOZORDER);
    
    /* Trigger init */
    SendMessageW(hwnd, WM_INITDIALOG, 0, 0);
    
    EnableWindow(hwndParent, FALSE);
    ShowWindow(hwnd, SW_SHOW);
    
    /* Message loop for modal simulation */
    MSG msg;
    INT_PTR ret = IDCANCEL;
    while (IsWindow(hwnd) && GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        /* Checking for our custom "EndDialog" replacement via visibility */
        if (!IsWindowVisible(hwnd)) {
            ret = GetWindowLongPtrW(hwnd, DWLP_USER);
            break;
        }
    }
    
    DestroyWindow(hwnd);
    EnableWindow(hwndParent, TRUE);
    SetForegroundWindow(hwndParent);
    
    return (ret == IDYES);
}

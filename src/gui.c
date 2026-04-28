#include "gui.h"
#include "resource.h"
#include "service.h"
#include "process.h"
#include "extractor.h"
#include <commctrl.h>
#include <stdio.h>

/* ============================================================
 * Strategy presets
 * ============================================================ */

static const StrategyPreset g_presets[] = {
    /* --- General Purpose: recommended first choice --- */
    {
        L"General Purpose (recommended)",
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
        L"--filter-udp=27015-27030,27036,4380 --dpi-desync=fake --dpi-desync-repeats=8 --dpi-desync-any-protocol"
    },
    {
        L"General Purpose (Advanced)",
        L"--wf-tcp=80,443,27015-27030,27036-27037 "
        L"--wf-udp=19294-19344,27015-27030,27036,4380,50000-50100 "
        L"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun "
        L"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 "
        L"--new "
        L"--filter-tcp=443 --hostlist-domains=discord.com,discordapp.com,discord.gg,discordapp.net,discord.media "
        L"--dpi-desync=fake,split2 --dpi-desync-split-pos=2 --dpi-desync-autottl=2:4 "
        L"--dpi-desync-fake-tls=tls_clienthello_www_google_com.bin --dpi-desync-any-protocol "
        L"--new "
        L"--filter-tcp=443 --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=8 "
        L"--dpi-desync-fooling=md5sig,badseq --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin "
        L"--dpi-desync-any-protocol "
        L"--new "
        L"--filter-tcp=80 --dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2 --dpi-desync-autottl=2 "
        L"--dpi-desync-fooling=md5sig "
        L"--new "
        L"--filter-udp=27015-27030,27036,4380 --dpi-desync=fake --dpi-desync-repeats=8 --dpi-desync-any-protocol"
    },

    /* ======================================================================
     * Presets based on Flowseal/zapret-discord-youtube (26k+ stars)
     * https://github.com/Flowseal/zapret-discord-youtube
     *
     * KEY RULES:
     *  - TCP uses "multisplit" (NOT "fake" alone — fake without proper TTL
     *    causes NET::ERR_CERT_AUTHORITY_INVALID because the fake packet
     *    reaches the server and corrupts the TLS handshake).
     *  - Discord voice/STUN on UDP 19294-19344 uses L7 protocol detection.
     *  - QUIC (UDP 443) uses "fake" with repeats=6 + realistic .bin payload.
     *  - General UDP 50000-50100 for game voice / media.
     *  - .bin payload files are extracted alongside winws.exe, so relative
     *    paths resolve via lpCurrentDirectory in CreateProcessW.
     * ====================================================================== */

    /* --- Turkey: recommended first choice (GoodbyeDPI -5 equivalent) --- */
    {
        L"Turkey \x2014 GoodbyeDPI -5",
        L"--wf-tcp=80,443 --wf-udp=19294-19344,50000-50100 "
        L"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun "
        L"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 "
        L"--new "
        L"--filter-tcp=80,443 --dpi-desync=fake,split2 --dpi-desync-split-pos=2 --dpi-desync-autottl=2:3 "
        L"--dpi-desync-fake-tls=tls_clienthello_www_google_com.bin --dpi-desync-any-protocol"
    },

    /* --- Turkey: Multisplit (old fallback) --- */
    {
        L"Turkey \x2014 Multisplit",
        L"--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 "
        L"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 "
        L"--dpi-desync-fake-quic=quic_initial_www_google_com.bin "
        L"--new "
        L"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun "
        L"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 "
        L"--new "
        L"--filter-tcp=443 --dpi-desync=multisplit "
        L"--dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 "
        L"--dpi-desync-split-seqovl-pattern=tls_clienthello_www_google_com.bin "
        L"--new "
        L"--filter-tcp=80 --dpi-desync=fake,split2"
    },

    /* --- Turkey: simple fake with timestamp fooling (alt for some ISPs) --- */
    {
        L"Turkey \x2014 Simple Fake (alt)",
        L"--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 "
        L"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 "
        L"--dpi-desync-fake-quic=quic_initial_www_google_com.bin "
        L"--new "
        L"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun "
        L"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 "
        L"--new "
        L"--filter-tcp=80,443 --dpi-desync=fake --dpi-desync-repeats=6 "
        L"--dpi-desync-fooling=ts "
        L"--dpi-desync-fake-tls=tls_clienthello_www_google_com.bin"
    },

    /* --- Turkey: fake with badsum fooling (prevents fake reaching server) --- */
    {
        L"Turkey \x2014 Fake + Badsum",
        L"--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 "
        L"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 "
        L"--dpi-desync-fake-quic=quic_initial_www_google_com.bin "
        L"--new "
        L"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun "
        L"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 "
        L"--new "
        L"--filter-tcp=80,443 --dpi-desync=fake --dpi-desync-repeats=6 "
        L"--dpi-desync-fooling=badsum "
        L"--dpi-desync-fake-tls=tls_clienthello_www_google_com.bin"
    },

    /* --- Turkey: fake + autottl (auto-calculates TTL so fake expires before server) --- */
    {
        L"Turkey \x2014 Fake + AutoTTL",
        L"--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 "
        L"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 "
        L"--dpi-desync-fake-quic=quic_initial_www_google_com.bin "
        L"--new "
        L"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun "
        L"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol --dpi-desync-cutoff=d4 "
        L"--new "
        L"--filter-tcp=80,443 --dpi-desync=fake --dpi-desync-autottl "
        L"--dpi-desync-fooling=badsum "
        L"--dpi-desync-fake-tls=tls_clienthello_www_google_com.bin"
    },

    /* --- Russia: general purpose (from Flowseal, designed for RU ISPs) --- */
    {
        L"Russia \x2014 General",
        L"--wf-tcp=80,443 --wf-udp=443,50000-50100 "
        L"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 "
        L"--dpi-desync-fake-quic=quic_initial_www_google_com.bin "
        L"--new "
        L"--filter-tcp=443 --dpi-desync=multisplit "
        L"--dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 "
        L"--dpi-desync-split-seqovl-pattern=tls_clienthello_www_google_com.bin "
        L"--new "
        L"--filter-tcp=80 --dpi-desync=fake,split2"
    },
};

#define PRESET_COUNT (sizeof(g_presets) / sizeof(g_presets[0]))

/* ============================================================
 * DPI scaling helper
 * ============================================================ */

static int Dpi_Scale(HWND hwnd, int value)
{
    /* Try GetDpiForWindow (Win10 1607+) */
    typedef UINT(WINAPI *PFN_GetDpiForWindow)(HWND);
    static PFN_GetDpiForWindow pfn = NULL;
    static BOOL checked = FALSE;

    if (!checked) {
        HMODULE hUser = GetModuleHandleW(L"user32.dll");
        if (hUser) {
            pfn = (PFN_GetDpiForWindow)GetProcAddress(hUser, "GetDpiForWindow");
        }
        checked = TRUE;
    }

    UINT dpi = 96;
    if (pfn && hwnd) {
        dpi = pfn(hwnd);
    } else {
        HDC hdc = GetDC(NULL);
        if (hdc) {
            dpi = (UINT)GetDeviceCaps(hdc, LOGPIXELSX);
            ReleaseDC(NULL, hdc);
        }
    }

    return MulDiv(value, (int)dpi, 96);
}

/* ============================================================
 * Window class registration
 * ============================================================ */

/* Forward declaration of window procedure (lives in main.c) */
extern LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);

BOOL Gui_RegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance      = hInstance;
    wc.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_APP_ICON));
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = GUI_WNDCLASS;
    wc.hIconSm       = wc.hIcon;

    return RegisterClassExW(&wc) != 0;
}

/* ============================================================
 * InputBox dialog
 * ============================================================ */

static wchar_t g_inputBuf[128];
static HWND g_hInputEdit;

static LRESULT CALLBACK InputWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_COMMAND:
        if (LOWORD(wp) == 1) { /* OK */
            GetWindowTextW(g_hInputEdit, g_inputBuf, 128);
            DestroyWindow(hwnd);
        } else if (LOWORD(wp) == 2 || LOWORD(wp) == IDCANCEL) { /* Cancel */
            g_inputBuf[0] = 0;
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE:
        g_inputBuf[0] = 0;
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

BOOL Gui_InputBox(HWND parent, const wchar_t *title, const wchar_t *prompt, wchar_t *buf, int bufLen) {
    g_inputBuf[0] = 0;
    if (buf && buf[0]) wcscpy_s(g_inputBuf, 128, buf);
    
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = InputWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"ZapretInputBox";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
    RegisterClassW(&wc);
    
    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);
    
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, L"ZapretInputBox", title,
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        (cx - 300) / 2, (cy - 150) / 2, 300, 150,
        parent, NULL, wc.hInstance, NULL);
        
    /* Use default GUI font */
    NONCLIENTMETRICSW ncm = { .cbSize = sizeof(ncm) };
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    HFONT hFont = CreateFontIndirectW(&ncm.lfMessageFont);
        
    HWND hPrompt = CreateWindowW(L"STATIC", prompt, WS_CHILD | WS_VISIBLE,
        15, 15, 260, 20, hwnd, NULL, wc.hInstance, NULL);
    SendMessageW(hPrompt, WM_SETFONT, (WPARAM)hFont, FALSE);
        
    g_hInputEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_inputBuf,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        15, 40, 255, 25, hwnd, NULL, wc.hInstance, NULL);
    SendMessageW(g_hInputEdit, WM_SETFONT, (WPARAM)hFont, FALSE);
        
    HWND hOk = CreateWindowW(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
        105, 75, 80, 25, hwnd, (HMENU)1, wc.hInstance, NULL);
    SendMessageW(hOk, WM_SETFONT, (WPARAM)hFont, FALSE);
        
    HWND hCancel = CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        190, 75, 80, 25, hwnd, (HMENU)2, wc.hInstance, NULL);
    SendMessageW(hCancel, WM_SETFONT, (WPARAM)hFont, FALSE);
        
    EnableWindow(parent, FALSE); /* Modal effect */
    ShowWindow(hwnd, SW_SHOW);
    SetFocus(g_hInputEdit);
    
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    
    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
    
    if (g_inputBuf[0]) {
        wcscpy_s(buf, bufLen, g_inputBuf);
        return TRUE;
    }
    return FALSE;
}

/* ============================================================
 * Window creation with all controls
 * ============================================================ */

HWND Gui_CreateWindow(HINSTANCE hInstance, AppConfig *cfg)
{
    int W = GUI_WIDTH;
    int H = GUI_HEIGHT;

    /* Center on screen */
    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);

    HWND hwnd = CreateWindowExW(
        0,
        GUI_WNDCLASS,
        GUI_TITLE,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_THICKFRAME,
        (cx - W) / 2, (cy - H) / 2, W, H,
        NULL, LoadMenuW(hInstance, MAKEINTRESOURCEW(IDR_MAIN_MENU)), hInstance, cfg  /* pass config via CREATESTRUCT.lpCreateParams */
    );

    if (!hwnd) return NULL;

    /* All controls use DPI-scaled coordinates */
    int s = 1; /* will be computed inside WM_CREATE */

    /* We create controls in WM_CREATE handler via Gui_CreateControls */

    return hwnd;
}

/* Called from WM_CREATE in main.c */
void Gui_CreateControls(HWND hwnd, HINSTANCE hInst, AppConfig *cfg)
{
    /* Font */
    NONCLIENTMETRICSW ncm = { .cbSize = sizeof(ncm) };
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    HFONT hFont = CreateFontIndirectW(&ncm.lfMessageFont);

    #define S(v) Dpi_Scale(hwnd, v)
    #define SETFONT(h) SendMessageW(h, WM_SETFONT, (WPARAM)hFont, TRUE)

    int x = S(15), y = S(10);
    int cw = S(515); /* content width */
    HWND h;

    /* --- Status row --- */
    h = CreateWindowExW(0, L"STATIC", L"\x25CF", /* ● */
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        x, y + S(2), S(12), S(16), hwnd, (HMENU)IDC_STATUS_DOT, hInst, NULL);
    SETFONT(h);

    h = CreateWindowExW(0, L"STATIC", L"Status: Stopped",
        WS_CHILD | WS_VISIBLE,
        x + S(14), y, S(200), S(20), hwnd, (HMENU)IDC_STATUS_LABEL, hInst, NULL);
    SETFONT(h);

    h = CreateWindowExW(0, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_RIGHT,
        x + S(300), y, S(160), S(20), hwnd, (HMENU)IDC_PID_LABEL, hInst, NULL);
    SETFONT(h);

    y += S(30);

    /* --- Strategy group box --- */
    h = CreateWindowExW(0, L"BUTTON", L"Strategy",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        x, y, cw, S(175), hwnd, (HMENU)IDC_GRP_STRATEGY, hInst, NULL);
    SETFONT(h);

    y += S(20);

    /* Preset label + combo */
    h = CreateWindowExW(0, L"STATIC", L"Preset:",
        WS_CHILD | WS_VISIBLE,
        x + S(10), y + S(3), S(50), S(20), hwnd, (HMENU)IDC_LBL_PRESET, hInst, NULL);
    SETFONT(h);

    h = CreateWindowExW(0, L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        x + S(65), y, cw - S(130), S(200), hwnd, (HMENU)IDC_PRESET_COMBO, hInst, NULL);
    SETFONT(h);

    /* Add '✎' rename button */
    h = CreateWindowExW(0, L"BUTTON", L"\x270E",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x + cw - S(60), y, S(25), S(22), hwnd, (HMENU)IDC_BTN_REN_PRESET, hInst, NULL);
    SETFONT(h);

    /* Add 'X' delete button */
    h = CreateWindowExW(0, L"BUTTON", L"\x2715", /* Unicode cross */
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x + cw - S(30), y, S(25), S(22), hwnd, (HMENU)IDC_BTN_DEL_PRESET, hInst, NULL);
    SETFONT(h);

    y += S(30);

    /* Args label */
    h = CreateWindowExW(0, L"STATIC", L"winws arguments:",
        WS_CHILD | WS_VISIBLE,
        x + S(10), y, S(200), S(18), hwnd, (HMENU)IDC_LBL_ARGS, hInst, NULL);
    SETFONT(h);

    y += S(20);

    /* Args edit (multiline) */
    h = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL |
        WS_VSCROLL | ES_WANTRETURN,
        x + S(10), y, cw - S(25), S(90), hwnd, (HMENU)IDC_ARGS_EDIT, hInst, NULL);
    SETFONT(h);

    y += S(105);

    /* --- Options group box --- */
    h = CreateWindowExW(0, L"BUTTON", L"Options",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        x, y, cw, S(60), hwnd, (HMENU)IDC_GRP_OPTIONS, hInst, NULL);
    SETFONT(h);

    h = CreateWindowExW(0, L"BUTTON", L"Auto-start",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        x + S(10), y + S(20), S(100), S(20), hwnd, (HMENU)IDC_CHK_AUTOSTART, hInst, NULL);
    SETFONT(h);



    h = CreateWindowExW(0, L"BUTTON", L"Don't show tray notification",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        x + S(240), y + S(20), cw - S(245), S(20), hwnd, (HMENU)IDC_CHK_NOTRAY_NOTIF, hInst, NULL);
    SETFONT(h);

    y += S(70);

    /* --- Service group box --- */
    h = CreateWindowExW(0, L"BUTTON", L"Service",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        x, y, cw, S(55), hwnd, (HMENU)IDC_GRP_SERVICE, hInst, NULL);
    SETFONT(h);

    h = CreateWindowExW(0, L"BUTTON", L"Install as Windows Service (auto-start with Windows)",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        x + S(10), y + S(22), S(400), S(20), hwnd, (HMENU)IDC_CHK_SERVICE, hInst, NULL);
    SETFONT(h);

    y += S(65);

    /* --- Buttons row --- */
    h = CreateWindowExW(0, L"BUTTON", L"\x25B6 Start",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, y, S(90), S(30), hwnd, (HMENU)IDC_BTN_START, hInst, NULL);
    SETFONT(h);

    h = CreateWindowExW(0, L"BUTTON", L"\x25A0 Stop",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x + S(100), y, S(90), S(30), hwnd, (HMENU)IDC_BTN_STOP, hInst, NULL);
    SETFONT(h);

    h = CreateWindowExW(0, L"BUTTON", L"Find Best",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x + cw - S(210), y, S(100), S(30), hwnd, (HMENU)IDC_BTN_SCAN, hInst, NULL);
    SETFONT(h);

    h = CreateWindowExW(0, L"BUTTON", L"Save Preset",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x + cw - S(100), y, S(100), S(30), hwnd, (HMENU)IDC_BTN_SAVE_PRESET, hInst, NULL);
    SETFONT(h);

    y += S(40);

    /* --- Log label --- */
    h = CreateWindowExW(0, L"STATIC", L"Ready.",
        WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP | SS_SUNKEN,
        x, y, cw, S(22), hwnd, (HMENU)IDC_LOG_LABEL, hInst, NULL);
    SETFONT(h);

    #undef S
    #undef SETFONT
}

/* ============================================================
 * Update status display
 * ============================================================ */

void Gui_UpdateStatus(HWND hwnd, BOOL running, DWORD pid)
{
    HWND hLabel = GetDlgItem(hwnd, IDC_STATUS_LABEL);
    HWND hDot   = GetDlgItem(hwnd, IDC_STATUS_DOT);
    HWND hPid   = GetDlgItem(hwnd, IDC_PID_LABEL);

    if (running) {
        SetWindowTextW(hLabel, L"Status: Running");
        SetWindowTextW(hDot, L"\x25CF"); /* ● in green — color set via WM_CTLCOLORSTATIC */

        wchar_t pidText[64];
        _snwprintf_s(pidText, 64, _TRUNCATE, L"PID: %lu", pid);
        SetWindowTextW(hPid, pidText);
    } else {
        SetWindowTextW(hLabel, L"Status: Stopped");
        SetWindowTextW(hDot, L"\x25CF");
        SetWindowTextW(hPid, L"");
    }

    /* Force repaint of the dot for color update */
    InvalidateRect(hDot, NULL, TRUE);
}

/* ============================================================
 * Control ↔ Config sync
 * ============================================================ */

void Gui_SetControls(HWND hwnd, const AppConfig *cfg)
{
    SetDlgItemTextW(hwnd, IDC_ARGS_EDIT, cfg->winwsArgs);

    HWND hCombo = GetDlgItem(hwnd, IDC_PRESET_COMBO);
    
    /* Repopulate the combo box to reflect any added/removed custom presets */
    SendMessageW(hCombo, CB_RESETCONTENT, 0, 0);
    for (int i = 0; i < (int)PRESET_COUNT; i++) {
        SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)g_presets[i].name);
    }
    if (cfg) {
        for (int i = 0; i < cfg->customPresetCount; i++) {
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)cfg->customPresets[i].name);
        }
    }

    /* Find and select preset based on args text */
    Gui_UpdatePresetSelectionForArgs(hwnd, (AppConfig *)cfg);

    CheckDlgButton(hwnd, IDC_CHK_AUTOSTART,
                   cfg->autoStart ? BST_CHECKED : BST_UNCHECKED);

    CheckDlgButton(hwnd, IDC_CHK_NOTRAY_NOTIF,
                   cfg->dontShowNotification ? BST_CHECKED : BST_UNCHECKED);

    /* Service checkbox reflects actual service state */
    BOOL svcInstalled = Service_IsInstalled(cfg->serviceName);
    CheckDlgButton(hwnd, IDC_CHK_SERVICE,
                   svcInstalled ? BST_CHECKED : BST_UNCHECKED);
}

void Gui_ReadControls(HWND hwnd, AppConfig *cfg)
{
    GetDlgItemTextW(hwnd, IDC_ARGS_EDIT, cfg->winwsArgs, CONFIG_MAX_ARGS);

    /* Get selected preset name */
    HWND hCombo = GetDlgItem(hwnd, IDC_PRESET_COMBO);
    int sel = (int)SendMessageW(hCombo, CB_GETCURSEL, 0, 0);
    if (sel >= 0 && sel < (int)PRESET_COUNT) {
        wcscpy_s(cfg->presetName, CONFIG_MAX_NAME, g_presets[sel].name);
    }

    cfg->autoStart = (IsDlgButtonChecked(hwnd, IDC_CHK_AUTOSTART) == BST_CHECKED);

    cfg->dontShowNotification = (IsDlgButtonChecked(hwnd, IDC_CHK_NOTRAY_NOTIF) == BST_CHECKED);
}

void Gui_SetLog(HWND hwnd, const wchar_t *msg)
{
    SetDlgItemTextW(hwnd, IDC_LOG_LABEL, msg);
}

/* ============================================================
 * Get preset args for a given combo selection index
 * ============================================================ */

const wchar_t *Gui_GetPresetArgs(const AppConfig *cfg, int index)
{
    if (index >= 0 && index < (int)PRESET_COUNT) {
        return g_presets[index].args;
    }
    if (cfg && index >= (int)PRESET_COUNT && index < (int)PRESET_COUNT + cfg->customPresetCount) {
        return cfg->customPresets[index - (int)PRESET_COUNT].args;
    }
    return L"";
}

void Gui_UpdatePresetSelectionForArgs(HWND hwnd, AppConfig *cfg)
{
    wchar_t currentArgs[CONFIG_MAX_ARGS];
    GetDlgItemTextW(hwnd, IDC_ARGS_EDIT, currentArgs, CONFIG_MAX_ARGS);

    int matchIdx = -1;
    /* Check built-ins */
    for (int i = 0; i < (int)PRESET_COUNT; i++) {
        if (wcscmp(g_presets[i].args, currentArgs) == 0) {
            matchIdx = i;
            break;
        }
    }
    /* Check custom */
    if (matchIdx == -1) {
        for (int i = 0; i < cfg->customPresetCount; i++) {
            if (wcscmp(cfg->customPresets[i].args, currentArgs) == 0) {
                matchIdx = (int)PRESET_COUNT + i;
                break;
            }
        }
    }

    HWND hCombo = GetDlgItem(hwnd, IDC_PRESET_COMBO);
    int count = (int)SendMessageW(hCombo, CB_GETCOUNT, 0, 0);
    
    if (matchIdx != -1) {
        /* If the last item is "<Custom>", remove it because we matched a real preset */
        if (count > (int)PRESET_COUNT + cfg->customPresetCount) {
            SendMessageW(hCombo, CB_DELETESTRING, count - 1, 0);
        }
        SendMessageW(hCombo, CB_SETCURSEL, matchIdx, 0);
        
        /* Update config with the real preset name */
        if (matchIdx < (int)PRESET_COUNT) {
            wcscpy_s(cfg->presetName, CONFIG_MAX_NAME, g_presets[matchIdx].name);
        } else {
            wcscpy_s(cfg->presetName, CONFIG_MAX_NAME, cfg->customPresets[matchIdx - (int)PRESET_COUNT].name);
        }
    } else {
        /* No match. Add "<Custom>" if it doesn't exist */
        if (count == (int)PRESET_COUNT + cfg->customPresetCount) {
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"<Custom>");
        }
        SendMessageW(hCombo, CB_SETCURSEL, (int)PRESET_COUNT + cfg->customPresetCount, 0);
        wcscpy_s(cfg->presetName, CONFIG_MAX_NAME, L"<Custom>");
    }
}

int Gui_GetPresetCount(const AppConfig *cfg)
{
    return (int)PRESET_COUNT + (cfg ? cfg->customPresetCount : 0);
}

BOOL Gui_AddCustomPreset(AppConfig *cfg, const wchar_t *name, const wchar_t *args)
{
    if (!cfg || !name || !args) return FALSE;
    
    /* Check if preset with same name already exists */
    for (int i = 0; i < cfg->customPresetCount; i++) {
        if (wcscmp(cfg->customPresets[i].name, name) == 0) {
            /* Overwrite existing */
            wcscpy_s(cfg->customPresets[i].args, CONFIG_MAX_ARGS, args);
            return TRUE;
        }
    }
    
    /* Not found, add new */
    if (cfg->customPresetCount >= MAX_CUSTOM_PRESETS) return FALSE;
    
    wcscpy_s(cfg->customPresets[cfg->customPresetCount].name, CONFIG_MAX_NAME, name);
    wcscpy_s(cfg->customPresets[cfg->customPresetCount].args, CONFIG_MAX_ARGS, args);
    cfg->customPresetCount++;
    return TRUE;
}

BOOL Gui_RemoveCustomPreset(AppConfig *cfg, int index)
{
    if (!cfg) return FALSE;
    int customIdx = index - (int)PRESET_COUNT;
    if (customIdx < 0 || customIdx >= cfg->customPresetCount) return FALSE;
    
    for (int i = customIdx; i < cfg->customPresetCount - 1; i++) {
        cfg->customPresets[i] = cfg->customPresets[i + 1];
    }
    cfg->customPresetCount--;
    return TRUE;
}

BOOL Gui_RenameCustomPreset(AppConfig *cfg, int index, const wchar_t *newName)
{
    if (!cfg || !newName) return FALSE;
    int customIdx = index - (int)PRESET_COUNT;
    if (customIdx < 0 || customIdx >= cfg->customPresetCount) return FALSE;
    
    wcscpy_s(cfg->customPresets[customIdx].name, CONFIG_MAX_NAME, newName);
    return TRUE;
}

/* ============================================================
 * Responsive layout — repositions all controls on WM_SIZE
 * ============================================================ */

void Gui_OnResize(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    int W = rc.right;
    int H = rc.bottom;

    if (W == 0 || H == 0) return; /* minimized */

    #define S(v) Dpi_Scale(hwnd, v)

    int margin = S(15);
    int x = margin;
    int cw = W - 2 * margin;  /* content width tracks window width */
    if (cw < S(200)) cw = S(200);

    int y = S(10);

    /* --- Status row --- */
    MoveWindow(GetDlgItem(hwnd, IDC_STATUS_DOT),   x, y + S(-1.5), S(12), S(16), TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_STATUS_LABEL),  x + S(14), y, S(200), S(20), TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_PID_LABEL),     x + cw - S(160), y, S(160), S(20), TRUE);

    y += S(30);

    /* Calculate how much vertical space the fixed-height sections need */
    int fixedBelow = S(5)   /* gap after strategy */
                   + S(60)  /* options groupbox */
                   + S(10)  /* gap */
                   + S(55)  /* service groupbox */
                   + S(10)  /* gap */
                   + S(30)  /* buttons */
                   + S(10)  /* gap */
                   + S(22)  /* log bar */
                   + S(5);  /* bottom padding */

    /* Strategy groupbox gets all remaining vertical space */
    int stratH = H - y - fixedBelow;
    if (stratH < S(140)) stratH = S(140);

    MoveWindow(GetDlgItem(hwnd, IDC_GRP_STRATEGY), x, y, cw, stratH, TRUE);

    int sy = y + S(20);

    /* Preset row */
    MoveWindow(GetDlgItem(hwnd, IDC_LBL_PRESET),   x + S(10), sy + S(3), S(50), S(20), TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_PRESET_COMBO),  x + S(65), sy, cw - S(130), S(200), TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_BTN_REN_PRESET), x + cw - S(60), sy, S(25), S(22), TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_BTN_DEL_PRESET), x + cw - S(30), sy, S(25), S(22), TRUE);

    sy += S(30);

    /* Args label */
    MoveWindow(GetDlgItem(hwnd, IDC_LBL_ARGS), x + S(10), sy, S(200), S(18), TRUE);

    sy += S(20);

    /* Args edit — fills remaining space in strategy groupbox */
    int argsH = stratH - S(20 + 30 + 20 + 15);
    if (argsH < S(40)) argsH = S(40);
    MoveWindow(GetDlgItem(hwnd, IDC_ARGS_EDIT), x + S(10), sy, cw - S(25), argsH, TRUE);

    y += stratH + S(5);

    /* --- Options groupbox --- */
    MoveWindow(GetDlgItem(hwnd, IDC_GRP_OPTIONS),      x, y, cw, S(60), TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_CHK_AUTOSTART),    x + S(10), y + S(20), S(100), S(20), TRUE);

    MoveWindow(GetDlgItem(hwnd, IDC_CHK_NOTRAY_NOTIF), x + S(240), y + S(20), cw - S(245), S(20), TRUE);

    y += S(70);

    /* --- Service groupbox --- */
    MoveWindow(GetDlgItem(hwnd, IDC_GRP_SERVICE), x, y, cw, S(55), TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_CHK_SERVICE), x + S(10), y + S(22), cw - S(25), S(20), TRUE);

    y += S(65);

    /* --- Buttons row --- */
    MoveWindow(GetDlgItem(hwnd, IDC_BTN_START), x, y, S(90), S(30), TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_BTN_STOP),  x + S(100), y, S(90), S(30), TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_BTN_SCAN),  x + cw - S(210), y, S(100), S(30), TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_BTN_SAVE_PRESET),  x + cw - S(100), y, S(100), S(30), TRUE);

    y += S(40);

    /* --- Log bar --- */
    MoveWindow(GetDlgItem(hwnd, IDC_LOG_LABEL), x, y, cw, S(22), TRUE);

    #undef S

    InvalidateRect(hwnd, NULL, TRUE);
}

/* ============================================================
 * Selective Import Dialog
 * ============================================================ */

static ImportPresetItem *g_importItems = NULL;
static int g_importCount = 0;

static LRESULT CALLBACK ImportWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_INITDIALOG: {
        HWND hList = GetDlgItem(hwnd, IDC_LIST_IMPORT);
        for (int i = 0; i < g_importCount; i++) {
            SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)g_importItems[i].name);
            /* Select all by default */
            SendMessageW(hList, LB_SETSEL, TRUE, i);
        }
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_BTN_IMPORT_ALL: {
            HWND hList = GetDlgItem(hwnd, IDC_LIST_IMPORT);
            for (int i = 0; i < g_importCount; i++) {
                SendMessageW(hList, LB_SETSEL, TRUE, i);
            }
            break;
        }
        case IDC_BTN_IMPORT_NONE: {
            HWND hList = GetDlgItem(hwnd, IDC_LIST_IMPORT);
            for (int i = 0; i < g_importCount; i++) {
                SendMessageW(hList, LB_SETSEL, FALSE, i);
            }
            break;
        }
        case IDC_BTN_IMPORT_SEL: {
            HWND hList = GetDlgItem(hwnd, IDC_LIST_IMPORT);
            for (int i = 0; i < g_importCount; i++) {
                g_importItems[i].selected = (SendMessageW(hList, LB_GETSEL, i, 0) > 0);
            }
            SetWindowLongPtrW(hwnd, DWLP_USER, IDYES);
            ShowWindow(hwnd, SW_HIDE);
            break;
        }
        case IDCANCEL:
            SetWindowLongPtrW(hwnd, DWLP_USER, IDCANCEL);
            ShowWindow(hwnd, SW_HIDE);
            break;
        }
        break;
    case WM_CLOSE:
        SetWindowLongPtrW(hwnd, DWLP_USER, IDCANCEL);
        ShowWindow(hwnd, SW_HIDE);
        break;
    }
    return FALSE;
}

BOOL Gui_ImportSelector(HWND parent, ImportPresetItem *items, int count) {
    g_importItems = items;
    g_importCount = count;
    
    #pragma pack(push, 1)
    struct {
        DLGTEMPLATE dlg;
        WORD menu;
        WORD _class;
        wchar_t title[64];
    } templ = {0};
    #pragma pack(pop)
    
    templ.dlg.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_CENTER;
    templ.dlg.cx = 250;
    templ.dlg.cy = 200;
    wcscpy_s(templ.title, 64, L"Select Presets to Import");

    HWND hwnd = CreateDialogIndirectW(GetModuleHandleW(NULL), &templ.dlg, parent, ImportWndProc);
    
    NONCLIENTMETRICSW ncm = { .cbSize = sizeof(ncm) };
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    HFONT hFont = CreateFontIndirectW(&ncm.lfMessageFont);
    
    #define S(v) Dpi_Scale(parent, v)
    
    HWND h;
    h = CreateWindowW(L"STATIC", L"Select the presets you wish to import:", WS_CHILD | WS_VISIBLE, S(10), S(10), S(230), S(20), hwnd, (HMENU)0, NULL, NULL); 
    SendMessageW(h, WM_SETFONT, (WPARAM)hFont, FALSE);
    
    /* LBS_MULTIPLESEL | LBS_EXTENDEDSEL enables standard shift/ctrl click multi-select */
    h = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_MULTIPLESEL | LBS_EXTENDEDSEL, S(10), S(30), S(230), S(160), hwnd, (HMENU)IDC_LIST_IMPORT, NULL, NULL); 
    SendMessageW(h, WM_SETFONT, (WPARAM)hFont, FALSE);
    
    h = CreateWindowW(L"BUTTON", L"Select All", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, S(10), S(200), S(70), S(25), hwnd, (HMENU)IDC_BTN_IMPORT_ALL, NULL, NULL); 
    SendMessageW(h, WM_SETFONT, (WPARAM)hFont, FALSE);
    
    h = CreateWindowW(L"BUTTON", L"Deselect All", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, S(85), S(200), S(80), S(25), hwnd, (HMENU)IDC_BTN_IMPORT_NONE, NULL, NULL); 
    SendMessageW(h, WM_SETFONT, (WPARAM)hFont, FALSE);
    
    h = CreateWindowW(L"BUTTON", L"Import", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, S(170), S(200), S(70), S(25), hwnd, (HMENU)IDC_BTN_IMPORT_SEL, NULL, NULL); 
    SendMessageW(h, WM_SETFONT, (WPARAM)hFont, FALSE);
    
    #undef S
    
    RECT r = {0, 0, Dpi_Scale(parent, 250), Dpi_Scale(parent, 235)};
    AdjustWindowRect(&r, WS_POPUP | WS_CAPTION | WS_SYSMENU, FALSE);
    SetWindowPos(hwnd, NULL, 0, 0, r.right - r.left, r.bottom - r.top, SWP_NOMOVE | SWP_NOZORDER);
    
    SendMessageW(hwnd, WM_INITDIALOG, 0, 0);
    
    EnableWindow(parent, FALSE);
    ShowWindow(hwnd, SW_SHOW);
    
    MSG msg;
    INT_PTR ret = IDCANCEL;
    while (IsWindow(hwnd) && GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (!IsWindowVisible(hwnd)) {
            ret = GetWindowLongPtrW(hwnd, DWLP_USER);
            break;
        }
    }
    
    DestroyWindow(hwnd);
    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
    
    return (ret == IDYES);
}

int Gui_CrashDialog(HWND parent, BOOL isCustom)
{
    TASKDIALOGCONFIG config = {0};
    config.cbSize = sizeof(config);
    config.hwndParent = parent;
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_USE_COMMAND_LINKS;
    config.pszWindowTitle = L"Engine Crash Detected";
    config.pszMainInstruction = L"The winws engine crashed immediately!";
    config.pszContent = L"This is usually caused by invalid winws arguments or an incompatible preset.";
    config.pszMainIcon = TD_ERROR_ICON;

    TASKDIALOG_BUTTON buttons[3];
    int buttonCount = 0;

    buttons[buttonCount].nButtonID = ID_CRASH_EDIT;
    buttons[buttonCount].pszButtonText = L"Keep Preset, Stop Engine\nStay on this preset but stop the engine so I can fix the arguments.";
    buttonCount++;

    if (isCustom) {
        buttons[buttonCount].nButtonID = ID_CRASH_DELETE;
        buttons[buttonCount].pszButtonText = L"Delete Preset, Fall Back to Recommended\nPermanently remove this faulty custom preset from my list.";
        buttonCount++;
    }

    buttons[buttonCount].nButtonID = ID_CRASH_FALLBACK;
    buttons[buttonCount].pszButtonText = isCustom ? 
        L"Keep Preset, Fall Back to Recommended\nKeep this preset for later but use the safe default for now." :
        L"Fall Back to Recommended\nUse the safe recommended default instead.";
    buttonCount++;

    config.pButtons = buttons;
    config.cButtons = buttonCount;

    int result = 0;
    TaskDialogIndirect(&config, &result, NULL, NULL);
    return result;
}

#pragma once

/* ============================================================
 * Embedded zapret binaries (RCDATA resources)
 * ============================================================ */
#define IDR_WINWS_EXE           101
#define IDR_CYGWIN1_DLL         102
#define IDR_WINDIVERT_DLL       103
#define IDR_WINDIVERT64_SYS     104
#define IDR_QUIC_INITIAL_BIN    105
#define IDR_TLS_CLIENTHELLO_BIN 106
#define IDR_STUN_BIN            107

/* ============================================================
 * Application icon
 * ============================================================ */
#define IDI_APP_ICON            201

/* ============================================================
 * GUI Control IDs
 * ============================================================ */
#define IDC_STATUS_DOT          1001
#define IDC_STATUS_LABEL        1002
#define IDC_PID_LABEL           1003
#define IDC_PRESET_COMBO        1004
#define IDC_ARGS_EDIT           1005
#define IDC_CHK_AUTOSTART       1006
#define IDC_CHK_NOTRAY_NOTIF    1007
#define IDC_CHK_SERVICE         1008
#define IDC_BTN_START           1009
#define IDC_BTN_STOP            1010
#define IDC_BTN_SAVE_PRESET     1011
#define IDC_LOG_LABEL           1012
#define IDC_GRP_STRATEGY        1013
#define IDC_GRP_OPTIONS         1014
#define IDC_GRP_SERVICE         1015
#define IDC_LBL_PRESET          1016
#define IDC_LBL_ARGS            1017
#define IDC_LBL_SERVICE_DESC    1018
#define IDC_CHK_AUTODNS         1019
#define IDC_BTN_DEL_PRESET      1020
#define IDC_BTN_REN_PRESET      1021
#define IDC_BTN_SCAN            1022

/* Scanner UI */
#define IDC_LBL_HOSTS           1023
#define IDC_LIST_HOSTS          1024
#define IDC_EDIT_HOST           1025
#define IDC_BTN_ADD_HOST        1026
#define IDC_BTN_DEL_HOST        1027
#define IDC_LOG_SCANNER         1028
#define IDC_PROG_SCANNER        1029
#define IDC_BTN_START_SCAN      1030
#define IDC_CHK_BUILTIN         1031

/* Import Selector UI */
#define IDC_LIST_IMPORT         1032
#define IDC_BTN_IMPORT_SEL      1033
#define IDC_BTN_IMPORT_ALL      1034
#define IDC_BTN_IMPORT_NONE     1035

/* ============================================================
 * System tray
 * ============================================================ */
#define WM_TRAYICON             (WM_USER + 1)
#define IDM_TRAY_SHOW           2001
#define IDM_TRAY_START          2002
#define IDM_TRAY_STOP           2003
#define IDM_TRAY_EXIT           2004

/* ============================================================
 * Menus
 * ============================================================ */
#define IDR_MAIN_MENU           2010
#define IDM_FILE_IMPORT         2011
#define IDM_FILE_EXPORT         2012
#define IDM_FILE_CLEAN          2013
#define IDM_FILE_EXIT           2014

/* ============================================================
 * Timer
 * ============================================================ */
#define TIMER_STATUS_POLL       3001
#define TIMER_STATUS_INTERVAL   2000  /* ms */

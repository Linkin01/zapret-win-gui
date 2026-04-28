#pragma once

#include <windows.h>
#include <stdbool.h>

/* Start the background thread for WinDivert DNS interception */
BOOL DnsRedir_Start(LPCWSTR extractDir);

/* Stop the DNS interception thread and close handles */
void DnsRedir_Stop(void);

/* Check if DNS interception is currently active */
BOOL DnsRedir_IsRunning(void);

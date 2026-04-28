#pragma once

#include <windows.h>
#include "config.h"

/* Opens the Scanner dialog. Returns TRUE if the user accepted a new preset,
 * in which case `cfg` is updated with the new arguments. */
BOOL Scanner_Run(HWND hwndParent, AppConfig *cfg);

/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ansi-color.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void display_internal(bool enable_color, const char *color, const char *fmt, ...) {
        va_list ap;

        va_start(ap, fmt);

        if (!enable_color || (isatty(STDOUT_FILENO) < 0 && isatty(STDERR_FILENO) < 0)) {
                vprintf(fmt, ap);
                va_end(ap);
                return;
        }

        printf("%s", color);
        vprintf(fmt, ap);
        printf("%s", ansi_color_reset());
        va_end(ap);
}

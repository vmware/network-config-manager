/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ansi-color.h"
#include "parse-util.h"

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#elif defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif

void display_internal(bool enable_color, const char *color, const char *fmt, ...) {
       bool env_enable = true;
       const char *e;
       va_list ap;

       e = getenv("NMCTL_BEAUTIFY");
       if (e)
               env_enable = parse_boolean(e);

       va_start(ap, fmt);

       if (!env_enable || !enable_color || (isatty(STDOUT_FILENO) < 0 && isatty(STDERR_FILENO) < 0)) {
               vprintf(fmt, ap);
               va_end(ap);
               return;
       }

       printf("%s", color);
       vprintf(fmt, ap);
       printf("%s", ansi_color_reset());
       va_end(ap);
}

/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ansi-color.h"
#include "parse-util.h"
#include "string-util.h"

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#elif defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif

bool colors_supported(void) {
       const char *e;

       if (isatty(STDOUT_FILENO) < 0 && isatty(STDERR_FILENO) < 0)
           return false;

       e = getenv("TERM");
       if (e) {
           if (string_equal(e, "dumb"))
               return false;
       }

       e = getenv("NMCTL_BEAUTIFY");
       if (e)
           return parse_boolean(e) ? true : false;

       return true;
}

void display(bool enable_color, const char *color, const char *fmt, ...) {
       va_list ap;

       va_start(ap, fmt);

       if (!colors_supported() || !enable_color) {
               vprintf(fmt, ap);
               va_end(ap);
               return;
       }

       printf("%s", color);
       vprintf(fmt, ap);
       printf("%s", ansi_color_reset());
       va_end(ap);
}

/* 
 * Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "color.h"

static const char *const color_codes[] = {
        "\e[31m",
        "\e[32m",
        "\e[33m",
        "\e[34m",
        "\e[35m",
        "\e[36m",
        "\e[37m",
        "\e[1;31m",
        "\e[1;32m",
        "\e[1;33m",
        "\e[1;34m",
        "\e[1;35m",
        "\e[1;36m",
        "\e[1;37m",
        "\x1B[0;1;39m",
        "\x1b[31m\x1b[44m",
        "\x1B[0;1;35m",
        "\e[0m",
        NULL,
};

static bool color_is_enabled;

void enable_color(void)
{
        if (isatty(fileno(stdout)))
                color_is_enabled = true;
}

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#elif defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif

int cprintf(FILE *fp, color_t clr, const char *fmt, ...)
{
        int ret = 0;
        va_list args;

        va_start(args, fmt);

        if (!color_is_enabled) {
                ret = vfprintf(fp, fmt, args);
                goto end;
        }

        ret += fprintf(fp, "%s", color_codes[clr]);
        ret += vfprintf(fp, fmt, args);
        ret += fprintf(fp, "%s", color_codes[C_CLEAR]);

end:
        va_end(args);
        return ret;
}

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#elif defined(__clang__)
#pragma clang diagnostic pop
#endif

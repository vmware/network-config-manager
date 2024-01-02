/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>

#define ANSI_COLOR_RED           "\x1b[31m"
#define ANSI_COLOR_GREEN         "\x1b[32m"
#define ANSI_COLOR_YELLOW        "\x1b[33m"
#define ANSI_COLOR_BLUE          "\x1b[34m"
#define ANSI_COLOR_MAGENTA       "\x1b[35m"
#define ANSI_COLOR_CYAN          "\x1b[36m"
#define ANSI_COLOR_RESET         "\x1b[0m"

#define ANSI_COLOR_BOLD_RED      "\x1b[1;31m"
#define ANSI_COLOR_BOLD_GREEN    "\x1b[1;32m"
#define ANSI_COLOR_BOLD_YELLOW   "\x1b[1;33m"
#define ANSI_COLOR_BOLD_BLUE     "\x1b[1;34m"
#define ANSI_COLOR_BOLD_MAGENTA  "\x1b[1;36m"
#define ANSI_COLOR_BOLD_CYAN     "\x1b[1;36m"

#define ANSI_COLOR_BLUE_HEADER   "\x1b[31m\x1b[44m"
#define ANSI_COLOR_HEADER_RESET  "\x1b[0m"

#define ANSI_COLOR_BLUE_MAGENTA  "\x1B[0;1;35m"
#define ANSI_COLOR_GRAY_BOLD     "\x1B[0;1;90m"

#define ANSI_COLOR_BOLD          "\x1B[0;1;39m"
#define ANSI_COLOR_UNDERLINE      "\x1B[0;4m"
#define ANSI_COLOR_UNDERLINE_BOLD "\x1B[0;1;4m"

bool colors_supported(void);

#define DEFINE_ANSI_COLOR_INLINE_FUNCTION(name, NAME)                 \
        static inline const char *ansi_color_##name(void) {           \
                return colors_supported() ? ANSI_COLOR_##NAME : "";   \
        }

DEFINE_ANSI_COLOR_INLINE_FUNCTION(red,               RED);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(green,             GREEN);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(yellow,            YELLOW);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(bold_yellow,       BOLD_YELLOW);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(blue,              BLUE);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(bold_blue,         BOLD_BLUE);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(magenta,           MAGENTA);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(blue_magenta,      BLUE_MAGENTA);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(cyan,              CYAN);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(bold_cyan,         BOLD_CYAN);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(bold,              CYAN);
DEFINE_ANSI_COLOR_INLINE_FUNCTION(reset,             RESET);

void display(bool enable_color, const char *color, const char *fmt, ...);

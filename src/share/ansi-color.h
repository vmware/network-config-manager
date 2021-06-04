/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

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

static inline const char *ansi_color_red(void) {
        return ANSI_COLOR_RED;
}

static inline const char *ansi_color_green(void) {
        return ANSI_COLOR_GREEN;
}

static inline const char *ansi_color_yellow(void) {
        return ANSI_COLOR_YELLOW;
}

static inline const char *ansi_color_blue(void) {
        return ANSI_COLOR_BLUE;
}

static inline const char *ansi_color_magneta(void) {
        return ANSI_COLOR_MAGENTA;
}

static inline const char * ansi_color_cyan(void) {
        return ANSI_COLOR_CYAN;
}

static inline const char *ansi_color_reset(void) {
        return ANSI_COLOR_RESET;
}

static inline const char *ansi_color_bold_red(void) {
        return ANSI_COLOR_BOLD_RED;
}

static inline const char *ansi_color_bold_green(void) {
        return ANSI_COLOR_BOLD_GREEN;
}

static inline const char *ansi_color_bold_yellow(void) {
        return ANSI_COLOR_BOLD_YELLOW;
}

static inline const char *ansi_color_bold_blue(void) {
        return ANSI_COLOR_BOLD_BLUE;
}

static inline const char *ansi_color_bold_magneta(void) {
        return ANSI_COLOR_BOLD_MAGENTA;
}

static inline const char * ansi_color_bold_cyan(void) {
        return ANSI_COLOR_BOLD_CYAN;
}

static inline const char *ansi_color_blue_header(void) {
        return ANSI_COLOR_BLUE_HEADER;
}

static inline const char *ansi_color_bold(void) {
        return ANSI_COLOR_BOLD;
}

static inline const char *ansi_color_underline(void) {
        return ANSI_COLOR_UNDERLINE;
}

static inline const char *ansi_color_underline_bold(void) {
        return ANSI_COLOR_UNDERLINE_BOLD;
}

static inline const char *ansi_color_blue_magenta(void) {
        return ANSI_COLOR_BLUE_MAGENTA;
}

static inline const char *ansi_color_grey_bold(void) {
        return ANSI_COLOR_GRAY_BOLD;
}

static inline const char *ansi_color_header_reset(void) {
        return ANSI_COLOR_HEADER_RESET;
}

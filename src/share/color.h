/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>

#define cprout(clr, fmt, ...)   cprintf(stdout, (clr), fmt, ##__VA_ARGS__)

typedef enum _color_t {
    C_RED,
    C_GREEN,
    C_YELLOW,
    C_BLUE,
    C_MAGENTA,
    C_CYAN,
    C_WHITE,
    C_BOLD_RED,
    C_BOLD_GREEN,
    C_BOLD_YELLOW,
    C_BOLD_BLUE,
    C_BOLD_MAGENTA,
    C_BOLD_CYAN,
    C_BOLD_WHITE,
    C_BOLD,
    C_BLUE_HDR,
    C_BLUE_MAGENTA,
    C_CLEAR
} color_t;

void enable_color(void);
int cprintf(FILE *fp, color_t clr, const char *fmt, ...);

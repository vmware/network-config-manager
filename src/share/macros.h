/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#undef NDEBUG

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#define SET_FLAG(v, flag, b) \
        (v) = (b) ? ((v) | (flag)) : ((v) & ~(flag))
#define FLAGS_SET(v, flags) \
        ((~(v) & (flags)) == 0)

#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))
#define OFFSETOF(x,y) __builtin_offsetof(x,y)

#define _public_ __attribute__((visibility("default")))

static inline void parse_next_arg(char **argv, int argc,int i) {
        if (i + 1 >= argc) {
                printf("Missing argument: %s\n", argv[i]);
                _exit(-EINVAL);
        }
}

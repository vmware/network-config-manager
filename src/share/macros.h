/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
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

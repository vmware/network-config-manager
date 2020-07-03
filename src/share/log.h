/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include <glib.h>

#define log_debug   g_debug
#define log_error   g_error
#define log_warning g_warning
#define log_notice  g_notice
#define log_info    g_info

static inline int log_oom(void) {
        log_warning("Out of memory");
        return -ENOMEM;
}

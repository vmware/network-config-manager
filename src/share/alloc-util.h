/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include <assert.h>
#include <errno.h>
#include <glib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#define new(t, n) ((t *) g_new(t, n))
#define new0(t, n) ((t*) g_new0(t, n))

static inline void *mfree(void *memory) {
        g_free(memory);

        return NULL;
}

static inline void freep(void *p) {
        g_free(*(void **) p);
}

#define DEFINE_CLEANUP(type, func)                              \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        func(*p);                               \
        }                                                       \
        struct __useless_struct_to_allow_trailing_semicolon__

#define _cleanup_(x) __attribute__((cleanup(x)))

static inline void strv_free(char **strv) {
        if (strv && *strv)
                g_strfreev(strv);
}

static inline void g_string_unrefp(GString **s) {
        if (s && *s)
                g_string_free(*s, false);
}

static inline void g_dir_unrefp(GDir **d) {
        if (d && *d)
                g_dir_close(*d);
}

static inline void close_fdp(int *fd) {
        if (fd && *fd && *fd >= 0)
                close(*fd);
}

DEFINE_CLEANUP(FILE *, fclose);
DEFINE_CLEANUP(FILE *, pclose);
DEFINE_CLEANUP(int *, close_fdp);
DEFINE_CLEANUP(GString **, g_string_unrefp);
DEFINE_CLEANUP(char **, strv_free);
DEFINE_CLEANUP(GHashTable *, g_hash_table_unref);
DEFINE_CLEANUP(GDir **, g_dir_unrefp);

#define _auto_cleanup_ _cleanup_(freep)
#define _auto_cleanup_fclose_ _cleanup_(fclosep)
#define _auto_cleanup_close_ _cleanup_(close_fdp)
#define _auto_cleanup_pclose_ _cleanup_(pclosep)
#define _auto_cleanup_closedir_ _cleanup_(closedirp)
#define _auto_cleanup_hash_ _cleanup_(g_hash_table_unrefp)
#define _auto_cleanup_strv_ _cleanup_(strv_freep)
#define _auto_cleanup_gstring_ _cleanup_(strv_freep)

#define steal_pointer(ptr)                      \
        ({                                      \
                typeof(ptr) _ptr_ = (ptr);      \
                (ptr) = NULL;                   \
                _ptr_;                          \
        })

#define steal_fd(fd)                    \
        ({                              \
                int _fd_ = (fd);        \
                (fd) = -1;              \
                _fd_;                   \
        })

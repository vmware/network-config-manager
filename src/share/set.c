/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <assert.h>

#include "alloc-util.h"
#include "log.h"
#include "macros.h"
#include "set.h"

int set_new(Set **ret, GHashFunc hash_func, GEqualFunc compare_func) {
        _auto_cleanup_ Set *s = NULL;

        s = new0(Set, 1);
        if (!s)
                return log_oom();

        if (hash_func && compare_func) {
                *s = (Set) {
                        .hash = g_hash_table_new_full(hash_func, compare_func, NULL, NULL),
                };
        } else {
                *s = (Set) {
                        .hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL),
                };
        }

        if (!s->hash)
                return log_oom();

        *ret = steal_ptr(s);
        return 0;
}

void set_free(Set *s) {
        if (!s)
                return;

        g_hash_table_destroy(s->hash);
        free(s);
}

bool set_add(Set *s, void *k) {
        assert(s);
        assert(k);

        return g_hash_table_add(s->hash, k);
}

bool set_contains(Set *s, void *k) {
        assert(s);
        assert(k);

        return g_hash_table_contains(s->hash, k);
}

void set_foreach(Set *s, GHFunc func, gpointer user_data) {
        assert(s);
        assert(func);

        return g_hash_table_foreach(s->hash, func, user_data);
}

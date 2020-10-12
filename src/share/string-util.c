/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "macros.h"
#include "string-util.h"

const char *bool_to_string(bool x) {
        if (x)
                return "yes";
        else
                return "no";

        return "n/a";
}

int split_pair(const char *s, const char *sep, char **l, char **r) {
        _auto_cleanup_ char *a = NULL, *b = NULL;
        _auto_cleanup_strv_ char **x = NULL;

        assert(s);
        assert(sep);
        assert(l);
        assert(r);

        if (isempty_string(sep))
                return -EINVAL;

        x = g_strsplit(s, sep, 0);
        if (!x)
                return -EINVAL;

        if (x[0]) {
                a = g_strdup(x[0]);
                if (!a)
                        return -ENOMEM;;
        }

        if (x[1]) {
                b = g_strdup(x[1]);
                if (!b)
                        return -ENOMEM;;
        }

        *l = steal_pointer(a);
        *r = steal_pointer(b);

        return 0;
}

char *truncate_newline(char *s) {
        assert(s);

        s[strcspn(s, NEWLINE)] = 0;
        return s;
}

char *string_strip(char *s) {
        char *t = NULL;

        if (!s)
                return NULL;

        t = g_strescape(s, NULL);

        return g_strstrip(t);
}

int skip_first_word_and_split(char *line, const char *first_word, const char *sep, char ***ret) {
        _auto_cleanup_strv_ char **a = NULL;
        size_t n;
        char *k;

        assert(line);
        assert(sep);
        assert(first_word);

        if (string_has_prefix(line, first_word)) {
                n = strspn(line, first_word);
                k = line + n;
                k = string_strip(k);

                a = strsplit(k, sep, 0);
                if (!a)
                        return -ENOMEM;
        }

        *ret = steal_pointer(a);

        return 0;
}

char **strv_new(char *x) {
        _auto_cleanup_strv_ char **a = NULL;

        assert(x);

         a = new0(char *, 2);
         if (!a)
                 return NULL;

         a[0] = g_strdup(x);
         if (!a[0])
                 return NULL;

         return steal_pointer(a);
}

int strv_add(char ***l, char *value) {
        char **c;
        size_t n, m;

        assert(l);
        assert(value);

        n = g_strv_length(*l);
        m = n + 2;

        c = realloc(*l, m * sizeof(char*));
        if (!c)
                return -ENOMEM;

        c[n] = value;
        c[n+1] = NULL;

        *l = c;
        return 0;
}

int argv_to_strv(int argc, char *argv[], char ***ret) {
        _auto_cleanup_strv_ char **s = NULL;
        int r, i;

        assert(argc);
        assert(argv);

        for (i = 0; i < argc; i++) {
                if (!s) {
                        s = strv_new(string_strip(argv[i]));
                        if (!s)
                                return -ENOMEM;

                        continue;
                }

                r = strv_add(&s, string_strip(argv[i]));
                if (r < 0)
                        return r;
        }

        *ret = steal_pointer(s);

        return 0;
}

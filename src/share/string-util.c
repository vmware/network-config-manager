/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
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

char *rstrip(char *s) {
        char *p;

        assert(s);

        for (p = s + strlen(s);p > s && isspace((unsigned char)(*--p));)
                *p = '\0';

        return s;
}

char *lskip(const char *s) {
        assert(s);

        for (;*s && isspace((unsigned char)(*s));)
                s++;

        return (char *)s;
}

char *find_chars_or_comment(const char *s, const char *chars) {
        assert(s);

        for (;*s && (!chars || !strchr(chars, *s));)
                s++;

        return (char *) s;
}

char *string_copy(char *dest, const char *src, size_t size) {
        size_t i;

        assert(dest);
        assert(src);
        assert(size > 0);

        for (i = 0; i < size - 1 && src[i]; i++)
                dest[i] = src[i];

        dest[i] = '\0';
        return dest;
}

const char *bool_to_str(bool x) {
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

        if (isempty_str(sep))
                return -EINVAL;

        x = g_strsplit(s, sep, 2);
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

        *l = steal_ptr(a);
        *r = steal_ptr(b);
        return 0;
}

char *truncate_newline(char *s) {
        assert(s);

        s[strcspn(s, NEWLINE)] = 0;
        return s;
}

char *str_strip(char *s) {
        char *t = NULL;

        if (!s)
                return NULL;

        t = g_strcompress(s);
        if (!t)
                return NULL;

        return g_strstrip(t);
}

char *free_and_strdup(char *s, char *t) {
        if (!s || !t)
                return NULL;

        free(s);
        return strdup(t);
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
                k = str_strip(k);

                a = strsplit(k, sep, 0);
                if (!a)
                        return -ENOMEM;
        }

        *ret = steal_ptr(a);
        return 0;
}

char **strv_new(const char *x) {
        _auto_cleanup_strv_ char **a = NULL;

        assert(x);

         a = new0(char *, 2);
         if (!a)
                 return NULL;

         a[0] = g_strdup(x);
         if (!a[0])
                 return NULL;

         return steal_ptr(a);
}

int strv_add(char ***l, const char *value) {
        char **c;
        size_t n, m;

        assert(l);
        assert(*l);
        assert(value);

        n = g_strv_length(*l);
        m = n + 2;

        c = realloc(*l, m * sizeof(char*));
        if (!c)
                return -ENOMEM;

        c[n] = strdup(value);
        if (!c[n])
                return -ENOMEM;

        c[n+1] = NULL;

        *l = c;
        return 0;
}

int strv_extend(char ***l, const char *value) {
        char **c;
        size_t n, m;

        assert(l);
        assert(value);

        if (!*l) {
                *l = strv_new(value);
                if (!*l)
                        return -ENOMEM;

                return 0;
        }

        n = g_strv_length(*l);
        m = n + 2;

        c = realloc(*l, m * sizeof(char*));
        if (!c)
                return -ENOMEM;

        c[n] = strdup(value);
        if (!c[n])
                return -ENOMEM;

        c[n+1] = NULL;

        *l = c;
        return 0;
}


int argv_to_strv(int argc, char *argv[], char ***ret) {
        _auto_cleanup_strv_ char **s = NULL;
        int r;

        assert(argc);
        assert(argv);

        for (int i = 0; i < argc; i++) {
                if (!s) {
                        s = strv_new(str_strip(argv[i]));
                        if (!s)
                                return -ENOMEM;

                        continue;
                }

                r = strv_add(&s, str_strip(argv[i]));
                if (r < 0)
                        return r;
        }

        *ret = steal_ptr(s);
        return 0;
}

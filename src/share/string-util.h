/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <string.h>

#define WHITESPACE        " \t\n\r"
#define NEWLINE           "\n\r"
#define QUOTES            "\"\'"
#define COMMENTS          "#;"

#define str_eq(a,b) (strcmp((a),(b)) == 0)
#define str_eq_fold(a,b) (strcasecmp((a),(b)) == 0)

#define strjoin g_strjoin
#define strsplit g_strsplit
#define string_has_prefix g_str_has_prefix
#define string_has_suffix g_str_has_suffix
#define strerror g_strerror

char* free_and_strdup(char *s, char *t);

static inline const char *str_na(const char *s) {
        return s ?: "n/a";
}

static inline const char *str_na_json(const char *s) {
        return s ?: "";
}

static inline bool isempty(const char *p) {
        return !p || !p[0];
}

static inline bool strv_empty(const char **p) {
        return !p || !p[0];
}

char* rstrip(char *s);
char* lskip(const char *s);
char* find_chars_or_comment(const char *s, const char *chars);
char* string_copy(char *dest, const char *src, size_t size);

int split_pair(const char *s, const char *sep, char **l, char **r);

char* truncate_newline(char *s);
char* str_strip(char *s);

#define strv_foreach(s, l)                      \
        for ((s) = (l); (s) && *(s); (s)++)

char** strv_new(const char *x);
#define strv_join(s, t) g_strjoinv(s, t)
#define strv_contains(s, t) g_strv_contains(s, t)
#define strv_length(s) g_strv_length(s)
#define strv_dup(s) g_strdupv(s)

char** strv_unique(char **s, char **t);
char** strv_remove(char **p, const char *s);
char** strv_remove_duplicates(char **s);

int strv_add(char ***l, const char *value);
char** strv_merge(char **a, char **b);

#define strv_parse_shell g_shell_parse_argv
int argv_to_strv(int argc, char *argv[], char ***ret);
int strv_extend(char ***l, const char *value);

int skip_first_word_and_split(char *line, const char *first_word, const char *sep, char ***ret);
const char *bool_to_str(bool x);

int unhexchar(char c);

/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <ctype.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "config-parser.h"
#include "config-parser.h"
#include "string-util.h"
#include "log.h"

int parse_key_file(const char *path, KeyFile **ret) {
        _cleanup_(section_freep) Section *section = NULL;
        _cleanup_(g_error_freep) GError *error = NULL;
        _auto_cleanup_ KeyFile *key_file = NULL;
        _auto_cleanup_strv_ char **lines = NULL;
        _auto_cleanup_ char *contents = NULL;
        char section_name[LINE_MAX] = {};
        char **l = NULL;
        char *s, *e;
        size_t n;
        int r;

        assert(path);

        if (!g_file_test(path, G_FILE_TEST_EXISTS))
                return -ENOENT;

        if (!g_file_get_contents(path, &contents, &n , &error))
                return -error->code;

        r = key_file_new(path, &key_file);
        if (r < 0)
                return r;

        lines = strsplit(contents, "\n", 0);
        if (!lines)
                return log_oom();

        strv_foreach(l, lines) {
                _auto_cleanup_ char *t = NULL;

                t = g_strdup(*l);
                if (!t)
                        return log_oom();

                s = string_strip(t);
                n = (int) strlen(s);
                if (n <= 0)
                        continue;

                if (isempty_string(s) || strchr(COMMENTS, *s))
                        continue;

                e = find_chars_or_comment(s, NULL);
                if (*e)
                        *e = '\0';
                rstrip(s);

                if (*s == '[') {
                        /* A "[section_name]" line */
                        e = find_chars_or_comment(s + 1, "]");
                        if (*e == ']') {
                                *e = '\0';
                                string_copy(section_name, s + 1, sizeof(section_name));

                                if (section) {
                                        r = add_section_to_key_file(key_file, section);
                                        if (r < 0)
                                                return r;

                                        steal_pointer(section);
                                }

                                r = section_new(section_name, &section);
                                if (r < 0)
                                        return r;
                        }
                } else if (*s) {
                        _auto_cleanup_ char *k = NULL, *v = NULL;

                        r = parse_line(s, &k, &v);
                        if (r < 0)
                                continue;

                        r = add_key_to_section(section, k, v);
                        if (r < 0)
                                return r;

                        steal_pointer(k);
                        steal_pointer(v);
                }
        }

        if (section) {
                r = add_section_to_key_file(key_file, section);
                if (r < 0)
                        return r;
                steal_pointer(section);
        }

        *ret = steal_pointer(key_file);
        return 0;
}

static void display_keys(gpointer data_ptr, gpointer ignored) {
        Key *k = data_ptr;

        printf("%s=%s\n", k->name, k->v);
}

static void display_sections(gpointer data_ptr, gpointer ignored) {
        Section *s = data_ptr;

        printf("\n[%s]\n", s->name);
        g_list_foreach(s->keys, display_keys, NULL);
}

int display_key_file(const KeyFile *k) {
        assert(k);

        printf("File: %s, sections: %ld\n", k->name, k->nsections);

        g_list_foreach(k->sections, display_sections, NULL);
        return 0;
}

bool key_file_config_exists(const KeyFile *key_file, const char *section, const char *k, const char *v) {
        GList *i;

        assert(k);

        assert(key_file);
        assert(section);
        assert(k);

        for (i = key_file->sections; i; i = g_list_next (i)) {
                Section *s = (Section *) i->data;

                if (string_equal(s->name, section)) {
                        for (GList *j = s->keys; j; j = g_list_next (j)) {
                                Key *key = (Key *) j->data;

                                if (string_equal(key->name, k) && string_equal(key->v, v))
                                        return true;
                        }
                }
        }

        return false;
}

char *key_file_config_get(const KeyFile *key_file, const char *section, const char *k) {
        GList *i;

        assert(k);

        assert(key_file);
        assert(section);
        assert(k);

        for (i = key_file->sections; i; i = g_list_next (i)) {
                Section *s = (Section *) i->data;

                if (string_equal(s->name, section)) {
                        for (GList *j = s->keys; j; j = g_list_next (j)) {
                                Key *key = (Key *) j->data;

                                if (string_equal(key->name, k))
                                        return key->v;
                        }
                }
        }

        return NULL;
}


int parse_config_file(const char *path, const char *section, const char *k, char **ret) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        gchar *s;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = parse_key_file(path, &key_file);
        if (r < 0)
                return r;

        r = key_file_parse_string(key_file, section, k, &s);
        if (r < 0)
                return r;

        *ret = g_strdup(s);
        if (!*ret)
                return -ENOMEM;

        return 0;
}

int parse_line(const char *line, char **key, char **value) {
        _auto_cleanup_ char *p = NULL, *s = NULL;

        assert(line);

        p = g_strdup(line);
        if (!p)
                return -ENOMEM;

        s = string_strip(p);
        if (!s)
                return -ENODATA;

        if (isempty_string(s) || *s == '#')
                return -ENODATA;

        return split_pair(s, "=", key, value);
}

int parse_config_file_integer(const char *path, const char *section, const char *k, unsigned *ret) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = parse_key_file(path, &key_file);
        if (r < 0)
                return r;

        return key_file_parse_integer(key_file, section, k, ret);
}

int parse_state_file(const char *path, const char *key, char **value, GHashTable **table) {
        _auto_cleanup_hash_ GHashTable *hash = NULL;
        _cleanup_(g_error_freep) GError *e = NULL;
        _auto_cleanup_strv_ char **lines = NULL;
        _auto_cleanup_ char *contents = NULL;
        char **l = NULL;
        char *p = NULL;
        size_t n;
        int r;

        assert(path);

        if (!g_file_test(path, G_FILE_TEST_EXISTS))
                return -ENOENT;

        if (!g_file_get_contents(path, &contents, &n , &e))
                return -e->code;

        hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        if (!hash)
                return log_oom();

        lines = strsplit(contents, "\n", 0);
        if (!lines)
                return log_oom();

        strv_foreach(l, lines) {
                _auto_cleanup_ char *t = NULL, *s = NULL, *k = NULL, *v = NULL;

                t = g_strdup(*l);
                if (!t)
                        return log_oom();

                s = string_strip(t);
                n = (int) strlen(s);
                if (n <= 0)
                        continue;

                r = parse_line(s, &k, &v);
                if (r >= 0) {
                        if (!g_hash_table_insert(hash, k, v))
                                continue;
                }

                steal_pointer(k);
                steal_pointer(v);
        }

        if (key && value) {
                p = g_hash_table_lookup(hash, key);
                if (p) {
                        *value = g_strdup(p);
                        if (!*value)
                                return log_oom();
                } else
                        return -ENOENT;
        }

        if (table)
                *table = steal_pointer(hash);

        return 0;
}

int parse_resolv_conf(char ***dns, char ***domains) {
        _auto_cleanup_strv_ char **lines = NULL, **a = NULL, **b = NULL;
        _auto_cleanup_ char *contents = NULL;
        char **l = NULL;
        GError *e = NULL;
        size_t n;
        int r;

        assert(dns);
        assert(domains);

        if (!g_file_test("/etc/resolv.conf", G_FILE_TEST_EXISTS)) {
                log_warning("Failed to open /etc/resolv.conf. File does not exists.");
                return -ENOENT;
        }

        if (!g_file_get_contents("/etc/resolv.conf", &contents, &n , &e)) {
                log_warning("Failed to read file %s: %s", "/etc/resolv.conf", e->message);
                return -e->code;
        }

        lines = strsplit(contents, "\n", 0);
        if (!lines)
                return log_oom();

        strv_foreach(l, lines) {
                _auto_cleanup_ char *t = NULL;

                t = g_strdup(*l);
                if (!t)
                        return log_oom();

                t = string_strip(t);
                n = (int) strlen(t);
                if (n <= 0)
                        continue;

                if (*t == '#' || *t == ';')
                        continue;

                if (string_has_prefix(t, "nameserver")) {
                        r = skip_first_word_and_split(t, "nameserver", " ", &a);
                        if (r < 0)
                                return r;
                }

                if (string_has_prefix(t, "domain")) {
                        r = skip_first_word_and_split(t, "domain", " ", &b);
                        if (r < 0)
                                return r;
                }
        }

        *dns = steal_pointer(a);
        *domains = steal_pointer(b);
        return 0;
}

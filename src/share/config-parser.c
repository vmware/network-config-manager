/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "config-parser.h"
#include "string-util.h"
#include "log.h"

int load_config_file(const char *path, GKeyFile **ret) {
        _cleanup_(key_file_freep) GKeyFile *key_file = NULL;
        GError *error = NULL;

        assert(path);
        assert(ret);

        if (!g_file_test(path, G_FILE_TEST_EXISTS)) {
                log_warning("Failed to open config file '%s'. \n Seems systemd-networkd state files and configuration "
                            "files are not in sync. \nPlease restart syetemd-networkd to apply the new configurations.", path);
                return -EEXIST;
        }

        key_file = g_key_file_new();
        if (!key_file)
                return -ENOMEM;

        if (!g_key_file_load_from_file(key_file, path, G_KEY_FILE_NONE, &error))
                return -ENODATA;

        *ret = steal_pointer(key_file);

        return 0;
}

int parse_config_file(const char *path, const char *section, const char *k, char **ret) {
        _cleanup_(key_file_freep) GKeyFile *key_file = NULL;
        gchar *s;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        s = g_key_file_get_string(key_file, section, k, NULL);
        if (!s)
                return -ENODATA;

        *ret = g_strdup(s);
        if (!*ret)
                return -ENOMEM;

        return 0;
}

int parse_config_file_integer(const char *path, const char *section, const char *k, unsigned *ret) {
        _cleanup_(key_file_freep) GKeyFile *key_file = NULL;
        GError *error = NULL;
        int r, v;

        assert(path);
        assert(section);
        assert(k);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        v = g_key_file_get_integer(key_file, section, k, &error);
        if (error)
                return -error->code;

        *ret = v;

        return 0;
}

int parse_line(const char *line, char **key, char **value) {
        _auto_cleanup_ char *p = NULL, *s = NULL;
        int r;

        assert(line);

        p = g_strdup(line);
        if (!p)
                return -ENOMEM;

        s = string_strip(p);
        if (!s)
                return -ENODATA;

        if (isempty_string(s) || *s == '#')
                return -ENODATA;

        r = split_pair(s, "=", key, value);
        if (r < 0)
                return r;

       return 0;
}

int parse_state_file(const char *path, const char *key, char **ret) {
        _auto_cleanup_hash_ GHashTable *hash = NULL;
        _auto_cleanup_ char *contents = NULL;
        _auto_cleanup_strv_ char **lines = NULL;
        GError *e = NULL;
        char **l = NULL;
        char *p = NULL;
        size_t n;
        int r;

        assert(path);
        assert(key);

        if (!g_file_test(path, G_FILE_TEST_EXISTS))
                return -EEXIST;

        if (!g_file_get_contents(path, &contents, &n , &e))
                return -ENODATA;

        hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        if (!hash)
                return log_oom();

        lines = strsplit(contents, "\n", 0);
        if (!lines)
                return log_oom();

        strv_foreach(l, lines) {
                _auto_cleanup_ char *t = NULL, *s = NULL;
                char *k = NULL, *v = NULL;

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
        }

        p = g_hash_table_lookup(hash, key);
        if (p) {
                *ret = g_strdup(p);
                if (!*ret)
                        return log_oom();

                p = NULL;
        } else
                return -ENOENT;

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
                return -EEXIST;
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

/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <glib.h>

#include "alloc-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "file-util.h"
#include <gio/gio.h>
#include "log.h"
#include "string-util.h"

int config_manager_new(const Config *configs, ConfigManager **ret) {
        _auto_cleanup_ ConfigManager *m = NULL;

        assert(configs);
        assert(ret);

        m = new0(ConfigManager, 1);
        if (!m)
                return log_oom();

        *m = (ConfigManager) {
               .ctl_to_config_table = g_hash_table_new(g_str_hash, g_str_equal),
        };
        if (!m->ctl_to_config_table)
                return log_oom();

        for (size_t i = 0; configs[i].ctl_name; i++) 
                g_hash_table_insert(m->ctl_to_config_table, (gpointer *) configs[i].ctl_name, (gpointer *) configs[i].config);

        *ret = steal_pointer(m);
        return 0;
}

void config_manager_unref(ConfigManager *m) {
        if (!m)
                return;

        g_hash_table_unref(m->ctl_to_config_table);
        free(m);
}

const char *ctl_to_config(const ConfigManager *m, const char *name) {
        assert(m);
        assert(name);

        return g_hash_table_lookup(m->ctl_to_config_table, name);
}

int set_config_file_string(const char *path, const char *section, const char *k, const char *v) {
        _cleanup_(key_file_freep) GKeyFile *key_file = NULL;
        _cleanup_(g_error_freep) GError *e = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        g_key_file_set_string(key_file, section, k, v);

        if (!g_key_file_save_to_file (key_file, path, &e))
                return -e->code;

        steal_pointer(e);
        return set_file_permisssion(path, "systemd-network");
}

int set_config_file_bool(const char *path, const char *section, const char *k, bool b) {
        _cleanup_(key_file_freep) GKeyFile *key_file = NULL;
        _cleanup_(g_error_freep) GError *e = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        g_key_file_set_boolean(key_file, section, k, b);

        if (!g_key_file_save_to_file (key_file, path, &e))
                return -e->code;

        return set_file_permisssion(path, "systemd-network");
}

int set_config_file_integer(const char *path, const char *section, const char *k, int v) {
        _cleanup_(key_file_freep) GKeyFile *key_file = NULL;
        _cleanup_(g_error_freep) GError *e = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        g_key_file_set_integer(key_file, section, k, v);

        if (!g_key_file_save_to_file (key_file, path, &e))
                return -e->code;

        return set_file_permisssion(path, "systemd-network");
}

int remove_key_from_config_file(const char *path, const char *section, const char *k) {
        _cleanup_(key_file_freep) GKeyFile *key_file = NULL;
        _cleanup_(g_error_freep) GError *e = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        if (!g_key_file_remove_key(key_file, section, k, &e))
                return -e->code;

        if (!g_key_file_save_to_file(key_file, path, &e))
                return -e->code;

        return set_file_permisssion(path, "systemd-network");
}

int remove_section_from_config_file(const char *path, const char *section) {
        _cleanup_(key_file_freep) GKeyFile *key_file = NULL;
        _cleanup_(g_error_freep) GError *e = NULL;
        int r;

        assert(path);
        assert(section);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        if (!g_key_file_remove_group(key_file, section, &e))
                return -e->code;

        if (!g_key_file_save_to_file(key_file, path, &e))
                return -e->code;

        return set_file_permisssion(path, "systemd-network");
}

int write_to_conf_file(const char *path, const GString *s) {
        _cleanup_(g_error_freep) GError *e = NULL;

        assert(path);
        assert(s);

        if (!g_file_set_contents(path, s->str, s->len, &e))
                return -e->code;

        steal_pointer(e);
        return set_file_permisssion(path, "systemd-network");
}

int append_to_conf_file(const char *path, const GString *s) {
        _cleanup_(g_object_unref) GFileOutputStream *stream = NULL;
        _cleanup_(g_error_freep) GError *e = NULL;
        _cleanup_(g_object_unref) GFile *f = NULL;
        ssize_t k;
        int r;

        assert(path);
        assert(s);

        f = g_file_new_for_path(path);

        stream = g_file_append_to(f, G_FILE_CREATE_NONE, NULL, &e);
        if(!stream)
                return -e->code;

        k = g_output_stream_write(G_OUTPUT_STREAM(stream), s->str, s->len, NULL, &e);
        if (k == 0)
                return -e->code;

        r = g_output_stream_close(G_OUTPUT_STREAM (stream), NULL, &e);
        if (r < 0)
                return -e->code;

        return 0;
}

int read_conf_file(const char *path, char **s) {
        _cleanup_(g_error_freep) GError *e = NULL;
        _auto_cleanup_ char *c = NULL;
        size_t sz;

        assert(path);
        assert(s);

        if (!g_file_get_contents(path, &c, &sz, &e))
                return -e->code;

        *s = steal_pointer(c);
        return 0;
}

int remove_config_files_glob(const char *path, const char *section, const char *k, const char *v) {
        _cleanup_(globfree) glob_t g = {};
        int r;

        assert(path);
        assert(section);
        assert(k);
        assert(v);

        r = glob_files(path, 0, &g);
        if (r != -ENOENT)
                return r;

        for (size_t i = 0; i < g.gl_pathc; i++) {
                _auto_cleanup_ char *s = NULL;

                r = parse_config_file(g.gl_pathv[i], section, k, &s);
                if (r < 0)
                        return r;

                if (string_equal(s, v))
                        unlink(g.gl_pathv[i]);

        }

        return 0;
}

int remove_config_files_section_glob(const char *path, const char *section, const char *k, const char *v) {
        _cleanup_(globfree) glob_t g = {};
        int r;

        assert(path);
        assert(section);
        assert(k);
        assert(v);

        r = glob_files(path, 0, &g);
        if (r != -ENOENT)
                return r;

        for (size_t i = 0; i < g.gl_pathc; i++) {
                _auto_cleanup_ char *s = NULL;

                r = parse_config_file(g.gl_pathv[i], section, k, &s);
                if (r < 0)
                        return r;

                if (string_equal(s, v))
                        (void) remove_key_from_config_file(g.gl_pathv[i], section, k);
       }

        return 0;
}

int write_to_resolv_conf_file(char **dns, char **domains) {
        _auto_cleanup_ char *p = NULL;
        GString *c = NULL;
        size_t len;
        char **l;

        c = g_string_new(NULL);
        if (!c)
                return log_oom();

        if (dns && g_strv_length(dns) > 0) {
                c = g_string_append(c, "nameserver ");

                strv_foreach(l, dns)
                        g_string_append_printf(c, " %s", *l);

                c = g_string_append(c, "\n");
        }

        if (domains && g_strv_length(domains) > 0) {
                c = g_string_append(c, "domain ");

                strv_foreach(l, domains)
                        g_string_append_printf(c, " %s", *l);

                c = g_string_append(c, "\n");
        }

        len = c->len;
        p = g_string_free(c, FALSE);

        g_file_set_contents("/etc/resolv.conf", p, len, NULL);
        return 0;
}

int write_to_proxy_conf_file(GHashTable *table) {
        _auto_cleanup_ char *p = NULL;
        GHashTableIter iter;
        GString *c = NULL;
        char *k, *v;
        size_t len;

        c = g_string_new(NULL);
        if (!c)
                return log_oom();

        g_hash_table_iter_init (&iter, table);
        for (;g_hash_table_iter_next (&iter, (gpointer *) &k, (gpointer *) &v);) {

                if (v) {
                        if (*v != '"')
                                g_string_append_printf(c, "%s=\"%s\"\n", k , v);
                        else
                                g_string_append_printf(c, "%s=%s\n", k , v);
                } else
                        g_string_append_printf(c, "%s=\n", k);
        }

        len = c->len;
        p = g_string_free(c, FALSE);

        g_file_set_contents("/etc/sysconfig/proxy", p, len, NULL);
        return 0;
}

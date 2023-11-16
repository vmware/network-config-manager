/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <glib.h>
#include <gio/gio.h>

#include "alloc-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "file-util.h"
#include "log.h"
#include "string-util.h"

int key_new(const char *key, const char *value, Key **ret) {
        Key *k = NULL;

        assert(key);

        k = new0(Key, 1);
        if (!k)
                return -ENOMEM;

        k->name = strdup(key);
        if (!k->name)
                return -ENOMEM;

        if (value) {
                k->v = strdup(value);
                if (!k->v)
                        return -ENOMEM;
        }

        *ret = steal_ptr(k);
        return 0;
}

void key_free(void *p) {
        Key *k = (Key *) p;

        if (!k)
                return;

        free(k->name);
        free(k->v);
        free(k);
}

int section_new(const char *name, Section **ret) {
        Section *s = NULL;

        assert(name);

        s = new0(Section, 1);
        if (!s)
                return -ENOMEM;

        s->name = strdup(name);
        if (!s->name)
                return -ENOMEM;

        *ret = steal_ptr(s);
        return 0;
}

void section_free(void *p) {
        Section *s = (Section *) p;

        if (!s)
                return;

        g_list_free_full(g_list_first(s->keys), key_free);
        free(s->name);
        free(s);
}

int key_file_new(const char *file_name, KeyFile **ret) {
        KeyFile *k = NULL;

        assert(file_name);

        k = new0(KeyFile, 1);
        if (!k)
                return -ENOMEM;

        k->name = strdup(file_name);
        if (!k->name)
                return -ENOMEM;

        *ret = steal_ptr(k);
        return 0;
}

void key_file_free(KeyFile *k) {
        if (!k)
                return;

        free(k->name);
        g_list_free_full(g_list_first(k->sections), section_free);
        free(k);
}

int key_file_save(KeyFile *key_file) {
        _cleanup_(g_string_unrefp) GString *config = NULL;

        assert(key_file);

        config = g_string_new(NULL);
        if (!config)
                return log_oom();

        for (GList *iter = key_file->sections; iter; iter = g_list_next (iter)) {
                Section *s = (Section *) iter->data;

                if (g_list_length(s->keys) <= 0)
                        continue;

                g_string_append_printf(config, "[%s]\n", s->name);
                for (GList *i = s->keys; i; i = g_list_next (i)) {
                        Key *key = (Key *) i->data;
                        _auto_cleanup_ char *v = NULL;

                        v = key->v ? strdup(key->v) : strdup("");
                        g_string_append_printf(config, "%s=%s\n", key->name, v);
                }

                g_string_append(config, "\n");
        }

        return write_to_conf_file(key_file->name, config);
}

int add_key_to_section(Section *s, const char *k, const char *v) {
        _cleanup_(key_freep) Key *key = NULL;
        int r;

        assert(s);
        assert(k);

        r = key_new(k, v, &key);
        if (r < 0)
                return r;

        s->keys = g_list_append(s->keys, key);
        steal_ptr(key);
        return 0;
}

int add_section_to_key_file(KeyFile *k, Section *s) {
       assert(k);
       assert(s);

       k->sections = g_list_append(k->sections, s);
       k->nsections++;
       return 0;
}

int add_key_to_section_int(Section *s, const char *k, int v) {
        _auto_cleanup_ gchar *c = NULL;

        assert(s);
        assert(k);

        c = g_strdup_printf("%i", v);
        if (!c)
                return -ENOMEM;

        return add_key_to_section(s, k, c);
}

int add_key_to_section_uint(Section *s, const char *k, uint v) {
        _auto_cleanup_ gchar *c = NULL;

        assert(s);
        assert(k);

        c = g_strdup_printf("%u", v);
        if (!c)
                return -ENOMEM;

        return add_key_to_section(s, k, c);
}


int config_manager_new(const Config *configs, ConfigManager **ret) {
        _auto_cleanup_ ConfigManager *m = NULL;

        assert(configs);
        assert(ret);

        m = new(ConfigManager, 1);
        if (!m)
                return log_oom();

        *m = (ConfigManager) {
                    .ctl_to_config_table = g_hash_table_new(g_str_hash, g_str_equal),
        };
        if (!m->ctl_to_config_table)
                return log_oom();

        for (size_t i = 0; configs[i].ctl_name; i++)
                g_hash_table_insert(m->ctl_to_config_table, (gpointer *) configs[i].ctl_name, (gpointer *) configs[i].config);

        *ret = steal_ptr(m);
        return 0;
}

void config_manager_free(ConfigManager *m) {
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

int set_config(KeyFile *key_file, const char *section, const char *k, const char *v) {
        _cleanup_(section_freep) Section *sec = NULL;
        int r;

        assert(key_file);
        assert(section);
        assert(k);

        for (GList *iter = key_file->sections; iter; iter = g_list_next (iter)) {
                Section *s = (Section *) iter->data;

                if (str_eq(s->name, section)) {
                        for (GList *i = s->keys; i; i = g_list_next (i)) {
                                Key *key = (Key *) i->data;

                                if (str_eq(key->name, k)) {
                                        free(key->v);
                                        if (v) {
                                                key->v = strdup(v);
                                                if (!key->v)
                                                        return -ENOMEM;
                                        }

                                        return 0;
                                }
                        }

                        /* key not found. Add key to section */
                        r = add_key_to_section(s, k, v);
                        if (r < 0)
                                return r;

                        return 0;
                }
        }

        /* section not found. create a new section and add the key */
        r = section_new(section, &sec);
        if (r < 0)
                return r;

        r = add_key_to_section(sec, k, v);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, sec);
        if (r < 0)
                return r;

        steal_ptr(sec);
        return 0;
}

int set_config_uint(KeyFile *key_file, const char *section, const char *k, uint v) {
        _auto_cleanup_ gchar *s = NULL;
        int r;

        s = g_strdup_printf("%i", v);
        if (!s)
                return -ENOMEM;

        r = key_file_set_str(key_file, section, k, s);
        if (r < 0)
                return r;

        return 0;
}

int set_config_file_str(const char *path, const char *section, const char *k, const char *v) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = parse_key_file(path, &key_file);
        if (r < 0)
                return r;

        r = set_config(key_file, section, k, v);
        if (r < 0)
                return r;

        r = key_file_save (key_file);
        if (r < 0)
                return r;

        return set_file_permisssion(path, "systemd-network");
}

int set_config_file_int(const char *path, const char *section, const char *k, unsigned v) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_ gchar *s = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = parse_key_file(path, &key_file);
        if (r < 0)
                return r;

        s = g_strdup_printf("%u", v);
        if (!s)
                return -ENOMEM;

        r = key_file_set_str(key_file, section, k, s);
        if (r < 0)
                return r;

        r = key_file_save (key_file);
        if (r < 0)
                return r;

        return set_file_permisssion(path, "systemd-network");
}

int set_config_file_bool(const char *path, const char *section, const char *k, bool b) {
        assert(path);
        assert(section);
        assert(k);

        return set_config_file_str(path, section, k, bool_to_str(b));
}

int key_file_set_str(KeyFile *key_file, const char *section, const char *k, const char *v) {
        assert(key_file);
        assert(section);
        assert(k);

        return set_config(key_file, section, k, v);
}

int key_file_set_bool(KeyFile *key_file, const char *section, const char *k, const bool b) {
        assert(key_file);
        assert(section);
        assert(k);

        return set_config(key_file, section, k, bool_to_str(b));
}


static int add_config(KeyFile *key_file, const char *section, const char *k, const char *v) {
        _cleanup_(section_freep) Section *sec = NULL;
        int r;

        assert(key_file);
        assert(section);
        assert(k);

        r = section_new(section, &sec);
        if (r < 0)
                return r;

        r = add_key_to_section(sec, k, v);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, sec);
        if (r < 0)
                return r;

        steal_ptr(sec);
        return 0;
}

int add_config_file_str(const char *path, const char *section, const char *k, const char *v) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = parse_key_file(path, &key_file);
        if (r < 0)
                return r;

        r = add_config(key_file, section, k, v);
        if (r < 0)
                return r;

        r = key_file_save (key_file);
        if (r < 0)
                return r;

        return set_file_permisssion(path, "systemd-network");
}

int add_key_to_section_str(const char *path, const char *section, const char *k, const char *v) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        bool b = false;
        int r;

        assert(path);
        assert(section);
        assert(k);
        assert(v);

        r = parse_key_file(path, &key_file);
        if (r < 0)
                return r;

        for (GList *iter = key_file->sections; iter; iter = g_list_next (iter)) {
                Section *s = (Section *) iter->data;

                if (str_eq(s->name, section)) {
                        r = add_key_to_section(s, k, v);
                        if (r < 0)
                                return r;

                        b = true;
                        break;
                }
        }

        /* section not found. create a new section and add the key */
        if (!b) {
                _cleanup_(section_freep) Section *sec = NULL;

                r = section_new(section, &sec);
                if (r < 0)
                        return r;

                r = add_key_to_section(sec, k, v);
                if (r < 0)
                        return r;

                r = add_section_to_key_file(key_file, sec);
                if (r < 0)
                        return r;

                steal_ptr(sec);
        }

        r = key_file_save (key_file);
        if (r < 0)
                return r;

        return set_file_permisssion(path, "systemd-network");
}

int key_file_add_str(KeyFile *key_file, const char *section, const char *k, const char *v) {
        assert(key_file);
        assert(section);
        assert(k);

        return add_config(key_file, section, k, v);
}

int key_file_parse_str(KeyFile *key_file, const char *section, const char *k, char **v) {
        assert(key_file);
        assert(section);
        assert(k);

        for (GList *iter = key_file->sections; iter; iter = g_list_next (iter)) {
                Section *s = (Section *) iter->data;

                if (str_eq(s->name, section)) {
                        for (GList *i = s->keys; i; i = g_list_next (i)) {
                                Key *key = (Key *) i->data;

                                if (str_eq(key->name, k)) {
                                        *v = strdup(key->v);
                                        if (!*v)
                                                return -ENOMEM;
                                        return 0;
                                }
                        }
                }
        }

        return -ENOENT;
}

int key_file_parse_int(KeyFile *key_file, const char *section, const char *k, unsigned *v) {
        _auto_cleanup_ char *value = NULL;
        int r;

        assert(key_file);
        assert(section);
        assert(k);

        r = key_file_parse_str(key_file, section, k, &value);
        if (r < 0)
                return r;

        *v = g_ascii_strtoll(value, NULL, 10);
        return 0;
}

int key_file_set_uint(KeyFile *key_file, const char *section, const char *k, uint v) {
        _auto_cleanup_ gchar *s = NULL;
        int r;

        assert(section);
        assert(k);

        s = g_strdup_printf("%u", v);
        if (!s)
                return -ENOMEM;

        r = key_file_set_str(key_file, section, k, s);
        if (r < 0)
                return r;

        return set_file_permisssion(key_file->name, "systemd-network");
}

int remove_key_from_config_file(const char *path, const char *section, const char *k) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_ (key_freep) Key *p = NULL;
        GList *l = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = parse_key_file(path, &key_file);
        if (r < 0)
                return r;

        for (GList *iter = key_file->sections; iter; iter = g_list_next (iter)) {
                Section *s = (Section *) iter->data;

                if (str_eq(s->name, section)) {
                        for (GList *i = s->keys; i; i = g_list_next (i)) {
                                Key *key = (Key *) i->data;

                                if (str_eq(key->name, k)) {
                                        l = g_list_remove_link(s->keys, i);
                                        break;
                                }

                        }
                }
        }

        if (l)
                p = (Key *) l->data;

        r = key_file_save (key_file);
        if (r < 0)
                return r;

        return set_file_permisssion(path, "systemd-network");
}

int remove_key_value_from_config_file(const char *path, const char *section, const char *k, const char *v) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        GList *l = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = parse_key_file(path, &key_file);
        if (r < 0)
                return r;

        for (GList *iter = key_file->sections; iter; iter = g_list_next (iter)) {
                Section *s = (Section *) iter->data;

                if (str_eq(s->name, section)) {
                        for (GList *i = s->keys; i; i = g_list_next (i)) {
                                Key *key = (Key *) i->data;

                                if (str_eq(key->name, k) && str_eq(key->v, v)) {
                                        l = g_list_remove_link(s->keys, g_list_nth(s->keys, g_list_position(s->keys, i)));
                                        break;
                                }

                        }
                }
        }

        (void) l;

        r = key_file_save (key_file);
        if (r < 0)
                return r;

        return set_file_permisssion(path, "systemd-network");
}

int remove_section_from_config_file(const char *path, const char *section) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_ (section_freep) Section *sec = NULL;
        GList *l = NULL;
        int r;

        assert(path);
        assert(section);

        r = parse_key_file(path, &key_file);
        if (r < 0)
                return r;

        for (GList *iter = key_file->sections; iter; iter = g_list_next (iter)) {
                Section *s = (Section *) iter->data;

                if (str_eq(s->name, section)) {
                        l = g_list_remove_link(key_file->sections, iter);
                        break;
                }

        }

        if (l)
                sec = (Section *) l->data;

        r = key_file_save (key_file);
        if (r < 0)
                return r;

        return set_file_permisssion(path, "systemd-network");
}

int remove_section_from_config_file_key(const char *path, const char *section, const char *k, const char *v) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        GList *l = NULL;
        int r;

        assert(path);
        assert(section);

        r = parse_key_file(path, &key_file);
        if (r < 0)
                return r;

        for (GList *iter = key_file->sections; iter; iter = g_list_next (iter)) {
                Section *s = (Section *) iter->data;

                if (str_eq(s->name, section)) {
                        for (GList *i = s->keys; i; i = g_list_next (i)) {
                                Key *key = (Key *) i->data;

                                if (str_eq(key->name, k) && str_eq(key->v, v)) {
                                        l = g_list_remove_link(key_file->sections, iter);
                                        (void) l;
                                        break;
                                }
                        }
                }
        }

        r = key_file_save (key_file);
        if (r < 0)
                return r;

        return set_file_permisssion(path, "systemd-network");
}

int write_to_conf_file(const char *path, const GString *s) {
        _cleanup_(g_error_freep) GError *e = NULL;

        assert(path);
        assert(s);

        if (!g_file_set_contents(path, s->str, s->len, &e))
                return -e->code;

        steal_ptr(e);
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

        *s = steal_ptr(c);
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

                if (str_eq(s, v))
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

        for (size_t i = 0; i < g.gl_pathc; i++)
                (void) remove_key_value_from_config_file(g.gl_pathv[i], section, k, v);

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

int determine_conf_file_name(const char *ifname, char **ret) {
        _auto_cleanup_ char *n = NULL, *file = NULL;

        assert(ifname);

        if (strstr(ifname, "*"))
                n = strdup("network-config-manager");
        else
                n = strdup(ifname);
        if (!n)
                return log_oom();

        file = strjoin("-", "10", n, NULL);
        if (!file)
                return log_oom();

        *ret = steal_ptr(file);
        return 0;

}

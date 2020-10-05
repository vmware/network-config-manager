/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <glib.h>

#include "alloc-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "file-util.h"
#include "log.h"
#include "string-util.h"

int set_config_file_string(const char *path, const char *section, const char *k, const char *v) {
        _cleanup_(key_file_free) GKeyFile *key_file = NULL;
        GError *e = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        g_key_file_set_string(key_file, section, k, v);

        if (!g_key_file_save_to_file (key_file, path, &e)) {
                log_warning("Failed to write to '%s': %s", path, e->message);
                return -e->code;
        }

        return set_file_permisssion(path, "systemd-network");
}

int set_config_file_bool(const char *path, const char *section, const char *k, bool b) {
        _cleanup_(key_file_free) GKeyFile *key_file = NULL;
        GError *e = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        g_key_file_set_boolean(key_file, section, k, b);

        if (!g_key_file_save_to_file (key_file, path, &e)) {
                log_warning("Failed to write to '%s': %s", path, e->message);
                return -e->code;
        }

         return set_file_permisssion(path, "systemd-network");
}

int set_config_file_integer(const char *path, const char *section, const char *k, int v) {
        _cleanup_(key_file_free) GKeyFile *key_file = NULL;
        GError *e = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        g_key_file_set_integer(key_file, section, k, v);

        if (!g_key_file_save_to_file (key_file, path, &e)) {
                log_warning("Failed to write to '%s': %s", path, e->message);
                return -e->code;
        }

         return set_file_permisssion(path, "systemd-network");
}

int remove_key_from_config(const char *path, const char *section, const char *k) {
        _cleanup_(key_file_free) GKeyFile *key_file = NULL;
        GError *e = NULL;
        int r;

        assert(path);
        assert(section);
        assert(k);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        if (!g_key_file_remove_key(key_file, section, k, &e)) {
                g_debug("Failed to remove key from '%s': section %s key %s", path, section, k);
                return -e->code;
        }

        if (!g_key_file_save_to_file(key_file, path, &e)) {
                g_debug("Failed to write to '%s': %s", path, e->message);
                return -e->code;
        }

        return set_file_permisssion(path, "systemd-network");
}

int remove_section_from_config(const char *path, const char *section) {
        _cleanup_(key_file_free) GKeyFile *key_file = NULL;
        GError *e = NULL;
        int r;

        assert(path);
        assert(section);

        r = load_config_file(path, &key_file);
        if (r < 0)
                return r;

        if (!g_key_file_remove_group(key_file, section, &e)) {
                g_debug("Failed to remove key from '%s': section %s", path, section);
                return -e->code;
        }

        if (!g_key_file_save_to_file(key_file, path, &e)) {
                log_warning("Failed to write to '%s': %s", path, e->message);
                return -e->code;
        }

        return set_file_permisssion(path, "systemd-network");
}

int write_to_resolv_conf(char **dns, char **domains) {
        _auto_cleanup_ char *p = NULL;
        GString* c = NULL;
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

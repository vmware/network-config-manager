/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <network-config-manager.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "arphrd-to-name.h"
#include "config-parser.h"
#include "ctl-display.h"
#include "ctl.h"
#include "log.h"
#include "macros.h"
#include "network-json.h"
#include "network-manager.h"
#include "network-util.h"
#include "parse-util.h"

_public_ int ncm_configure_proxy(int argc, char *argv[]) {
        _auto_cleanup_  char *http = NULL, *https = NULL, *ftp = NULL, *gopher = NULL, *socks = NULL, *socks5 = NULL, *no_proxy = NULL;
        int r, enable = -1;

        for (int i = 1; i < argc; i++) {
                if (string_equal(argv[i], "enable")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse enable '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        enable = r;
                        continue;
                } else if (string_equal(argv[i], "http") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                http = strdup("");
                        else
                                http = strdup(argv[i]);
                        if (!http)
                                return log_oom();

                        continue;
                } else if (string_equal(argv[i], "https") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                https = strdup("");
                        else
                                https = strdup(argv[i]);
                        if (!https)
                                return log_oom();

                        continue;
                } else if (string_equal(argv[i], "ftp") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                ftp = strdup("");
                        else
                                ftp = strdup(argv[i]);
                        if (!ftp)
                                return log_oom();

                        continue;
                } else if (string_equal(argv[i], "gopher") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                gopher = strdup("");
                        else
                                gopher = strdup(argv[i]);
                        if (!gopher)
                                return log_oom();

                        continue;
                } else if (string_equal(argv[i], "socks") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                socks = strdup("");
                        else
                                socks = strdup(argv[i]);
                        if (!socks)
                                return log_oom();

                        continue;
                } else if (string_equal(argv[i], "socks5") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                socks5 = strdup("");
                        else
                                socks5 = strdup(argv[i]);
                        if (!socks5)
                                return log_oom();

                        continue;
                } else if (string_equal(argv[i], "noproxy") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                no_proxy = strdup("");
                        else
                                no_proxy = strdup(argv[i]);
                        if (!no_proxy)
                                return log_oom();

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], g_strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = manager_configure_proxy(enable, http, https, ftp, gopher, socks, socks5, no_proxy);
        if (r < 0) {
                log_warning("Failed to configure proxy settings: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_show_proxy(int argc, char *argv[]) {
        _auto_cleanup_hash_ GHashTable *table = NULL;
        char *v;
        int r;

        r = manager_parse_proxy_config(&table);
        if (r < 0) {
                log_warning("Failed to parse proxy settings: %s", g_strerror(-r));
                return r;
        }

        printf("Proxy Settings\n");

        v = g_hash_table_lookup(table, "PROXY_ENABLED");
        if(v)
                printf("      Enabled: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "HTTP_PROXY");
        if(v)
                printf("         HTTP: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "HTTPS_PROXY");
        if(v)
                printf("        HTTPS: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "FTP_PROXY");
        if(v)
                printf("          FTP: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "GOPHER_PROXY");
        if(v)
                printf("       Gopher: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "SOCKS_PROXY");
        if(v)
                printf("        Socks: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "SOCKS5_SERVER");
        if(v)
                printf("Socks5 Server: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "NO_PROXY");
        if(v)
                printf("     No Proxy: %s\n", (char *) v);

        return 0;
}

_public_ int ncm_get_proxy(char ***proxy) {
        _auto_cleanup_hash_ GHashTable *table = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        char *k = NULL, *v = NULL;
        GHashTableIter iter;
        int r;

        assert(proxy);

        r = manager_parse_proxy_config(&table);
        if (r < 0)
                return r;

        g_hash_table_iter_init (&iter, table);
        for (;g_hash_table_iter_next (&iter, (gpointer *) &k, (gpointer *) &v);) {
                _auto_cleanup_ char *p = NULL;

                p = string_join(":", k, v, NULL);
                if (!p)
                        return log_oom();

                if (!s) {
                        s = strv_new(p);
                        if (!s)
                                return log_oom();
                } else {
                        r = strv_add(&s, p);
                        if (r < 0)
                                return r;
                }

                steal_pointer(p);
        }

        *proxy = steal_pointer(s);
        return 0;
}

/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <network-config-manager.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "config-parser.h"
#include "log.h"
#include "macros.h"
#include "network-util.h"
#include "nftables.h"
#include "parse-util.h"

_public_ int ncm_nft_add_tables(int argc, char *argv[]) {
        int r, f;

        r = nft_family_name_to_type(argv[1]);
        if (r < 0) {
                log_warning("Failed to parse family type %s : %s", argv[1], g_strerror(-r));
                return r;
        }

        f = r;
        r = nft_add_table(f, argv[2]);
        if (r < 0) {
                log_warning("Failed to add table  %s : %s", argv[2], g_strerror(-r));
                return r;
        }

        return r;
}

_public_ int ncm_nft_show_tables(int argc, char *argv[]) {
        _cleanup_(g_ptr_array_unrefp) GPtrArray *s = NULL;
        int r, f = AF_UNSPEC;
        guint i;

        if (argc > 1) {
                r = nft_family_name_to_type(argv[1]);
                if (r < 0) {
                        log_warning("Failed to parse family type %s : %s", argv[1], g_strerror(-r));
                        return r;
                }
        }

        f = r;
        if (argc <= 2) {
                r = nft_get_tables(f, NULL, &s);
                if (r < 0) {
                        log_warning("Failed to get table %s : %s", argv[1] ? argv[1] : "", g_strerror(-r));
                        return r;
                }

                printf("Family   Tables\n");
                for (i = 0; i < s->len; i++) {
                        NFTNLTable *t = g_ptr_array_index(s, i);

                        printf("%s%-5s : %-3s %s\n", ansi_color_blue(), nft_family_to_name(t->family), ansi_color_reset(), t->name);
                }
        } else {
                _cleanup_(g_string_unrefp) GString *rl = NULL;

                r = nft_get_rules(argv[2], &rl);
                if (r < 0) {
                        log_warning("Failed to get rules for table '%s': %s", argv[1], g_strerror(-r));
                        return r;
                }
                if (!rl)
                        return r;

                printf("Table :  %s\n", argv[2]);
                g_print("%s", rl->str);
        }

        return 0;
}

_public_ int ncm_nft_get_tables(const char *family, const char *table, char ***ret) {
        _cleanup_(g_ptr_array_unrefp) GPtrArray *s = NULL;
        _auto_cleanup_strv_ char **p = NULL;
        int r, f = AF_UNSPEC;

        if (family) {
                r = nft_family_name_to_type(family);
                if (r < 0)
                        return r;;
        }

        f = r;
        r = nft_get_tables(f, table, &s);
        if (r < 0)
                return r;

        for (guint i = 0; i < s->len; i++) {
                _cleanup_(g_string_unrefp) GString *v = NULL;
                NFTNLTable *t = g_ptr_array_index(s, i);
                _auto_cleanup_ char *a = NULL;

                v = g_string_new(nft_family_to_name(t->family));
                if (!v)
                        return -ENOMEM;

                g_string_append_printf(v, ":%s", t->name);

                a = strdup(v->str);
                if (!a)
                        return -ENOMEM;

                if (!p) {
                        p = strv_new(a);
                        if (!p)
                                return -ENOMEM;

                } else {
                        r = strv_add(&p, a);
                        if (r < 0)
                                return r;
                }

                steal_pointer(a);
        }

        *ret = steal_pointer(p);
        return 0;
}

_public_ int ncm_nft_delete_table(int argc, char *argv[]) {
        int r, f;

        r = nft_family_name_to_type(argv[1]);
        if (r < 0) {
                log_warning("Failed to parse family type %s : %s", argv[1], g_strerror(-r));
                return r;
        }

        f = r;
        r = nft_delete_table(f, argv[2]);
        if (r < 0) {
                log_warning("Failed to delete table  %s : %s", argv[2], g_strerror(-r));
                return r;
        }

        return r;
}
_public_ int ncm_nft_add_chain(int argc, char *argv[]) {
        int r, f;

        r = nft_family_name_to_type(argv[1]);
        if (r < 0) {
                log_warning("Failed to parse family type %s : %s", argv[1], g_strerror(-r));
                return r;
        }

        f = r;
        r = nft_add_chain(f, argv[2], argv[3]);
        if (r < 0) {
                log_warning("Failed to add chain  %s : %s", argv[3], g_strerror(-r));
                return r;
        }

        return r;
}

_public_ int ncm_nft_show_chains(int argc, char *argv[]) {
        _cleanup_(g_ptr_array_unrefp) GPtrArray *s = NULL;
        int r, f = AF_UNSPEC;
        guint i;

        if (argc > 1) {
                r = nft_family_name_to_type(argv[1]);
                if (r < 0) {
                        log_warning("Failed to parse family type %s : %s", argv[1], g_strerror(-r));
                        return r;
                }
        }

        f = r;
        r = nft_get_chains(f, argc > 3 ? argv[2] : NULL, argc > 3 ? argv[3] : NULL, &s);
        if (r < 0) {
                log_warning("Failed to get chains %s : %s", argv[2] ? argv[2] : "", g_strerror(-r));
                return r;
        }

        printf("Family  Tables   Chains\n");
        for (i = 0; i < s->len; i++) {
                NFTNLChain *c = g_ptr_array_index(s, i);

                printf("%s%-5s : %s%-8s %-8s\n", ansi_color_blue(), nft_family_to_name(c->family), ansi_color_reset(), c->table, c->name);
        }

        return 0;
}

_public_ int ncm_nft_delete_chain(int argc, char *argv[]) {
        int r, f;

        r = nft_family_name_to_type(argv[1]);
        if (r < 0) {
                log_warning("Failed to parse family type %s : %s", argv[1], g_strerror(-r));
                return r;
        }

        f = r;
        r = nft_delete_chain(f, argv[2], argv[3]);
        if (r < 0) {
                log_warning("Failed to add chain  %s : %s", argv[3], g_strerror(-r));
                return r;

        }

        return r;
}

_public_ int ncm_nft_get_chains(char *family, const char *table, const char *chain, char ***ret) {
        _cleanup_(g_ptr_array_unrefp) GPtrArray *s = NULL;
        _auto_cleanup_strv_ char **p = NULL;
        int r, f = AF_UNSPEC;

        if (family) {
                r = nft_family_name_to_type(family);
                if (r < 0)
                        return r;
        }

        f = r;
        r = nft_get_chains(f, table, chain, &s);
        if (r < 0)
                return r;

        for (guint i = 0; i < s->len; i++) {
                _cleanup_(g_string_unrefp) GString *v = NULL;
                NFTNLChain *c= g_ptr_array_index(s, i);
                _auto_cleanup_ char *a = NULL;

                v = g_string_new(nft_family_to_name(c->family));
                if (!v)
                        return -ENOMEM;

                g_string_append_printf(v, ":%s:%s", c->table, c->name);

                a = strdup(v->str);
                if (!a)
                        return -ENOMEM;

                if (!p) {
                        p = strv_new(a);
                        if (!p)
                                return -ENOMEM;

                } else {
                        r = strv_add(&p, a);
                        if (r < 0)
                                return r;
                }

                steal_pointer(a);
        }

        *ret = steal_pointer(p);
        return 0;
}

_public_ int ncm_nft_add_rule_port(int argc, char *argv[]) {
        IPPacketProtocol protocol;
        IPPacketPort port_type;
        NFPacketAction action;
        uint16_t port;
        int r, f;

        r = nft_family_name_to_type(argv[1]);
        if (r < 0 || r == NF_PROTO_FAMILY_IPV6) {
                log_warning("Unsupproted family type %s : %s", argv[1], g_strerror(-r));
                return r;
        }

        f = r;
        protocol = ip_packet_protcol_name_to_type(argv[4]);
        if (protocol < 0) {
                log_warning("Failed to parse protocol %s : %s", argv[4], g_strerror(-r));
                return r;
        }

        port_type = ip_packet_port_name_to_type(argv[5]);
        if (port_type < 0) {
                log_warning("Failed to parse IP protocol %s : %s", argv[5], g_strerror(-r));
                return r;
        }

        r = parse_uint16(argv[6], &port);
        if (r < 0) {
                log_warning("Failed to parse port %s : %s", argv[5], g_strerror(r));
                return r;
        }

        action = nft_packet_action_name_to_type(argv[7]);
        if (action < 0) {
                log_warning("Failed to parse action %s : %s", argv[6], g_strerror(r));
                return r;
        }

        r = nft_configure_rule_port(f, argv[2], argv[3], protocol,  port_type , port, action);
        if (r < 0) {
                log_warning("Failed to add rule for %s port %s : %s", argv[4], argv[3], g_strerror(-r));
                return r;
        }

        return r;
}

_public_ int ncm_nft_show_rules(int argc, char *argv[]) {
        _cleanup_(g_string_unrefp) GString *s = NULL;
        int r;

        r = nft_get_rules(argv[1], &s);
        if (r < 0) {
                log_warning("Failed to get rules for table '%s': %s", argv[1], g_strerror(-r));
                return r;
        }
        if (!s)
                return r;

        g_print("%s", s->str);
        return 0;
}

_public_ int ncm_get_nft_rules(const char *table, char **ret) {
        _cleanup_(g_string_unrefp) GString *s = NULL;
        int r;

        assert(table);

        r = nft_get_rules(table, &s);
        if (r < 0) {
                log_warning("Failed to get rules %s : %s", table, g_strerror(-r));
                return r;
        }
        if (!s)
                return r;

        *ret = strdup(s->str);
        if (!*ret)
                return -ENOMEM;

        return 0;
}

_public_ int ncm_nft_delete_rule(int argc, char *argv[]) {
        int r, f, h = 0;

        r = nft_family_name_to_type(argv[1]);
        if (r < 0) {
                log_warning("Failed to parse family type %s : %s", argv[1], g_strerror(-r));
                return r;
        }

        f = r;
        if (argc > 4) {
                r = parse_integer(argv[4], &h);
                if (r < 0) {
                        log_warning("Failed to parse handle %s : %s", argv[4], g_strerror(-r));
                        return r;
                }
        }

        r = nft_delete_rule(f, argv[2], argv[3], h);
        if (r < 0) {
                log_warning("Failed to delete rule family=%s table=%s chain=%s : %s", argv[1], argv[2], argv[3], g_strerror(-r));
                return r;
        }

        return r;
}

_public_ int ncm_nft_run_command(int argc, char *argv[]) {
        _cleanup_(g_string_unrefp) GString *s = NULL;
        _auto_cleanup_strv_ char **c = NULL;
        int r;

        r = argv_to_strv(argc - 1, argv + 1, &c);
        if (r < 0) {
                log_warning("Failed to parse nft command: %s", g_strerror(-r));
                return r;
        }

        r = nft_run_command(c, &s);
        if (r < 0) {
                log_warning("Failed run command: %s", g_strerror(-r));
                return r;

        }

        g_print("%s", s->str);
        return r;
}

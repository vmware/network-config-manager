/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <grp.h>
#include <pwd.h>
#include <network-config-manager.h>
#include <network-config-manager.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "arphrd-to-name.h"
#include "config-parser.h"
#include "dbus.h"
#include "dns.h"
#include "log.h"
#include "macros.h"
#include "network-address.h"
#include "network-link.h"
#include "network-manager.h"
#include "netdev-manager.h"
#include "network-util.h"
#include "parse-util.h"

_public_ int ncm_create_bridge(int argc, char *argv[]) {
        _auto_cleanup_strv_ char **devs = NULL;
        char **s;
        int r;

       for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "dev") || string_equal_fold(argv[i], "device") || string_equal_fold(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = argv_to_strv(argc - i, argv + i, &devs);
                        if (r < 0) {
                                log_warning("Failed to parse devices: %s", strerror(-r));
                                return r;
                        }
                }
        }

       if (strv_length(devs) <= 0) {
               log_warning("Failed to parse devices: %s", strerror(-r));
               return r;
       }

        strv_foreach(s, devs) {
                _auto_cleanup_ IfNameIndex *p = NULL;

                r = parse_ifname_or_index(*s, &p);
                if (r < 0) {
                        log_warning("Failed to find device '%s': %s", *s, strerror(-r));
                        return r;
                }
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return r;
        }

        r = manager_create_bridge(argv[1], devs);
        if (r < 0) {
                log_warning("Failed to create bridge '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_bond(int argc, char *argv[]) {
        _auto_cleanup_strv_ char **devs = NULL;
        _cleanup_(bond_unrefp) Bond *b = NULL;
        char **s;
        int r;

        r = bond_new(&b);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "mode") || string_equal_fold(argv[i], "m")) {
                        parse_next_arg(argv, argc, i);

                        r = bond_name_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse bond mode '%s' : %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        b->mode = r;
                } if (string_equal_fold(argv[i], "xmit-hash-policy") || string_equal_fold(argv[i], "xhp")) {
                        parse_next_arg(argv, argc, i);

                        r = bond_xmit_hash_policy_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse bond xmit hash policy '%s' : %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        b->xmit_hash_policy = r;
                } else if (string_equal_fold(argv[i], "dev") || string_equal_fold(argv[i], "device") || string_equal_fold(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = argv_to_strv(argc - i, argv + i, &devs);
                        if (r < 0) {
                                log_warning("Failed to parse devices: %s", strerror(-r));
                                return r;
                        }
                }
        }

        if (strv_length(devs) <= 0) {
               log_warning("Failed to parse devices: %s", strerror(EINVAL));
               return r;
       }

        strv_foreach(s, devs) {
                _auto_cleanup_ IfNameIndex *p = NULL;

                r = parse_ifname_or_index(*s, &p);
                if (r < 0) {
                        log_warning("Failed to find device '%s': %s", *s, strerror(-r));
                        return r;
                }
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return r;
        }

        r = manager_create_bond(argv[1], b, devs);
        if (r < 0) {
                log_warning("Failed to create bond '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_macvlan(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool have_mode = false;
        MACVLanMode mode;
        int r;

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "dev") || string_equal_fold(argv[i], "device") || string_equal_fold(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (string_equal_fold(argv[i], "mode")) {
                        parse_next_arg(argv, argc, i);

                        r = macvlan_name_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse MacVLan/MacVTap mode '%s' : %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        have_mode = true;
                        mode = r;

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_mode) {
                log_warning("Missing MacVLan/MacVTap mode: %s", strerror(EINVAL));
                return -EINVAL;
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return r;
        }

        if (string_equal_fold(argv[0], "create-macvlan"))
                r = manager_create_macvlan(argv[1], p->ifname, mode, true);
        else
                r = manager_create_macvlan(argv[1], p->ifname, mode, false);

        if (r < 0) {
                log_warning("Failed to %s '%s': %s", argv[0], argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_ipvlan(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool have_mode = false;
        IPVLanMode mode;
        int r;

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "dev") || string_equal_fold(argv[i], "device") || string_equal_fold(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (string_equal_fold(argv[i], "mode")) {
                        parse_next_arg(argv, argc, i);

                        r = ipvlan_name_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse IPVLan/IPVTap mode '%s' : %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        have_mode = true;
                        mode = r;

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_mode) {
                log_warning("Missing IPVLan/IPVTap mode: %s", strerror(EINVAL));
                return -EINVAL;
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return r;
        }

        if (string_equal_fold(argv[0], "create-ipvlan"))
                r = manager_create_ipvlan(argv[1], p->ifname, mode, true);
        else
                r = manager_create_ipvlan(argv[1], p->ifname, mode, false);

        if (r < 0) {
                log_warning("Failed to %s '%s': %s", argv[0], argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_vxlan(int argc, char *argv[]) {
        _cleanup_(vxlan_unrefp) VxLan *v = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool have_vni = false;
        int r;

        r = vxlan_new(&v);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "dev") || string_equal_fold(argv[i], "device") || string_equal_fold(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (string_equal_fold(argv[i], "vni")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v->vni);
                        if (r < 0) {
                                log_warning("Failed to parse vni %s: %s", argv[i], strerror(-r));
                                return r;
                        }

                        have_vni = true;
                        continue;
                } else if (string_equal_fold(argv[i], "local")) {
                       _auto_cleanup_ IPAddress *ip = NULL;

                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &ip);
                        if (r < 0) {
                                log_warning("Failed to parse local address : %s", argv[i]);
                                return r;
                        }
                        v->local = *ip;
                        continue;
                } else if (string_equal_fold(argv[i], "remote")) {
                       _auto_cleanup_ IPAddress *ip = NULL;

                       parse_next_arg(argv, argc, i);

                       r = parse_ip_from_string(argv[i], &ip);
                       if (r < 0) {
                               log_warning("Failed to parse remote address : %s", argv[i]);
                               return r;
                       }
                       v->remote = *ip;
                       continue;
                } else if (string_equal_fold(argv[i], "group")) {
                       _auto_cleanup_ IPAddress *ip = NULL;

                       parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &ip);
                        if (r < 0) {
                                log_warning("Failed to parse greoup address : %s", argv[i]);
                                return r;
                        }
                        v->group = *ip;
                        continue;
                } else if (string_equal_fold(argv[i], "independent")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse independent %s : %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        v->independent = r;
                        continue;
                } else if (string_equal_fold(argv[i], "dport")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint16(argv[i], &v->destination_port);
                        if (r < 0) {
                                log_warning("Failed to parse port %s: %s", argv[i], strerror(-r));
                                return r;
                        }
                        continue;
                } else {

                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!have_vni) {
                log_warning("Missing VxLan vni: %s", strerror(EINVAL));
                return -EINVAL;
        }

        if (!v->independent && !p) {
                log_warning("Missing device: %s", strerror(EINVAL));
                return -EINVAL;
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return r;
        }

        r = manager_create_vxlan(argv[1], p ? p->ifname : NULL, v);
        if (r < 0) {
                log_warning("Failed to create vxlan '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_vlan(int argc, char *argv[]) {
        bool have_id = false, have_dev = false;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _cleanup_(vlan_unrefp) VLan *v = NULL;
        int r = 0;

        r = vlan_new(&v);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "dev") || string_equal_fold(argv[i], "device") || string_equal_fold(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device '%s': %s", argv[i], strerror(-r));
                                return -errno;
                        }
                        have_dev = true;
                        continue;
                } else if (string_equal_fold(argv[i], "id")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v->id);
                        if (r < 0) {
                                log_warning("Failed to parse VLan id '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        have_id = true;
                        continue;
                } else if (string_equal_fold(argv[i], "proto") || string_equal_fold(argv[i], "protocol")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal_fold(argv[i], "802.1q") || string_equal_fold(argv[i], "802.1ad")) {
                                v->proto = strdup(argv[i]);
                                if (!v->proto)
                                        return log_oom();
                        } else {
                                log_warning("Failed to parse VLan proto '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (string_equal_fold(argv[i], "gvrp")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse gvrp '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        v->gvrp = r;
                        continue;

                } else if (string_equal_fold(argv[i], "mvrp")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse mvrp '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        v->mvrp = r;
                        continue;

                } else if (string_equal_fold(argv[i], "loose-binding")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse loose-binding '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        v->loose_binding = r;
                        continue;

                } else if (string_equal_fold(argv[i], "reorder-hdr")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse reorder_hdr '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        v->reorder_header = r;
                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }
        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_id) {
                log_warning("Missing VLan id: %s", strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_dev) {
                log_warning("Missing device: %s", strerror(EINVAL));
                return -EINVAL;
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return r;
        }

        r = manager_create_vlan(p, argv[1], v);
        if (r < 0) {
                log_warning("Failed to create vlan '%s': %s", argv[2], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_veth(int argc, char *argv[]) {
        _auto_cleanup_ char *peer = NULL;
        int r;

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "peer")) {
                        parse_next_arg(argv, argc, i);

                         if (!valid_ifname(argv[i])) {
                                 log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                                 return -EINVAL;
                         }

                         peer = strdup(argv[i]);
                         if (!peer)
                                 return log_oom();
                }
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_create_veth(argv[1], peer);
        if (r < 0) {
                log_warning("Failed to create veth '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_vrf(int argc, char *argv[]) {
        bool have_table = false;
        uint32_t table;
        int r;

        for (int i = 1; i < argc; i++) {
                if (string_equal_fold(argv[i], "table") || string_equal_fold(argv[i], "t")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[3], &table);
                        if (r < 0) {
                                log_warning("Failed to parse table id='%s' for '%s': %s", argv[i], argv[1], strerror(-r));
                                return r;
                        }
                        have_table = true;
                }
        }

        if (!have_table) {
                log_warning("Missing table id: %s", strerror(EINVAL));
                return -EINVAL;
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return r;
        }

        r = manager_create_vrf(argv[1], table);
        if (r < 0) {
                log_warning("Failed to create vrf '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_tunnel(int argc, char *argv[]) {
        _cleanup_(tunnel_unrefp) Tunnel *t = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        NetDevKind kind;
        char *c;
        int r;

        c = strchr(argv[0], '-');
        kind = netdev_name_to_kind(++c);
        if (kind < 0) {
                log_warning("Failed to find tunnel kind '%s': %s", c, strerror(EINVAL));
                return -EINVAL;
        }

        r = tunnel_new(&t);
        if (r < 0)
                return r;

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "dev") || string_equal_fold(argv[i], "device") || string_equal_fold(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device '%s': %s", argv[i], strerror(-r));
                                return -errno;
                        }
                        continue;
                } else if (string_equal_fold(argv[i], "local")) {
                        _auto_cleanup_ IPAddress *a = NULL;

                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &a);
                        if (r < 0) {
                                log_warning("Failed to parse local address : %s", argv[i]);
                                return r;
                        }
                        t->local = *a;
                        continue;
                } else if (string_equal_fold(argv[i], "remote")) {
                        _auto_cleanup_ IPAddress *a = NULL;

                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &a);
                        if (r < 0) {
                                log_warning("Failed to parse remote address : %s", argv[i]);
                                return r;
                        }
                        t->remote = *a;
                        continue;
                } else if (string_equal_fold(argv[i], "independent")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse independent %s : %s", argv[i], strerror(EINVAL));
                                return r;
                        }
                        t->independent = r;
                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!p && !t->independent) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return r;
        }

        r = manager_create_tunnel(argv[1], kind, p ? p->ifname : NULL, t);
        if (r < 0) {
                log_warning("Failed to create tunnel '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_wireguard_tunnel(int argc, char *argv[]) {
        _cleanup_(wireguard_unrefp) WireGuard *wg = NULL;
        int r;

        r = wireguard_new(&wg);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "private-key")) {
                        parse_next_arg(argv, argc, i);

                        wg->private_key = strdup(argv[i]);
                        if (!wg->private_key)
                                return log_oom();

                } else if (string_equal_fold(argv[i], "private-key-file")) {
                        parse_next_arg(argv, argc, i);

                        wg->private_key_file = strdup(argv[i]);
                        if (!wg->private_key_file)
                                return log_oom();

                        continue;

                } else if (string_equal_fold(argv[i], "public-key")) {
                        parse_next_arg(argv, argc, i);

                        wg->public_key = strdup(argv[i]);
                        if (!wg->public_key)
                                return log_oom();

                } else if (string_equal_fold(argv[i], "preshared-key")) {
                        parse_next_arg(argv, argc, i);

                        wg->preshared_key= strdup(argv[i]);
                        if (!wg->preshared_key)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "preshared-key-file")) {
                        parse_next_arg(argv, argc, i);

                        wg->preshared_key_file = strdup(argv[i]);
                        if (!wg->preshared_key_file)
                                return log_oom();
                        continue;
                } else if (string_equal_fold(argv[i], "allowed-ips")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse allowed ips '%s': %s", argv[i], strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        _auto_cleanup_ IPAddress *address = NULL;

                                        r = parse_ip_from_string(*d, &address);
                                        if (r < 0) {
                                                log_warning("Failed to parse allowed ips '%s': %s", argv[i], strerror(EINVAL));
                                                return -EINVAL;
                                        }
                                }
                        } else {
                                _auto_cleanup_ IPAddress *address = NULL;

                                r = parse_ip_from_string(argv[i], &address);
                                if (r < 0) {
                                        log_warning("Failed to parse allowed ips '%s': %s", argv[i], strerror(EINVAL));
                                        return -EINVAL;
                                }
                        }

                        wg->allowed_ips = strdup(argv[i]);
                        if (!wg->allowed_ips)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "endpoint")) {
                        _auto_cleanup_ IPAddress *address = NULL;
                        uint16_t port;

                        parse_next_arg(argv, argc, i);

                        r = parse_ip_port(argv[i], &address, &port);
                        if (r < 0) {
                                log_warning("Failed to parse endpoint '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        wg->endpoint = strdup(argv[i]);
                        if (!wg->endpoint)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "listen-port")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint16(argv[i], &wg->listen_port);
                        if (r < 0) {
                                log_warning("Failed to parse listen port '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return r;
        }

        r = manager_create_wireguard(argv[1], wg);
        if (r < 0) {
                log_warning("Failed to create wireguard tunnel '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_tun_tap(int argc, char *argv[]) {
        _cleanup_(tuntap_unrefp) TunTap *t = NULL;
        int r;

        r = tuntap_new(&t);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "user") || string_equal_fold(argv[i], "usr")) {
                        struct passwd *pw;

                        parse_next_arg(argv, argc, i);

                        pw = getpwnam(argv[i]);
                        if (!pw) {
                                log_warning("Failed to find user '%s': %s", argv[i], strerror(-ENOENT));
                                return -ENOENT;
                        }
                        t->user = strdup(argv[i]);
                        if (!t->user)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "group") || string_equal_fold(argv[i], "grp")) {
                        struct group *g;
                        parse_next_arg(argv, argc, i);

                        g = getgrnam(argv[i]);
                        if (!g) {
                                log_warning("Failed to find group '%s': %s", argv[i], strerror(-ENOENT));
                                return -ENOENT;
                        }

                        t->group = strdup(argv[i]);
                        if (!t->group)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "mq")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse multi queue %s: %s", argv[i], strerror(-r));
                                return r;
                        }

                        t->multi_queue = r;
                        continue;
                } else if (string_equal_fold(argv[i], "pkt-info")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse packet info %s: %s", argv[i], strerror(-r));
                                return r;
                        }

                        t->packet_info = r;
                        continue;
                } else if (string_equal_fold(argv[i], "kc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse keep carrier %s: %s", argv[i], strerror(-r));
                                return r;
                        }

                        t->keep_carrier = r;
                        continue;
              } else if (string_equal_fold(argv[i], "vnet-hdr")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse vnet header %s: %s", argv[i], strerror(-r));
                                return r;
                        }

                        t->vnet_hdr = r;
                        continue;

                } else {

                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!valid_ifname(argv[1])) {
                log_warning("Invalid ifname %s': %s", argv[1], strerror(EINVAL));
                return r;
        }

        r = manager_create_tun_tap(argv[1], string_equal(argv[0], "create-tun") ? NETDEV_KIND_TUN: NETDEV_KIND_TAP, t);
        if (r < 0) {
                log_warning("Failed to create tun tap='%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_remove_netdev(int argc, char *argv[]) {
        _cleanup_(config_manager_unrefp) ConfigManager *m = NULL;
        _auto_cleanup_ char *kind = NULL;
        int r;

        r = netdev_ctl_name_to_configs_new(&m);
        if (r < 0) {
                log_warning("Failed to remove netdev '%s': %s", argv[1], strerror(-r));
                return r;
        }
        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "kind") || string_equal_fold(argv[i], "k")) {
                        parse_next_arg(argv, argc, i);

                        if (!ctl_to_config(m, argv[i])) {
                                log_warning("Failed to find kind '%s': %s", argv[i], strerror(EINVAL));
                                continue;
                        }

                        kind = strdup(argv[i]);
                        if (!kind)
                                return log_oom();
                }
        }

        r = manager_remove_netdev(argv[1], kind ? ctl_to_config(m, kind) : NULL);
        if (r < 0) {
                log_warning("Failed to remove netdev '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

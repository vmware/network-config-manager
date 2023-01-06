/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <net/if.h>
#include <linux/if.h>
#include <net/ethernet.h>

#include "alloc-util.h"
#include "config-parser.h"
#include "dracut-parser.h"
#include "log.h"
#include "parse-util.h"
#include "network.h"
#include "string-util.h"

static const char *const dracut_dhcp_mode_table[_DRACUT_DHCP_MODE_MAX] = {
        [DRACUT_DHCP_MODE_NONE]    = "none",
        [DRACUT_DHCP_MODE_OFF]     = "off",
        [DRACUT_DHCP_MODE_ON]      = "on",
        [DRACUT_DHCP_MODE_ANY]     = "any",
        [DRACUT_DHCP_MODE_DHCP]    = "dhcp",
        [DRACUT_DHCP_MODE_DHCP6]   = "dhcp6",
        [DRACUT_DHCP_MODE_AUTO6]   = "auto6",
        [DRACUT_DHCP_MODE_EITHER6] = "either6",
        [DRACUT_DHCP_MODE_IBFT]    = "ibft",
};

const char *dracut_dhcp_mode_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(dracut_dhcp_mode_table))
                return NULL;

        return dracut_dhcp_mode_table[id];
}

int dracut_dhcp_mode_to_mode(const char *name) {
        assert(name);

        for (size_t i = DRACUT_DHCP_MODE_NONE; i < (int) ELEMENTSOF(dracut_dhcp_mode_table); i++)
                if (string_equal_fold(name, dracut_dhcp_mode_table[i]))
                        return i;

        return _DRACUT_DHCP_MODE_INVALID;
}

static const char *const dracut_to_networkd_dhcp_mode_table[_DRACUT_DHCP_MODE_MAX] = {
        [DRACUT_DHCP_MODE_NONE]    = "no",
        [DRACUT_DHCP_MODE_OFF]     = "no",
        [DRACUT_DHCP_MODE_ON]      = "yes",
        [DRACUT_DHCP_MODE_ANY]     = "yes",
        [DRACUT_DHCP_MODE_DHCP]    = "ipv4",
        [DRACUT_DHCP_MODE_DHCP6]   = "ipv6",
};

const char *dracut_to_networkd_dhcp_mode_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(dracut_to_networkd_dhcp_mode_table))
                return NULL;

        return dracut_to_networkd_dhcp_mode_table[id];
}

int dracut_to_networkd_dhcp_name_to_mode(const char *name) {
        assert(name);

        for (size_t i = DRACUT_DHCP_MODE_NONE; i < (int) ELEMENTSOF(dracut_to_networkd_dhcp_mode_table); i++)
                if (string_equal_fold(name, dracut_to_networkd_dhcp_mode_table[i]))
                        return i;

        return _DRACUT_DHCP_MODE_INVALID;
}

static int parse_dhcp_type(const char *s, Network *n) {

        assert(s);
        assert(n);

        n->dhcp_type = dracut_dhcp_mode_to_mode(s);
        return 0;
}

static int dracut_parse_mtu(char *mtu, Network *n) {
        assert(mtu);
        assert(n);

        return parse_mtu(mtu, &n->mtu);
}

static int dracut_parse_mac(char *mac, Network *n) {
        assert(n);
        assert(mac);

        if (!parse_ether_address(mac)) {
                log_warning("Failed to parse MAC address: %s", mac);
                return -EINVAL;
        }

        n->mac = g_strdup(mac);
        if (!n->mac)
                return log_oom();

        return 0;
}

/* ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<mtu>][:<macaddr>]]
 * ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<dns1>][:<dns2>]]
 * ip=<client-IP>:[<server-id>]:<gateway-IP-number>:<netmask>:<client-hostname>:<interface>:{dhcp|dhcp6|auto6|on|any|none|off}
 */
 static int parse_command_line_ip_interface(const char *line, Network *n) {
        _auto_cleanup_ IPAddress *peer = NULL, *prefix = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        _auto_cleanup_ Address *a = NULL;
        int r = 0;

        s = strsplit(line, ":", 9);
        if (!s)
                return -EINVAL;

        if (strv_length(s) > 0 && !isempty_string(s[0])) {
                r = parse_address_from_string_and_add(s[0], n->addresses);
                if (r < 0)
                        return r;
        }

        if (strv_length(s) >= 1 && !isempty_string(s[1])) {
                r = parse_ip_from_string(s[1], &peer);
                if (r < 0)
                        return r;

                a->peer = *peer;
        }

        steal_pointer(a);

        if (strv_length(s) >= 2 && !isempty_string(s[2])) {
                r = parse_ip_from_string(s[2], &n->gateway);
                if (r < 0)
                        return r;
        }

        if (strv_length(s) >= 3 && !isempty_string(s[3])) {
                r = parse_ip_from_string(s[3], &prefix);
                if (r >= 0)
                        n->gateway->prefix_len = ipv4_netmask_to_prefixlen(prefix);
                else
                        r = parse_integer(s[3], &n->gateway->prefix_len);
        } else
                n->gateway->prefix_len = 32;

        if (strv_length(s) >= 4 && !isempty_string(s[4])) {
                n->hostname = g_strdup(s[4]);
                if (!n->hostname)
                        return log_oom();
        }

        if (strv_length(s) >= 5 && !isempty_string(s[5])) {
                n->ifname = g_strdup(s[5]);
                if (!n->ifname)
                        return log_oom();
        }

        if (strv_length(s) >= 6 && !isempty_string(s[6]))
                (void) parse_dhcp_type(s[6], n);

        if (strv_length(s) >= 7 && !isempty_string(s[7]))
                r = dracut_parse_mtu(s[7], n);

        if (strv_length(s) >= 8 && !isempty_string(s[8]))
                r = dracut_parse_mac(s[8], n);

        if (r < 0) {
                if (strv_length(s) >= 7 && !isempty_string(s[7])) {
                        r = parse_address_from_string_and_add(s[7], n->nameservers);
                        if (r < 0)
                                return r;
                }

                if (strv_length(s) >= 7 && !isempty_string(s[8])) {
                        r = parse_address_from_string_and_add(s[8], n->nameservers);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

/* ip=<interface>:{dhcp|on|any|dhcp6|auto6}[:[<mtu>][:<macaddr>]] */
static int parse_command_line_ip_dhcp_interface(const char *line, Network *n) {
        _auto_cleanup_strv_ char **s = NULL;

        assert(line);
        assert(n);

        s = strsplit(line, ":", 4);
        if (!s)
                return -EINVAL;

        if (isempty_string(s[0]) || isempty_string(s[1]))
            return -EINVAL;

        n->ifname = g_strdup(s[0]);
        if (!n->ifname)
                return -ENOMEM;

        (void) parse_dhcp_type(s[1], n);

        if (g_strv_length(s) >= 2 && !isempty_string(s[2]))
                (void) dracut_parse_mtu(s[2], n);

        if (g_strv_length(s) >= 3 && !isempty_string(s[3]))
                (void) dracut_parse_mac(s[3], n);

        return 0;
}

static int parse_command_line_ip(const char *line, Network *n) {
        const char *p;
        int r;

        assert(line);
        assert(n);

        p = strchr(line, ':');
        if (!p)
                return parse_dhcp_type(line, n);

        r = parse_command_line_ip_interface(line, n);
        if (r < 0) {
                r = parse_command_line_ip_dhcp_interface(line, n);
                if (r < 0) {
                        log_warning("Failed to parse dracut command line : %s", line);
                        return r;
                }
        }

        return 0;
}

/* nameserver=srv1 [nameserver=srv2 [nameserver=srv3 […]]] */
static int parse_command_line_nameserver(const char *line, Network *n) {
        int r;

        assert(line);
        assert(n);

        r = parse_address_from_string_and_add(line, n->nameservers);
        if (r < 0) {
                log_warning("Failed to parse nameserver: %s", line);
                return r;
        }

        return 0;
}

/* rd.route=<net>/<netmask>:<gateway>[:<interface>] */
static int parse_command_line_rd_route(const char *line, Network *n) {
        _auto_cleanup_ IPAddress *destination = NULL, *gw = NULL;
        _auto_cleanup_ Route *route = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        int r;

        assert(line);
        assert(n);

        if (!n->routes) {
                n->routes = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
                if (!n->routes)
                        return log_oom();
        }

        s = strsplit(line, ":", 3);
        if (!s)
                return -EINVAL;

        r = route_new(&route);
        if (r < 0)
                return r;

        if (!isempty_string(s[0])) {
                r = parse_ip_from_string(s[0], &destination);
                if (r < 0)
                        return r;

                route->destination = *destination;

        }

       if (!isempty_string(s[1])) {
                r = parse_ip_from_string(s[1], &gw);
                if (r < 0)
                        return r;

                route->gw = *gw;
       }

       if (!g_hash_table_insert(n->routes, route, route)) {
               log_warning("Failed to add route: %s", line);
               return false;
       }
       route = NULL;

       if (!isempty_string(s[2])) {
               n->ifname = g_strdup(s[2]);
               if (!n->ifname)
                       return log_oom();
       }

       return 0;
}

static int merge_network_routes(void *key, void *value, void *network) {
        Route *route = value;
        Network *n = network;

        if (!g_hash_table_insert(n->routes, route, route)) {
                log_warning("Failed to merge route: %s", n->ifname);
                return -1;
        }

        return 0;
}

static int merge_network(GHashTable *networks_by_ifname, Network *n) {
        Network *v;
        int r;

        assert(networks_by_ifname);
        assert(n);

        v = g_hash_table_lookup(networks_by_ifname, n->ifname);
        if (!v)
                return -ENOENT;

        if (!v->routes) {
                v->routes = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
                if (!v->routes)
                        return log_oom();
        }

        r = g_hash_table_foreach_steal(n->routes, merge_network_routes, v);
        if (r < 0)
                return r;

        return 1;
}

int parse_proc_command_line(const char *cmd_line, GHashTable **ret) {
        _auto_cleanup_hash_ GHashTable *networks = NULL, *networks_by_ifname = NULL;
        _auto_cleanup_strv_ char **s;
        static Network *network;
        char **j;
        int r;

        assert(cmd_line);

        s = strsplit(cmd_line, " ", -1);
        if (!s)
                return log_oom();

        networks = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_network_free);
        if (!networks)
                return log_oom();

        networks_by_ifname = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
        if (!networks_by_ifname)
                return log_oom();

        strv_foreach(j, s) {
                _cleanup_(network_unrefp) Network *n = NULL;
                _auto_cleanup_ char *k = NULL, *v = NULL;

                r = parse_line(*j, &k, &v);
                if (r < 0)
                        return r;

                r = network_new(&n);
                if (r < 0)
                        return r;

                if (string_equal(k, "ip")) {

                        network = n;

                        r = parse_command_line_ip(v, n);
                        if (r < 0)
                                return r;

                        if (n->ifname) {
                                if (!g_hash_table_insert(networks_by_ifname, n->ifname, n))
                                        return log_oom();
                        }
                } else if (string_equal(k, "rd.route")) {
                        r = parse_command_line_rd_route(v, n);
                        if (r < 0)
                                return r;

                        r = merge_network(networks_by_ifname, n);
                        if (r >= 0)
                                continue;
                } else if (string_equal(k, "nameserver")) {
                        if (network) {
                                r = parse_command_line_nameserver(v, network);
                                if (r < 0)
                                        return r;
                        }
                } else
                        continue;

                n->parser_type = PARSER_TYPE_DRACUT;

                if (!g_hash_table_insert(networks, n, n))
                        return log_oom();

                steal_pointer(n);
        }

        *ret = steal_pointer(networks);
        return 0;
}

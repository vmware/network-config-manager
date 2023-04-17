/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "network-manager.h"
#include "netdev-link.h"
#include "network-sriov.h"
#include "network.h"
#include "networkd-api.h"
#include "parse-util.h"
#include "string-util.h"
#include "yaml-network-parser.h"
#include "yaml-parser.h"

static ParserTable match_vtable[] = {
        { "name",                       CONF_TYPE_NETWORK,     parse_yaml_string,                 offsetof(Network, ifname)},
        { "driver",                     CONF_TYPE_NETWORK,     parse_yaml_scalar_or_sequence,     offsetof(Network, driver)},
        { "macaddress",                 CONF_TYPE_NETWORK,     parse_yaml_mac_address,            offsetof(Network, match_mac)},
        { NULL,                         _CONF_TYPE_INVALID,    0,                                 0}
};

static ParserTable network_vtable[] = {
        { "unmanaged",                  CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, unmanaged)},
        { "mtu",                        CONF_TYPE_NETWORK,     parse_yaml_uint32,                       offsetof(Network, mtu)},
        { "arp",                        CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, arp)},
        { "multicast",                  CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, multicast)},
        { "allmulticast",               CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, all_multicast)},
        { "promiscuous",                CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, promiscuous)},
        { "required-for-online",        CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, req_for_online)},
        { "optional",                   CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, optional)},
        { "ignore-carrier",             CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, configure_without_carrier)},
        { "keep-configuration",         CONF_TYPE_NETWORK,     parse_yaml_keep_configuration,           offsetof(Network, keep_configuration)},
        { "infiniband-mode",            CONF_TYPE_NETWORK,     parse_yaml_infiniband_mode,              offsetof(Network, ipoib_mode)},
        { "neigh-suppress",             CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, neighbor_suppression)},
        { "required-family-for-online", CONF_TYPE_NETWORK,     parse_yaml_rf_online,                    offsetof(Network, req_family_for_online)},
        { "activation-mode",            CONF_TYPE_NETWORK,     parse_yaml_activation_policy,            offsetof(Network, activation_policy)},
        { "macaddress",                 CONF_TYPE_NETWORK,     parse_yaml_mac_address,                  offsetof(Network, mac)},
        { "dhcp",                       CONF_TYPE_NETWORK,     parse_yaml_dhcp_type,                    offsetof(Network, dhcp_type)},
        { "dhcp4",                      CONF_TYPE_NETWORK,     parse_yaml_dhcp_type,                    offsetof(Network, dhcp4)},
        { "dhcp6",                      CONF_TYPE_NETWORK,     parse_yaml_dhcp_type,                    offsetof(Network, dhcp6)},
        { "dhcp-identifier",            CONF_TYPE_NETWORK,     parse_yaml_dhcp_client_identifier,       offsetof(Network, dhcp_client_identifier_type)},
        { "lldp",                       CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, lldp)},
        { "emit-lldp",                  CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, emit_lldp)},
        { "accept-ra",                  CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, ipv6_accept_ra)},
        { "enable-dhcp4-server",        CONF_TYPE_NETWORK,     parse_yaml_bool,                         offsetof(Network, enable_dhcp4_server)},
        { "link-local",                 CONF_TYPE_NETWORK,     parse_yaml_link_local_type,              offsetof(Network, link_local)},
        { "ipv6-address-generation",    CONF_TYPE_NETWORK,     parse_yaml_ipv6_address_generation_mode, offsetof(Network, ipv6_address_generation)},
        { "ipv6-privacy",               CONF_TYPE_NETWORK,     parse_yaml_ipv6_privacy_extensions,      offsetof(Network, ipv6_privacy)},
        { "ipv6-mtu",                   CONF_TYPE_NETWORK,     parse_yaml_uint32,                       offsetof(Network, ipv6_mtu)},
        { "ntp",                        CONF_TYPE_NETWORK,     parse_yaml_sequence,                     offsetof(Network, ntps)},
        { NULL,                         _CONF_TYPE_INVALID,    0,                                       0}
};

static ParserTable dhcp4_overrides_vtable[] = {
        { "use-dns",        CONF_TYPE_DHCP4,     parse_yaml_bool,   offsetof(Network, dhcp4_use_dns)},
        { "use-domain",     CONF_TYPE_DHCP4,     parse_yaml_bool,   offsetof(Network, dhcp4_use_domains)},
        { "use-ntp",        CONF_TYPE_DHCP4,     parse_yaml_bool,   offsetof(Network, dhcp4_use_ntp)},
        { "use-mtu",        CONF_TYPE_DHCP4,     parse_yaml_bool,   offsetof(Network, dhcp4_use_mtu)},
        { "use-routes",     CONF_TYPE_DHCP4,     parse_yaml_bool,   offsetof(Network, dhcp4_use_routes)},
        { "use-gateway",    CONF_TYPE_DHCP4,     parse_yaml_bool,   offsetof(Network, dhcp4_use_gw)},
        { "use-hostname",   CONF_TYPE_DHCP4,     parse_yaml_bool,   offsetof(Network, dhcp4_use_hostname)},
        { "send-hostname",  CONF_TYPE_DHCP4,     parse_yaml_bool,   offsetof(Network, dhcp4_send_hostname)},
        { "send-release",   CONF_TYPE_DHCP4,     parse_yaml_bool,   offsetof(Network, dhcp4_send_release)},
        { "route-metric",   CONF_TYPE_DHCP4,     parse_yaml_uint32, offsetof(Network, dhcp4_route_metric)},
        { "hostname",       CONF_TYPE_DHCP4,     parse_yaml_string, offsetof(Network, dhcp4_hostname)},
        { NULL,             _CONF_TYPE_INVALID,  0,                 0}
};

static ParserTable dhcp6_overrides_vtable[] = {
        { "use-dns",       CONF_TYPE_DHCP6,     parse_yaml_bool,             offsetof(Network, dhcp6_use_dns)},
        { "use-domain",    CONF_TYPE_DHCP6,     parse_yaml_bool,             offsetof(Network, dhcp6_use_domains)},
        { "use-ntp",       CONF_TYPE_DHCP6,     parse_yaml_bool,             offsetof(Network, dhcp6_use_ntp)},
        { "use-address",   CONF_TYPE_DHCP6,     parse_yaml_bool,             offsetof(Network, dhcp6_use_address)},
        { "use-hostname",  CONF_TYPE_DHCP6,     parse_yaml_bool,             offsetof(Network, dhcp6_use_hostname)},
        { "send-release",  CONF_TYPE_DHCP6,     parse_yaml_bool,             offsetof(Network, dhcp6_send_release)},
        { "without-ra",    CONF_TYPE_DHCP6,     parse_yaml_dhcp6_without_ra, offsetof(Network, dhcp6_client_start_mode)},
        { "rapid-commit",  CONF_TYPE_DHCP6,     parse_yaml_bool,             offsetof(Network, dhcp6_rapid_commit)},
        { NULL,            _CONF_TYPE_INVALID,  0,                           0}
};

static ParserTable router_advertisement_overrides_vtable[] = {
        { "token",                 CONF_TYPE_RA,       parse_yaml_string,           offsetof(Network, ipv6_ra_token)},
        { "use-dns",               CONF_TYPE_RA,       parse_yaml_bool,             offsetof(Network, ipv6_ra_use_dns)},
        { "use-domain",            CONF_TYPE_RA,       parse_yaml_bool,             offsetof(Network, ipv6_ra_use_domains)},
        { "use-mtu",               CONF_TYPE_RA,       parse_yaml_bool,             offsetof(Network, ipv6_ra_use_mtu)},
        { "use-gateway",           CONF_TYPE_RA,       parse_yaml_bool,             offsetof(Network, ipv6_ra_use_gw)},
        { "use-route-prefix",      CONF_TYPE_RA,       parse_yaml_bool,             offsetof(Network, ipv6_ra_use_route_prefix)},
        { "use-autonomous-prefix", CONF_TYPE_RA,       parse_yaml_bool,             offsetof(Network, ipv6_ra_use_auto_prefix)},
        { "use-on-link-prefix",    CONF_TYPE_RA,       parse_yaml_bool,             offsetof(Network, ipv6_ra_use_onlink_prefix)},
        { NULL,                    _CONF_TYPE_INVALID, 0,                           0}
};

static ParserTable address_vtable[] = {
        { "label",     CONF_TYPE_ADDRESS,     parse_yaml_addresses, offsetof(Network, addresses)},
        { "addresses", CONF_TYPE_ADDRESS,     parse_yaml_addresses, offsetof(Network, addresses)},
        { NULL,        _CONF_TYPE_INVALID,    0,                    0}
};

static ParserTable nameservers_vtable[] = {
        { "search",     CONF_TYPE_DNS,      parse_yaml_domains,              offsetof(Network, domains)},
        { "addresses",  CONF_TYPE_DNS,      parse_yaml_nameserver_addresses, offsetof(Network, nameservers)},
        { NULL,         _CONF_TYPE_INVALID, 0,                               0}
};

static ParserTable route_vtable[] = {
        { "via",                        CONF_TYPE_ROUTE,    parse_yaml_route,       offsetof(Route, gw)},
        { "to",                         CONF_TYPE_ROUTE,    parse_yaml_route,       offsetof(Route, dst)},
        { "from",                       CONF_TYPE_ROUTE,    parse_yaml_address,     offsetof(Route, prefsrc)},
        { "table",                      CONF_TYPE_ROUTE,    parse_yaml_uint32,      offsetof(Route, table)},
        { "type",                       CONF_TYPE_ROUTE,    parse_yaml_route_type,  offsetof(Route, type)},
        { "scope",                      CONF_TYPE_ROUTE,    parse_yaml_route_scope, offsetof(Route, scope)},
        { "metric",                     CONF_TYPE_ROUTE,    parse_yaml_uint32,      offsetof(Route, metric)},
        { "on-link",                    CONF_TYPE_ROUTE,    parse_yaml_bool,        offsetof(Route, onlink)},
        { "congestion-window",          CONF_TYPE_ROUTE,    parse_yaml_uint32,      offsetof(Route, initcwnd)},
        { "advertised-receive-window",  CONF_TYPE_ROUTE,    parse_yaml_uint32,      offsetof(Route, initrwnd)},
        { "quick-ack",                  CONF_TYPE_ROUTE,    parse_yaml_bool,        offsetof(Route, quick_ack)},
        { "fast-open-no-cookie",        CONF_TYPE_ROUTE,    parse_yaml_bool,        offsetof(Route, tfo)},
        { "ttl-propogate",              CONF_TYPE_ROUTE,    parse_yaml_bool,        offsetof(Route, ttl_propogate)},
        { NULL,                         _CONF_TYPE_INVALID, 0,                      0}
};

static ParserTable routing_policy_rule_vtable[] = {
        { "from",            CONF_TYPE_ROUTING_POLICY_RULE, parse_yaml_address, offsetof(RoutingPolicyRule, from)},
        { "to",              CONF_TYPE_ROUTING_POLICY_RULE, parse_yaml_address, offsetof(RoutingPolicyRule, to)},
        { "table",           CONF_TYPE_ROUTING_POLICY_RULE, parse_yaml_uint32,  offsetof(RoutingPolicyRule, table)},
        { "priority",        CONF_TYPE_ROUTING_POLICY_RULE, parse_yaml_uint32,  offsetof(RoutingPolicyRule, priority)},
        { "type-of-service", CONF_TYPE_ROUTING_POLICY_RULE, parse_yaml_uint32,  offsetof(RoutingPolicyRule, tos)},
        { "mark",            CONF_TYPE_ROUTING_POLICY_RULE, parse_yaml_uint32,  offsetof(RoutingPolicyRule, fwmark)},
        { NULL,              _CONF_TYPE_INVALID,            0,                  0}
};

static ParserTable dhcp4_server_static_lease_vtable[] = {
        { "address",    CONF_TYPE_DHCP4_SERVER, parse_yaml_address,     offsetof(DHCP4ServerLease, addr)},
        { "macaddress", CONF_TYPE_DHCP4_SERVER, parse_yaml_mac_address, offsetof(DHCP4ServerLease, mac)},
        { NULL,          _CONF_TYPE_INVALID,    0,                      0}
};

static ParserTable dhcp4_server_vtable[] = {
        { "pool-offset",        CONF_TYPE_DHCP4_SERVER, parse_yaml_uint32,  offsetof(DHCP4Server, pool_offset)},
        { "pool-size",          CONF_TYPE_DHCP4_SERVER, parse_yaml_uint32,  offsetof(DHCP4Server, pool_size)},
        { "emit-dns",           CONF_TYPE_DHCP4_SERVER, parse_yaml_bool,    offsetof(DHCP4Server, emit_dns)},
        { "dns",                CONF_TYPE_DHCP4_SERVER, parse_yaml_address, offsetof(DHCP4Server, dns)},
        { "default-lease-time", CONF_TYPE_DHCP4_SERVER, parse_yaml_string,  offsetof(DHCP4Server, default_lease_time)},
        { "max-lease-time",     CONF_TYPE_DHCP4_SERVER, parse_yaml_string,  offsetof(DHCP4Server, max_lease_time)},
        { NULL,                 _CONF_TYPE_INVALID,     0,                  0}
};

static ParserTable sriov_vtable[] = {
        { "virtual-function",    CONF_TYPE_SRIOV,   parse_yaml_uint32, offsetof(SRIOV, vf)},
        { "vlan-id",             CONF_TYPE_SRIOV,   parse_yaml_uint32, offsetof(SRIOV, vlan)},
        { "quality-of-service",  CONF_TYPE_SRIOV,   parse_yaml_string, offsetof(SRIOV, qos)},
        { "vlan-protocol",       CONF_TYPE_SRIOV,   parse_yaml_string, offsetof(SRIOV, vlan_proto)},
        { "link-state",          CONF_TYPE_SRIOV,   parse_yaml_uint32, offsetof(SRIOV, link_state)},
        { "macaddress",          CONF_TYPE_SRIOV,   parse_yaml_string, offsetof(SRIOV, macaddr)},
        { NULL,                 _CONF_TYPE_INVALID,                 0, 0}
};

static int parse_route(GHashTable *config, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        _auto_cleanup_ Route *rt = NULL;
        int r;

        assert(config);
        assert(dp);
        assert(node);
        assert(network);

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *n;

                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) parse_route(config, dp, n, network);
        }

        for (yaml_node_pair_t *p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                yaml_node_t *k, *v;
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(config, scalar(k));
                if (!table)
                        continue;

                if (!rt) {
                        r = route_new(&rt);
                        if (r < 0)
                                return log_oom();
                }

                t = (uint8_t *) rt + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), rt, t, dp, v);
                        network->modified = true;
                }
        }

        if (rt) {
                g_hash_table_insert(network->routes, rt, rt);

                network->modified = true;
                steal_pointer(rt);
        }


        return 0;
}

static int parse_address(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network, IPAddress **addr) {
        _auto_cleanup_ IPAddress *a = NULL;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *n;

                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) parse_address(m, dp, n, network, addr);
        }

        for (yaml_node_pair_t *p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                yaml_node_t *k, *v;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                if (!a && !*addr) {
                        a = new0(IPAddress, 1);
                        if (!a)
                                return log_oom();
                }

                if (str_eq(scalar(k), "lifetime")) {
                        free(a->lifetime);
                        a->lifetime = strdup(scalar(v));
                        if (!a->lifetime)
                                return log_oom();
                } else if (str_eq(scalar(k), "label")) {
                        free(a->label);
                        a->label = strdup(scalar(v));
                        if (!a->label)
                                return log_oom();
                } else {
                        _auto_cleanup_ IPAddress *address = NULL;

                        r = parse_ip_from_str(scalar(k), &address);
                        if (r < 0) {
                                log_debug("Failed to parse address='%s': %s", scalar(k), strerror(-r));
                                continue;
                        }

                        if (*addr) {
                                if ((*addr)->label)
                                        address->label = strdup((*addr)->label);
                                if ((*addr)->lifetime)
                                        address->lifetime = (*addr)->lifetime;

                                free(*addr);
                                steal_pointer(*addr);
                        }

                        set_add(network->addresses, address);
                        steal_pointer(address);

                        network->modified = true;

                        if (v) {
                                r = parse_address_from_str_and_add(scalar(v), network->addresses);
                                if (r < 0)
                                        log_debug("Failed to parse address='%s': %s", scalar(v), strerror(-r));
                        }
                }
        }

        if (a) {
                *addr = a;
                steal_pointer(a);
        }

        return 0;
}

static int parse_routing_policy_rule(GHashTable *config, yaml_document_t *dp, yaml_node_t *node, Network *network) {
       _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *rule = NULL;
        int r;

        assert(config);
        assert(dp);
        assert(node);
        assert(network);

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *n;

                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) parse_routing_policy_rule(config, dp, n, network);
        }

        for (yaml_node_pair_t *p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                yaml_node_t *k, *v;
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(config, scalar(k));
                if (!table)
                        continue;

                if (!rule) {
                        r = routing_policy_rule_new(&rule);
                        if (r < 0)
                                return log_oom();
                }

                t = (uint8_t *) rule + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), rule, t, dp, v);
                        network->modified = true;
                }
        }

        if (rule) {
                g_hash_table_insert(network->routing_policy_rules, rule, rule);

                network->modified = true;
                steal_pointer(rule);
        }

        return 0;
}

static int parse_dhcp4_server_static_lease(GHashTable *config, yaml_document_t *dp, yaml_node_t *node, DHCP4Server *s) {
        _auto_cleanup_ DHCP4ServerLease *l = NULL;

        assert(config);
        assert(dp);
        assert(node);
        assert(s);

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *n;

                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) parse_dhcp4_server_static_lease(config, dp, n, s);
        }

        for (yaml_node_pair_t *p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                yaml_node_t *k, *v;
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(config, scalar(k));
                if (!table)
                        continue;

                if (!l) {
                        l = new0(DHCP4ServerLease, 1);
                        if (!l)
                                return log_oom();
                }

                t = (uint8_t *) l + table->offset;
                if (table->parser)
                        (void) table->parser(scalar(k), scalar(v), l, t, dp, v);
        }

        if (l) {
                g_hash_table_insert(s->static_leases, GUINT_TO_POINTER(l), l);
                steal_pointer(l);
        }

        return 0;
}

static int parse_dhcp4_server(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        DHCP4Server *s = NULL;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *n;

                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) parse_dhcp4_server(m, dp, n, network);
        }

        for (yaml_node_pair_t *p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                yaml_node_t *k, *v;
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                if (!s) {
                        r = dhcp4_server_new(&s);
                        if (r < 0)
                                return log_oom();

                        network->dhcp4_server = s;
                        network->modified = true;
                }

                if (k && str_eq(scalar(k), "static-leases")) {
                        parse_dhcp4_server_static_lease(m->dhcp4_server_static_lease, dp, v, s);
                        continue;
                }

                table = g_hash_table_lookup(m->dhcp4_server, scalar(k));
                if (!table)
                        continue;

                t = (uint8_t *) s + table->offset;
                if (table->parser)
                        (void) table->parser(scalar(k), scalar(v), s, t, dp, v);
        }

        return 0;
}

static int parse_config(GHashTable *config, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        assert(dp);
        assert(node);
        assert(network);

        for ( yaml_node_pair_t *p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                yaml_node_t *k, *v;
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                table = g_hash_table_lookup(config, scalar(k));
                if (!table)
                        continue;

                t = (uint8_t *) network + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), network, t, dp, v);
                        network->modified = true;
                }
        }

        return 0;
}

int parse_network(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        for (yaml_node_pair_t *p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                yaml_node_t *k, *v;
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                table = g_hash_table_lookup(m->network, scalar(k));
                if (table) {
                        t = (uint8_t *) network + table->offset;
                        if (table->parser) {
                                (void) table->parser(scalar(k), scalar(v), network, t, dp, v);
                                network->modified = true;
                        }

                        continue;
                }

                switch (conf_type_to_mode(scalar(k))) {
                        case CONF_TYPE_MATCH:
                                r = parse_config(m->match, dp, v, network);
                                if (r < 0)
                                        return r;
                                break;

                        case CONF_TYPE_DHCP4:
                                r = parse_config(m->dhcp4, dp, v, network);
                                if (r < 0)
                                        return r;
                                break;

                        case CONF_TYPE_DHCP6:
                                r = parse_config(m->dhcp6, dp, v, network);
                                if (r < 0)
                                        return r;
                                break;

                        case CONF_TYPE_RA:
                                r = parse_config(m->router_advertisement, dp, v, network);
                                if (r < 0)
                                        return r;
                                break;

                        case CONF_TYPE_ADDRESS: {
                                IPAddress *a = NULL;

                                r = parse_address(m, dp, v, network, &a);
                                if (r < 0)
                                        return r;
                        }
                                break;

                        case CONF_TYPE_ROUTE:
                                r = parse_route(m->route, dp, v, network);
                                if (r < 0)
                                        return r;
                                break;

                        case CONF_TYPE_ROUTING_POLICY_RULE:
                                r = parse_routing_policy_rule(m->routing_policy_rule, dp, v, network);
                                if (r < 0)
                                        return r;
                                break;

                        case CONF_TYPE_DNS:
                                r = parse_config(m->nameserver, dp, v, network);
                                if (r < 0)
                                        return r;
                                break;
                        case CONF_TYPE_DHCP4_SERVER:
                                r = parse_dhcp4_server(m, dp, v, network);
                                if (r < 0)
                                        return r;
                                break;

                        case CONF_TYPE_LINK:
                                r = yaml_parse_link_parameters(m, dp, v, network);
                                if (r < 0)
                                        return r;
                                break;

                        default:
                                if (v) {
                                        r = parse_network(m, dp, v, network);
                                        if (r < 0)
                                                return r;
                                }
                }

                /* .link  */
                r = parse_link(m, dp, k, v, network);
                if (r <= 0)
                        log_debug("Failed find key='%s' in link table", scalar(k));
        }

        return 0;
}

int parse_ethernet_config(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Networks *nets) {
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(nets);

        for (yaml_node_pair_t *p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                _cleanup_(network_freep) Network *net = NULL;
                yaml_node_t *n;

                n = yaml_document_get_node(dp, p->key);
                if (!n)
                        continue;

                r = yaml_network_new(scalar(n), &net);
                if (r < 0)
                        return r;

                n = yaml_document_get_node(dp, p->value);
                if (!n)
                        continue;

                r = parse_network(m, dp, n, net);
                if (r < 0)
                        return r;

                if (g_hash_table_insert(nets->networks, (gpointer *) net->ifname, (gpointer *) net))
                        steal_pointer(net);
        }

        return 0;
}

int yaml_network_new(const char *ifname, Network **ret) {
        _cleanup_(network_freep) Network *n = NULL;
        int r;

        r = network_new(&n);
        if (r < 0)
                return r;

        n->parser_type = PARSER_TYPE_YAML;
        n->ifname = strdup(ifname);
        if (!n->ifname)
                return log_oom();

        *ret = steal_pointer(n);
        return 0;
}

int yaml_register_network(YAMLManager *m) {
        assert(m);
        assert(m->match);
        assert(m->network);
        assert(m->dhcp4);
        assert(m->dhcp6);
        assert(m->router_advertisement);
        assert(m->address);
        assert(m->routing_policy_rule);
        assert(m->route);
        assert(m->nameserver);

        for (size_t i = 0; match_vtable[i].key; i++) {
               if (!g_hash_table_insert(m->match, (void *) match_vtable[i].key, &match_vtable[i])) {
                        log_warning("Failed add key='%s' to match table", match_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; network_vtable[i].key; i++) {
               if (!g_hash_table_insert(m->network, (void *) network_vtable[i].key, &network_vtable[i])) {
                        log_warning("Failed add key='%s' to network table", network_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; dhcp4_overrides_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->dhcp4, (void *) dhcp4_overrides_vtable[i].key, &dhcp4_overrides_vtable[i])) {
                        log_warning("Failed add key='%s' to dhcp4 table", dhcp4_overrides_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; dhcp6_overrides_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->dhcp6, (void *) dhcp6_overrides_vtable[i].key, &dhcp6_overrides_vtable[i])) {
                        log_warning("Failed add key='%s' to dhcp6 table", dhcp6_overrides_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; router_advertisement_overrides_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->router_advertisement, (void *) router_advertisement_overrides_vtable[i].key, &router_advertisement_overrides_vtable[i])) {
                        log_warning("Failed add key='%s' to IPv6 RA table", router_advertisement_overrides_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; address_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->address, (void *) address_vtable[i].key, &address_vtable[i])) {
                        log_warning("Failed add key='%s' to address table", address_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; routing_policy_rule_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->routing_policy_rule, (void *) routing_policy_rule_vtable[i].key, &routing_policy_rule_vtable[i])) {
                        log_warning("Failed add key='%s' to routing policy rule table", routing_policy_rule_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; route_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->route, (void *) route_vtable[i].key, &route_vtable[i])) {
                        log_warning("Failed add key='%s' to route table", route_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; nameservers_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->nameserver, (void *) nameservers_vtable[i].key, &nameservers_vtable[i])) {
                        log_warning("Failed add key='%s' to nameserver table", nameservers_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; dhcp4_server_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->dhcp4_server, (void *) dhcp4_server_vtable[i].key, &dhcp4_server_vtable[i])) {
                        log_warning("Failed add key='%s' to dhcp4 server table", dhcp4_server_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; dhcp4_server_static_lease_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->dhcp4_server_static_lease, (void *) dhcp4_server_static_lease_vtable[i].key, &dhcp4_server_static_lease_vtable[i])) {
                        log_warning("Failed add key='%s' dhcp4 server static lease table", dhcp4_server_static_lease_vtable[i].key);
                        return -EINVAL;
                }
        }

        return 0;
}

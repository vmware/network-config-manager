/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "network-manager.h"
#include "netdev.h"
#include "network.h"
#include "parse-util.h"
#include "string-util.h"
#include "yaml-network-parser.h"
#include "yaml-netdev-parser.h"
#include "yaml-parser.h"

static const char *const yaml_netdev_kind_table[_YAML_NETDEV_KIND_MAX] = {
        [YAML_NETDEV_KIND_VLAN]    = "vlans",
        [YAML_NETDEV_KIND_BRIDGE]  = "bridges",
        [YAML_NETDEV_KIND_BOND]    = "bonds",
        [YAML_NETDEV_KIND_VXLAN]   = "vxlans",
        [YAML_NETDEV_KIND_MACVLAN] = "macvlans",
        [YAML_NETDEV_KIND_MACVTAP] = "macvtaps",
        [YAML_NETDEV_KIND_IPVLAN]  = "ipvlans",
        [YAML_NETDEV_KIND_IPVTAP]  = "ipvtaps",
        [YAML_NETDEV_KIND_VRF]     = "vrfs",
        [YAML_NETDEV_KIND_VETH]    = "veths",
        [YAML_NETDEV_KIND_TUN]     = "tuns",
        [YAML_NETDEV_KIND_TAP]     = "taps",
        [YAML_NETDEV_KIND_TUNNEL]  = "tunnels",
};

const char *yaml_netdev_kind_to_name(YAMLNetDevKind id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(yaml_netdev_kind_table))
                return NULL;

        return yaml_netdev_kind_table[id];
}

int yaml_netdev_name_to_kind(const char *name) {
        assert(name);

        for (size_t i = YAML_NETDEV_KIND_VLAN; i < (int) ELEMENTSOF(yaml_netdev_kind_table); i++)
                if (yaml_netdev_kind_table[i] && string_equal_fold(name, yaml_netdev_kind_table[i]))
                        return i;

        return _YAML_NETDEV_KIND_INVALID;
}

bool is_yaml_netdev_kind(const char *s) {
        int r;

        assert(s);

        r = yaml_netdev_name_to_kind(s);
        if (r < 0)
                return false;

        return true;
}

static int yaml_detect_tunnel_kind(yaml_document_t *dp, yaml_node_t *node) {
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        int r;

        assert(dp);
        assert(node);

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                if (string_equal(scalar(k), "mode")) {
                        r = netdev_name_to_kind(scalar(v));
                        if (r < 0) {
                                log_warning("Failed to parse tunnel mode = %s", scalar(v));
                                return -EINVAL;
                        }

                        return r;
                }
        }

        return -EINVAL;
}

static ParserTable parser_bond_vtable[] = {
        { "interfaces",           CONF_TYPE_NETDEV_BOND, parse_yaml_sequence,       offsetof(Bond, interfaces)},
        { "mode",                 CONF_TYPE_NETDEV_BOND, parse_yaml_bond_mode,      offsetof(Bond, mode)},
        { "lacp-rate",            CONF_TYPE_NETDEV_BOND, parse_yaml_bond_lacp_rate, offsetof(Bond, lacp_rate)},
        { "mii-monitor-interval", CONF_TYPE_NETDEV_BOND, parse_yaml_uint64,         offsetof(Bond, mii_monitor_interval)},
        { "min-links",            CONF_TYPE_NETDEV_BOND, parse_yaml_uint32,         offsetof(Bond, min_links)},
        { "arp-interval",         CONF_TYPE_NETDEV_BOND, parse_yaml_uint64,         offsetof(Bond, arp_interval)},
        { NULL,         _CONF_TYPE_INVALID,    0,                         0}
};

static int yaml_yaml_parse_bond_parameters(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Bond *bond) {
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        yaml_node_item_t *i;
        yaml_node_t *n;

        assert(m);
        assert(dp);
        assert(node);
        assert(bond);

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) yaml_yaml_parse_bond_parameters(m, dp, n, bond);
        }

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->bond, scalar(k));
                if (!table)
                        continue;

                t = (uint8_t *) bond + table->offset;
                if (table->parser)
                        (void) table->parser(scalar(k), scalar(v), bond, t, dp, v);
        }

        return 0;
}

static int yaml_parse_bond(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        _auto_cleanup_ Bond *bond = NULL;
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        r = bond_new(&bond);
        if (r < 0)
                return log_oom();

        *network->netdev = (NetDev) {
                           .ifname = strdup(network->ifname),
                           .kind = YAML_NETDEV_KIND_BOND,
                           .bond = bond,
        };
        if (!network->netdev->ifname)
                return log_oom();

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->bond, scalar(k));
                if (!table) {
                        if (string_equal(scalar(k), "parameters"))
                                yaml_yaml_parse_bond_parameters(m, dp, v, bond);
                        else
                                (void) parse_network(m, dp, node, network);
                        continue;
                }

                t = (uint8_t *) bond + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), bond, t, dp, v);
                        network->modified = true;
                }
        }

        steal_pointer(bond);
        return 0;
}

static ParserTable parser_bridge_vtable[] = {
        { "interfaces",    CONF_TYPE_NETDEV_BRIDGE, parse_yaml_sequence, offsetof(Bridge, interfaces)},
        { "priority",      CONF_TYPE_NETDEV_BRIDGE, parse_yaml_uint32,   offsetof(Bridge, priority)},
        { "forward-delay", CONF_TYPE_NETDEV_BRIDGE, parse_yaml_uint32,   offsetof(Bridge, forward_delay)},
        { "hello-time",    CONF_TYPE_NETDEV_BRIDGE, parse_yaml_uint32,   offsetof(Bridge, hello_time)},
        { "max-age",       CONF_TYPE_NETDEV_BRIDGE, parse_yaml_uint32,   offsetof(Bridge, max_age)},
        { "ageing-time",   CONF_TYPE_NETDEV_BRIDGE, parse_yaml_uint32,   offsetof(Bridge, ageing_time)},
        { "aging-time",    CONF_TYPE_NETDEV_BRIDGE, parse_yaml_uint32,   offsetof(Bridge, ageing_time)},
        { "stp",           CONF_TYPE_NETDEV_BRIDGE, parse_yaml_bool,     offsetof(Bridge, stp)},
        { NULL,            _CONF_TYPE_INVALID,    0,                  0}
};

static int yaml_yaml_parse_bridge_parameters(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Bridge *br) {
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        yaml_node_item_t *i;
        yaml_node_t *n;

        assert(m);
        assert(dp);
        assert(node);
        assert(br);

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) yaml_yaml_parse_bridge_parameters(m, dp, n, br);
        }

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->bridge, scalar(k));
                if (!table)
                        continue;

                t = (uint8_t *) br + table->offset;
                if (table->parser)
                        (void) table->parser(scalar(k), scalar(v), br, t, dp, v);
        }

        return 0;
}

static int yaml_parse_bridge(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        _auto_cleanup_ Bridge *b = NULL;
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        r = bridge_new(&b);
        if (r < 0)
                return log_oom();

        *network->netdev = (NetDev) {
                           .ifname = strdup(network->ifname),
                           .kind = YAML_NETDEV_KIND_BRIDGE,
                           .bridge = b,
        };
        if (!network->netdev->ifname)
                return log_oom();

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->bridge, scalar(k));
                if (!table) {
                        if (string_equal(scalar(k), "parameters"))
                                yaml_yaml_parse_bridge_parameters(m, dp, v, b);
                        else
                                (void) parse_network(m, dp, node, network);

                        continue;
                }

                t = (uint8_t *) b + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), b, t, dp, v);
                        network->modified = true;
                }
        }

        steal_pointer(b);
        return 0;
}

static ParserTable parser_vlan_vtable[] = {
        { "id",   CONF_TYPE_NETDEV_VLAN, parse_yaml_uint32,  offsetof(VLan, id)},
        { "link", CONF_TYPE_NETDEV_VLAN, parse_yaml_string,  offsetof(VLan, master)},
        { NULL,   _CONF_TYPE_INVALID,    0,                  0}
};

static int yaml_parse_vlan(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        _auto_cleanup_ VLan *vlan = NULL;
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        r = vlan_new(&vlan);
        if (r < 0)
                return log_oom();

        *network->netdev = (NetDev) {
                           .ifname = strdup(network->ifname),
                           .kind = YAML_NETDEV_KIND_VLAN,
                           .vlan = vlan,
        };
        if (!network->netdev->ifname)
                return log_oom();

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->vlan, scalar(k));
                if (!table) {
                        (void) parse_network(m, dp, node, network);

                        continue;
                }

                t = (uint8_t *) vlan + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), vlan, t, dp, v);
                        network->modified = true;
                }
        }

        steal_pointer(vlan);
        return 0;
}

static ParserTable parser_tunnel_vtable[] = {
        { "local",  CONF_TYPE_NETDEV_TUNNEL, parse_yaml_address, offsetof(Tunnel, local)},
        { "remote", CONF_TYPE_NETDEV_TUNNEL, parse_yaml_address, offsetof(Tunnel, remote)},
        { "key",    CONF_TYPE_NETDEV_TUNNEL, parse_yaml_uint32,  offsetof(Tunnel, key)},
        { "input",  CONF_TYPE_NETDEV_TUNNEL, parse_yaml_uint32,  offsetof(Tunnel, ikey)},
        { "output", CONF_TYPE_NETDEV_TUNNEL, parse_yaml_uint32,  offsetof(Tunnel, okey)},
        { "ttl",    CONF_TYPE_NETDEV_TUNNEL, parse_yaml_uint32,  offsetof(Tunnel, ttl)},
        { NULL,     _CONF_TYPE_INVALID,      0,                  0}
};

static int yaml_parse_tunnel_keys(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Tunnel *tnl) {
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        yaml_node_item_t *i;
        yaml_node_t *n;

        assert(m);
        assert(dp);
        assert(node);
        assert(tnl);

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) yaml_parse_tunnel_keys(m, dp, n, tnl);
        }

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->tunnel, scalar(k));
                if (!table)
                        continue;

                t = (uint8_t *) tnl + table->offset;
                if (table->parser)
                        (void) table->parser(scalar(k), scalar(v), tnl, t, dp, v);
        }

        return 0;
}

static int yaml_parse_tunnel(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        _auto_cleanup_ Tunnel *tnl = NULL;
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        r = tunnel_new(&tnl);
        if (r < 0)
                return log_oom();

        *tnl = (Tunnel) {
                     .independent = true,
               };

        *network->netdev = (NetDev) {
                           .ifname = strdup(network->ifname),
                           .tunnel = tnl,
        };
        if (!network->netdev->ifname)
                return log_oom();

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->tunnel, scalar(k));
                if (!table) {
                        if (string_equal(scalar(k), "mode")) {
                                r = netdev_name_to_kind(scalar(v));
                                if (r < 0) {
                                        log_warning("Failed to parse tunnel mode = %s", scalar(v));
                                        return -EINVAL;
                                }
                                network->netdev->kind = r;
                        } else if (string_equal(scalar(k), "keys"))
                                yaml_parse_tunnel_keys(m, dp, v, tnl);
                        else
                                (void) parse_network(m, dp, node, network);

                        continue;
                }

                t = (uint8_t *) tnl + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), tnl, t, dp, v);
                        network->modified = true;
                }
        }

        steal_pointer(tnl);
        return 0;
}

static ParserTable parser_netdev_vrf_vtable[] = {
        { "interfaces", CONF_TYPE_NETDEV_VRF, parse_yaml_sequence, offsetof(VRF, interfaces)},
        { "table",      CONF_TYPE_NETDEV_VRF, parse_yaml_uint32,   offsetof(VRF, table)},
        { NULL,         _CONF_TYPE_INVALID,    0,                  0}
};

static int yaml_parse_netdev_vrf(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        _cleanup_(vrf_freep) VRF *vrf = NULL;
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        r = vrf_new(&vrf);
        if (r < 0)
                return log_oom();

        *network->netdev = (NetDev) {
                           .ifname = strdup(network->ifname),
                           .kind = YAML_NETDEV_KIND_VRF,
                           .vrf = vrf,
        };
        if (!network->netdev->ifname)
                return log_oom();

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->netdev_vrf, scalar(k));
                if (!table) {
                        (void) parse_network(m, dp, node, network);

                        continue;
                }

                t = (uint8_t *) vrf + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), vrf, t, dp, v);
                        network->modified = true;
                }
        }

        steal_pointer(vrf);
        return 0;
}

static ParserTable parser_netdev_vxlan_vtable[] = {
        { "id",               CONF_TYPE_NETDEV_VXLAN, parse_yaml_uint32,              offsetof(VxLan, vni)},
        { "local",            CONF_TYPE_NETDEV_VXLAN, parse_yaml_address,             offsetof(VxLan, local)},
        { "remote",           CONF_TYPE_NETDEV_VXLAN, parse_yaml_address,             offsetof(VxLan, remote)},
        { "link",             CONF_TYPE_NETDEV_VXLAN, parse_yaml_string,              offsetof(VxLan, master)},
        { "type-of-service",  CONF_TYPE_NETDEV_VXLAN, parse_yaml_uint32,              offsetof(VxLan, tos)},
        { "mac-learning",     CONF_TYPE_NETDEV_VXLAN, parse_yaml_bool,                offsetof(VxLan, learning)},
        { "ageing",           CONF_TYPE_NETDEV_VXLAN, parse_yaml_uint32,              offsetof(VxLan, fdb_ageing)},
        { "aging",            CONF_TYPE_NETDEV_VXLAN, parse_yaml_uint32,              offsetof(VxLan, fdb_ageing)},
        { "limit",            CONF_TYPE_NETDEV_VXLAN, parse_yaml_uint32,              offsetof(VxLan, max_fdb)},
        { "arp-proxy",        CONF_TYPE_NETDEV_VXLAN, parse_yaml_bool,                offsetof(VxLan, arp_proxy)},
        { "do-not-fragment",  CONF_TYPE_NETDEV_VXLAN, parse_yaml_bool,                offsetof(VxLan, df)},
        { "flow-label",       CONF_TYPE_NETDEV_VXLAN, parse_yaml_uint32,              offsetof(VxLan, flow_label)},
        { "notifications",    CONF_TYPE_NETDEV_VXLAN, parse_yaml_vxlan_notifications, offsetof(VxLan, l2miss)},
        { "checksums",        CONF_TYPE_NETDEV_VXLAN, parse_yaml_vxlan_csum,          offsetof(VxLan, udpcsum)},
        { "extensions",       CONF_TYPE_NETDEV_VXLAN, parse_yaml_vxlan_extensions,    offsetof(VxLan, group_policy)},
        { "port-range",       CONF_TYPE_NETDEV_VXLAN, parse_yaml_vxlan_port_range,    offsetof(VxLan, low_port)},
        { "short-circuit",    CONF_TYPE_NETDEV_VXLAN, parse_yaml_bool,                offsetof(VxLan, route_short_circuit)},
        { NULL,               _CONF_TYPE_INVALID,    0,                  0}
};

static int yaml_parse_netdev_vxlan(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        _cleanup_(vxlan_freep) VxLan *vx = NULL;
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        r = vxlan_new(&vx);
        if (r < 0)
                return log_oom();

        *network->netdev = (NetDev) {
                                 .ifname = strdup(network->ifname),
                                 .kind = YAML_NETDEV_KIND_VXLAN,
                                 .vxlan = vx,
                           };
        if (!network->netdev->ifname)
                return log_oom();

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->netdev_vxlan, scalar(k));
                if (!table) {
                        (void) parse_network(m, dp, node, network);

                        continue;
                }

                t = (uint8_t *) vx + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), vx, t, dp, v);
                        network->modified = true;
                }
        }

        steal_pointer(vx);
        return 0;
}

static ParserTable parser_wireguard_peer_vtable[] = {
        { "public",      CONF_TYPE_NETDEV_WIREGUARD, parse_yaml_string,   offsetof(WireGuardPeer, public_key)},
        { "shared",      CONF_TYPE_NETDEV_WIREGUARD, parse_yaml_string,   offsetof(WireGuardPeer, preshared_key_file)},
        { "allowed-ips", CONF_TYPE_NETDEV_WIREGUARD, parse_yaml_sequence, offsetof(WireGuardPeer, allowed_ips)},
        { "keepalive",   CONF_TYPE_NETDEV_WIREGUARD, parse_yaml_bool,     offsetof(WireGuardPeer, persistent_keep_alive)},
        { "endpoint",    CONF_TYPE_NETDEV_WIREGUARD, parse_yaml_string,   offsetof(WireGuardPeer, endpoint)},
        { NULL,          _CONF_TYPE_INVALID,    0,                  0}
};

static int yaml_parse_wireguard_peer(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, WireGuardPeer *peer) {
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        yaml_node_item_t *i;
        yaml_node_t *n;

        assert(m);
        assert(dp);
        assert(node);
        assert(peer);


        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) yaml_parse_wireguard_peer(m, dp, n, peer);
        }

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->wireguard_peer, scalar(k));
                if (!table)
                        continue;

                t = (uint8_t *) peer + table->offset;
                if (table->parser)
                        (void) table->parser(scalar(k), scalar(v), peer, t, dp, v);
        }

        return 0;
}

static ParserTable parser_wireguard_vtable[] = {
        { "key",         CONF_TYPE_NETDEV_WIREGUARD, parse_yaml_string,   offsetof(WireGuard, private_key_file)},
        { "mark",        CONF_TYPE_NETDEV_WIREGUARD, parse_yaml_uint32,   offsetof(WireGuard, fwmark)},
        { "port",        CONF_TYPE_NETDEV_WIREGUARD, parse_yaml_uint16,   offsetof(WireGuard, listen_port)},
        { NULL,          _CONF_TYPE_INVALID,    0,                  0}
};

static int yaml_parse_wireguard(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        _cleanup_(wireguard_freep) WireGuard *wg = NULL;
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        r = wireguard_new(&wg);
        if (r < 0)
                return log_oom();

        *network->netdev = (NetDev) {
                                 .ifname = strdup(network->ifname),
                                 .kind = NETDEV_KIND_WIREGUARD,
                                 .wg = wg,
                           };
        if (!network->netdev->ifname)
                return log_oom();

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->wireguard, scalar(k));
                if (!table) {
                        if (string_equal(scalar(k), "peers")) {
                                _cleanup_(wireguard_peer_freep) WireGuardPeer *peer = NULL;

                                r = wireguard_peer_new(&peer);
                                if (r < 0)
                                        return log_oom();

                                r = yaml_parse_wireguard_peer(m, dp, node, peer);
                                if (r < 0)
                                        return r;

                                wg->peers = g_list_append(wg->peers, peer);
                                steal_pointer(peer);
                        } else
                                (void) parse_network(m, dp, node, network);

                        continue;
                }

                t = (uint8_t *) wg + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), wg, t, dp, v);
                        network->modified = true;
                }
        }

        steal_pointer(wg);
        return 0;
}

int yaml_parse_netdev_config(YAMLManager *m, YAMLNetDevKind kind, yaml_document_t *dp, yaml_node_t *node, Networks *nets) {
        yaml_node_pair_t *p;
        yaml_node_t *n;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(nets);

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                _cleanup_(network_freep) Network *net = NULL;
                n = yaml_document_get_node(dp, p->key);

                r = network_new(&net);
                if (r < 0)
                        return r;

                net->parser_type = PARSER_TYPE_YAML;
                net->ifname = strdup(scalar(n));
                if (!net->ifname)
                        return log_oom();

                r = netdev_new(&net->netdev);
                if (r < 0)
                        return log_oom();

                n = yaml_document_get_node(dp, p->value);
                if (n) {
                        switch (kind) {
                                case YAML_NETDEV_KIND_VLAN:
                                        (void) yaml_parse_vlan(m, dp, n, net);
                                        break;
                                case YAML_NETDEV_KIND_BOND:
                                        (void) yaml_parse_bond(m, dp, n, net);
                                        break;
                                case YAML_NETDEV_KIND_BRIDGE:
                                        (void) yaml_parse_bridge(m, dp, n, net);
                                        break;
                                case YAML_NETDEV_KIND_TUNNEL:
                                        r = yaml_detect_tunnel_kind(dp, n);
                                        if (r < 0)
                                                return r;

                                        switch (r) {
                                                case NETDEV_KIND_VXLAN:
                                                        (void) yaml_parse_netdev_vxlan(m, dp, n, net);
                                                        break;
                                                case NETDEV_KIND_WIREGUARD:
                                                        (void) yaml_parse_wireguard(m, dp, n, net);
                                                        break;
                                                default:
                                                        (void) yaml_parse_tunnel(m, dp, n, net);
                                        }

                                        break;
                                case YAML_NETDEV_KIND_VRF:
                                        (void) yaml_parse_netdev_vrf(m, dp, n, net);
                                        break;
                                default:
                                        break;
                        }
                }

                if (!g_hash_table_insert(nets->networks, (gpointer *) net->ifname, (gpointer *) net))
                        return log_oom();

                steal_pointer(net);
        }

        return 0;
}

int yaml_register_netdev(YAMLManager *m) {
        assert(m);

        m->vlan = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->vlan)
                return log_oom();

        for (size_t i = 0; parser_vlan_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->vlan, (void *) parser_vlan_vtable[i].key, &parser_vlan_vtable[i])) {
                        log_warning("Failed add key='%s' to VLan table", parser_vlan_vtable[i].key);
                        return -EINVAL;
                }
        }

        m->bond = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->bond)
                return log_oom();

        for (size_t i = 0; parser_bond_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->bond, (void *) parser_bond_vtable[i].key, &parser_bond_vtable[i])) {
                        log_warning("Failed add key='%s' to Bond table", parser_bond_vtable[i].key);
                        return -EINVAL;
                }
        }

        m->bridge = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->bridge)
                return log_oom();

        for (size_t i = 0; parser_bridge_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->bridge, (void *) parser_bridge_vtable[i].key, &parser_bridge_vtable[i])) {
                        log_warning("Failed add key='%s' to Bridge table", parser_bridge_vtable[i].key);
                        return -EINVAL;
                }
        }

        m->tunnel = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->tunnel)
                return log_oom();

        for (size_t i = 0; parser_tunnel_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->tunnel, (void *) parser_tunnel_vtable[i].key, &parser_tunnel_vtable[i])) {
                        log_warning("Failed add key='%s' to Tunnel table", parser_tunnel_vtable[i].key);
                        return -EINVAL;
                }
        }

        m->netdev_vrf = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->netdev_vrf)
                return log_oom();

        for (size_t i = 0; parser_netdev_vrf_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->netdev_vrf, (void *) parser_netdev_vrf_vtable[i].key, &parser_netdev_vrf_vtable[i])) {
                        log_warning("Failed add key='%s' to VRF table", parser_netdev_vrf_vtable[i].key);
                        return -EINVAL;
                }
        }

        m->netdev_vxlan = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->netdev_vxlan)
                return log_oom();

        for (size_t i = 0; parser_netdev_vxlan_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->netdev_vxlan, (void *) parser_netdev_vxlan_vtable[i].key, &parser_netdev_vxlan_vtable[i])) {
                        log_warning("Failed add key='%s' to VRF table", parser_netdev_vxlan_vtable[i].key);
                        return -EINVAL;
                }
        }

        m->wireguard = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->wireguard)
                return log_oom();

        for (size_t i = 0; parser_wireguard_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->wireguard, (void *) parser_wireguard_vtable[i].key, &parser_wireguard_vtable[i])) {
                        log_warning("Failed add key='%s' to VRF table", parser_wireguard_vtable[i].key);
                        return -EINVAL;
                }
        }

        m->wireguard_peer = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->wireguard_peer)
                return log_oom();

        for (size_t i = 0; parser_wireguard_peer_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->wireguard_peer, (void *) parser_wireguard_peer_vtable[i].key, &parser_wireguard_peer_vtable[i])) {
                        log_warning("Failed add key='%s' to VRF table", parser_wireguard_peer_vtable[i].key);
                        return -EINVAL;
                }
        }


        return 0;
}

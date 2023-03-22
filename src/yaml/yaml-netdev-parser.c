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

static ParserTable parser_netdev_bond_vtable[] = {
        { "interfaces", CONF_TYPE_NETDEV_BOND, parse_yaml_sequence,  offsetof(Bond, interfaces)},
        { "mode",       CONF_TYPE_NETDEV_BOND, parse_yaml_bond_mode, offsetof(Bond, mode)},
        { NULL,         _CONF_TYPE_INVALID,    0,                    0}
};

static int yaml_yaml_parse_netdev_bond_parameters(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Bond *bond) {
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
                        (void) yaml_yaml_parse_netdev_bond_parameters(m, dp, n, bond);
        }

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->netdev_bond, scalar(k));
                if (!table)
                        continue;

                t = (uint8_t *) bond + table->offset;
                if (table->parser)
                        (void) table->parser(scalar(k), scalar(v), bond, t, dp, v);
        }

        return 0;
}

static int yaml_parse_netdev_bond(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
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

                table = g_hash_table_lookup(m->netdev_bond, scalar(k));
                if (!table) {
                        if (string_equal(scalar(k), "parameters"))
                                yaml_yaml_parse_netdev_bond_parameters(m, dp, v, bond);
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

static ParserTable parser_netdev_bridge_vtable[] = {
        { "interfaces", CONF_TYPE_NETDEV_BRIDGE, parse_yaml_sequence,  offsetof(Bridge, interfaces)},
        { NULL,         _CONF_TYPE_INVALID,    0,                  0}
};

static int yaml_parse_netdev_bridge(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
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

                table = g_hash_table_lookup(m->netdev_bridge, scalar(k));
                if (!table) {
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

static ParserTable parser_netdev_vlan_vtable[] = {
        { "id",   CONF_TYPE_NETDEV_VLAN, parse_yaml_uint32,  offsetof(VLan, id)},
        { "link", CONF_TYPE_NETDEV_VLAN, parse_yaml_string,  offsetof(VLan, master)},
        { NULL,   _CONF_TYPE_INVALID,    0,                  0}
};

static int yaml_parse_netdev_vlan(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
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

                table = g_hash_table_lookup(m->netdev_vlan, scalar(k));
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

static ParserTable parser_netdev_tunnel_vtable[] = {
        { "local",  CONF_TYPE_NETDEV_TUNNEL, parse_yaml_address, offsetof(Tunnel, local)},
        { "remote", CONF_TYPE_NETDEV_TUNNEL, parse_yaml_address, offsetof(Tunnel, remote)},
        { "key",    CONF_TYPE_NETDEV_TUNNEL, parse_yaml_uint32,  offsetof(Tunnel, key)},
        { "input",  CONF_TYPE_NETDEV_TUNNEL, parse_yaml_uint32,  offsetof(Tunnel, ikey)},
        { "output", CONF_TYPE_NETDEV_TUNNEL, parse_yaml_uint32,  offsetof(Tunnel, okey)},
        { "ttl",    CONF_TYPE_NETDEV_TUNNEL, parse_yaml_uint32,  offsetof(Tunnel, ttl)},
        { NULL,     _CONF_TYPE_INVALID,      0,                  0}
};

static int yaml_parse_netdev_tunnel_keys(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Tunnel *tnl) {
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
                        (void) yaml_parse_netdev_tunnel_keys(m, dp, n, tnl);
        }

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                table = g_hash_table_lookup(m->netdev_tunnel, scalar(k));
                if (!table)
                        continue;

                t = (uint8_t *) tnl + table->offset;
                if (table->parser)
                        (void) table->parser(scalar(k), scalar(v), tnl, t, dp, v);
        }

        return 0;
}

static int yaml_parse_netdev_tunnel(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
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

                table = g_hash_table_lookup(m->netdev_tunnel, scalar(k));
                if (!table) {
                        if (string_equal(scalar(k), "mode")) {
                                r = netdev_name_to_kind(scalar(v));
                                if (r < 0) {
                                        log_warning("Failed to parse tunnel mode = %s", scalar(v));
                                        return -EINVAL;
                                }
                                network->netdev->kind = r;
                        } else if (string_equal(scalar(k), "keys"))
                                yaml_parse_netdev_tunnel_keys(m, dp, v, tnl);
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
                                        (void) yaml_parse_netdev_vlan(m, dp, n, net);
                                        break;
                                case YAML_NETDEV_KIND_BOND:
                                        (void) yaml_parse_netdev_bond(m, dp, n, net);
                                        break;
                                case YAML_NETDEV_KIND_BRIDGE:
                                        (void) yaml_parse_netdev_bridge(m, dp, n, net);
                                        break;
                                case YAML_NETDEV_KIND_TUNNEL:
                                        (void) yaml_parse_netdev_tunnel(m, dp, n, net);
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

        m->netdev_vlan = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->netdev_vlan)
                return log_oom();

        for (size_t i = 0; parser_netdev_vlan_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->netdev_vlan, (void *) parser_netdev_vlan_vtable[i].key, &parser_netdev_vlan_vtable[i])) {
                        log_warning("Failed add key='%s' to VLan table", parser_netdev_vlan_vtable[i].key);
                        return -EINVAL;
                }
        }

        m->netdev_bond = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->netdev_bond)
                return log_oom();

        for (size_t i = 0; parser_netdev_bond_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->netdev_bond, (void *) parser_netdev_bond_vtable[i].key, &parser_netdev_bond_vtable[i])) {
                        log_warning("Failed add key='%s' to Bond table", parser_netdev_bond_vtable[i].key);
                        return -EINVAL;
                }
        }

        m->netdev_bridge = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->netdev_bridge)
                return log_oom();

        for (size_t i = 0; parser_netdev_bridge_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->netdev_bridge, (void *) parser_netdev_bridge_vtable[i].key, &parser_netdev_bridge_vtable[i])) {
                        log_warning("Failed add key='%s' to Bridge table", parser_netdev_bridge_vtable[i].key);
                        return -EINVAL;
                }
        }

        m->netdev_tunnel = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->netdev_tunnel)
                return log_oom();

        for (size_t i = 0; parser_netdev_tunnel_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->netdev_tunnel, (void *) parser_netdev_tunnel_vtable[i].key, &parser_netdev_tunnel_vtable[i])) {
                        log_warning("Failed add key='%s' to Tunnel table", parser_netdev_tunnel_vtable[i].key);
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

        return 0;
}

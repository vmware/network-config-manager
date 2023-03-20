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

static ParserTable parser_netdev_vlan_vtable[] = {
        { "id",   CONF_TYPE_NETDEV_VLAN, parse_yaml_uint32,  offsetof(VLan, id)},
        { NULL,   _CONF_TYPE_INVALID,    0,                  0}
};

static int parse_netdev_vlan_config(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        _auto_cleanup_ VLan *vlan = NULL;
        yaml_node_t *k, *v;
        yaml_node_pair_t *p;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        r = netdev_new(&network->netdev);
        if (r < 0)
                return log_oom();

        r = vlan_new(&vlan);
        if (r < 0)
                return log_oom();

        *network->netdev = (NetDev) {
                           .ifname = strdup(network->ifname),
                           .kind = NETDEV_KIND_VLAN,
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

                table = g_hash_table_lookup(m->netdev_vlan_config, scalar(k));
                if (!table) {
                        if (string_equal(scalar(k), "link")) {
                                network->netdev->master = strdup(scalar(v));
                                if (!network->netdev->master)
                                        return log_oom();
                        } else
                                (void) parse_network_config(m, dp, node, network);

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

int parse_netdev_config(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Networks *nets) {
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

                n = yaml_document_get_node(dp, p->value);
                if (n)
                        (void) parse_netdev_vlan_config(m, dp, n, net);

                if (!g_hash_table_insert(nets->networks, (gpointer *) net->ifname, (gpointer *) net))
                        return log_oom();

                steal_pointer(net);
        }

        return 0;
}

int yaml_register_netdev(YAMLManager *m) {
        assert(m);

        m->netdev_vlan_config = g_hash_table_new(g_str_hash, g_str_equal);
        if (!m->netdev_vlan_config)
                return log_oom();

        for (size_t i = 0; parser_netdev_vlan_vtable[i].key; i++) {
               if (!g_hash_table_insert(m->netdev_vlan_config, (void *) parser_netdev_vlan_vtable[i].key, &parser_netdev_vlan_vtable[i])) {
                        log_warning("Failed add key='%s' to VLan table", parser_netdev_vlan_vtable[i].key);
                        return -EINVAL;
                }
        }

        return 0;
}

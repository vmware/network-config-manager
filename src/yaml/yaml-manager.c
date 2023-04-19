/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "yaml-manager.h"
#include "yaml-network-parser.h"
#include "yaml-netdev-parser.h"
#include "yaml-link-parser.h"
#include "alloc-util.h"
#include "string-util.h"
#include "log.h"

static int yaml_parse_node(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Networks *networks) {
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(networks);

        switch (node->type) {
        case YAML_NO_NODE:
        case YAML_SCALAR_NODE:
                break;
        case YAML_SEQUENCE_NODE: {
                for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                        yaml_node_t *n = yaml_document_get_node(dp, *i);
                        if (n)
                                (void) yaml_parse_node(m, dp, n, networks);
                }
        }
                break;
        case YAML_MAPPING_NODE:
                for (yaml_node_pair_t *p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                        yaml_node_t *n = yaml_document_get_node(dp, p->key);

                        if (str_eq(scalar(n), "ethernets")) {
                                n = yaml_document_get_node(dp, p->value);
                                if (n)
                                        (void) parse_ethernet_config(m, dp, n, networks);
                        } else if (is_yaml_netdev_kind(scalar(n))) {
                                YAMLNetDevKind kind = yaml_netdev_name_to_kind(scalar(n));

                                n = yaml_document_get_node(dp, p->value);
                                if (n) {
                                        r = yaml_parse_netdev_config(m, kind, dp, n, networks);
                                        if (r < 0)
                                                return r;
                                }
                        } else {
                                n = yaml_document_get_node(dp, p->value);
                                if (n)
                                        (void) yaml_parse_node(m, dp, n, networks);
                        }
                }
                break;
                default:
                        log_warning("Failed to parse node type: '%d'", node->type);
                        break;
        }

        return 0;
}

static int yaml_parse_document(YAMLManager *m, yaml_document_t *dp, Networks *n) {
        return yaml_parse_node(m, dp, yaml_document_get_root_node(dp), n);
}

int yaml_parse_file(const char *file, Networks **n) {
        _cleanup_(yaml_manager_freep) YAMLManager *m = NULL;
        _cleanup_(networks_freep) Networks *networks = NULL;
        _auto_cleanup_fclose_ FILE *f = NULL;
        yaml_document_t document;
        yaml_parser_t parser;
        bool done = false;
        int r = 0;

        assert(file);
        assert(n);

        r = yaml_manager_new(&m);
        if (r < 0)
                return r;

        f = fopen(file, "r");
        if (!f) {
                log_warning("Failed to open yaml config file: %s", file);
                return -errno;
        }

        assert(yaml_parser_initialize(&parser));
        yaml_parser_set_input_file(&parser, f);

        r = networks_new(&networks);
        if (r < 0)
                return r;

        for (;!done;) {
                if (!yaml_parser_load(&parser, &document)) {
                        r = -EINVAL;
                        break;
                }

                done = !yaml_document_get_root_node(&document);
                if (!done)
                        r = yaml_parse_document(m, &document, networks);

                yaml_document_delete(&document);
        }

        yaml_parser_delete(&parser);
        if (r >= 0)
                *n = steal_pointer(networks);

        return r;
}

void networks_free(Networks *n) {
        if (!n)
                return;

        g_hash_table_unref(n->networks);
        free(n);
}

int networks_new(Networks **ret) {
        _auto_cleanup_ Networks *n = NULL;

        n = new0(Networks, 1);
        if (!n)
                return log_oom();

        n->networks = g_hash_table_new(g_str_hash, g_str_equal);
        if (!n->networks)
             return log_oom();

        *ret = steal_pointer(n);
        return 0;
}

void yaml_manager_free(YAMLManager *p) {
       if (!p)
                return;

        g_hash_table_destroy(p->match);
        g_hash_table_destroy(p->network);
        g_hash_table_destroy(p->address);
        g_hash_table_destroy(p->route);
        g_hash_table_destroy(p->routing_policy_rule);
        g_hash_table_destroy(p->dhcp4);
        g_hash_table_destroy(p->dhcp6);
        g_hash_table_destroy(p->nameserver);
        g_hash_table_destroy(p->router_advertisement);
        g_hash_table_destroy(p->dhcp4_server);
        g_hash_table_destroy(p->dhcp4_server_static_lease);
        g_hash_table_destroy(p->sriovs);

        g_hash_table_destroy(p->link);

        g_hash_table_destroy(p->vlan);
        g_hash_table_destroy(p->macvlan);
        g_hash_table_destroy(p->vxlan);
        g_hash_table_destroy(p->vrf);
        g_hash_table_destroy(p->bond);
        g_hash_table_destroy(p->bridge);
        g_hash_table_destroy(p->tunnel);
        g_hash_table_destroy(p->wireguard);
        g_hash_table_destroy(p->wireguard_peer);

        free(p);
}

int yaml_manager_new(YAMLManager **ret) {
        _cleanup_(yaml_manager_freep) YAMLManager *m = NULL;
        int r;

        m = new(YAMLManager, 1);
        if (!m)
                return log_oom();

        *m = (YAMLManager) {
                 .match = g_hash_table_new(g_str_hash, g_str_equal),
                 .network = g_hash_table_new(g_str_hash, g_str_equal),
                 .address = g_hash_table_new(g_str_hash, g_str_equal),
                 .route = g_hash_table_new(g_str_hash, g_str_equal),
                 .routing_policy_rule = g_hash_table_new(g_str_hash, g_str_equal),
                 .dhcp4 = g_hash_table_new(g_str_hash, g_str_equal),
                 .dhcp6 = g_hash_table_new(g_str_hash, g_str_equal),
                 .router_advertisement = g_hash_table_new(g_str_hash, g_str_equal),
                 .nameserver = g_hash_table_new(g_str_hash, g_str_equal),
                 .dhcp4_server = g_hash_table_new(g_str_hash, g_str_equal),
                 .dhcp4_server_static_lease = g_hash_table_new(g_str_hash, g_str_equal),
                 .sriovs = g_hash_table_new(g_str_hash, g_str_equal),
        };

        if (!m->network || !m->address || !m->dhcp4 || !m->dhcp6 || !m->nameserver || !m->route || !m->routing_policy_rule ||
            !m->nameserver || !m->router_advertisement || !m->dhcp4_server || !m->dhcp4_server_static_lease || !m->sriovs)
                return log_oom();

        r = yaml_register_network(m);
        if (r < 0)
                return r;

        r = yaml_register_link(m);
        if (r < 0)
                return r;

        r = yaml_register_netdev(m);
        if (r < 0)
                return r;

        *ret = steal_pointer(m);
        return 0;
}

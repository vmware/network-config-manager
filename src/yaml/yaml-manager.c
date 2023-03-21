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

static int parse_yaml_node(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Networks *networks) {
        yaml_node_item_t *i;
        yaml_node_pair_t *p;
        yaml_node_t *n;

        assert(m);
        assert(dp);
        assert(node);
        assert(networks);

        switch (node->type) {
        case YAML_NO_NODE:
        case YAML_SCALAR_NODE:
                break;
        case YAML_SEQUENCE_NODE: {
                for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                        n = yaml_document_get_node(dp, *i);
                        if (n)
                                (void) parse_yaml_node(m, dp, n, networks);
                }
        }
                break;
        case YAML_MAPPING_NODE:
                for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                        n = yaml_document_get_node(dp, p->key);

                        if (string_equal(scalar(n), "ethernets")) {
                                n = yaml_document_get_node(dp, p->value);
                                if (n)
                                        (void) parse_ethernet_config(m, dp, n, networks);
                        } else if (string_equal(scalar(n), "vlans") || string_equal(scalar(n), "bonds")) {
                                YAMLNetDevKind kind = yaml_netdev_name_to_kind(scalar(n));

                                n = yaml_document_get_node(dp, p->value);
                                if (n)
                                        (void) parse_netdev_config(m, kind, dp, n, networks);
                        } else {
                                n = yaml_document_get_node(dp, p->value);
                                if (n)
                                        (void) parse_yaml_node(m, dp, n, networks);
                        }
                }
                break;
                default:
                        log_warning("Failed to parse node type: '%d'", node->type);
                        break;
        }

        return 0;
}

static int parse_yaml_document(YAMLManager *m, yaml_document_t *dp, Networks *n) {
        return parse_yaml_node(m, dp, yaml_document_get_root_node(dp), n);
}

int parse_yaml_file(const char *file, Networks **n) {
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
                        r = parse_yaml_document(m, &document, networks);

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

        g_hash_table_destroy(p->match_config);
        g_hash_table_destroy(p->network_config);
        g_hash_table_destroy(p->address_config);
        g_hash_table_destroy(p->route_config);
        g_hash_table_destroy(p->routing_policy_rule_config);
        g_hash_table_destroy(p->dhcp4_config);
        g_hash_table_destroy(p->dhcp6_config);
        g_hash_table_destroy(p->nameserver_config);

        g_hash_table_destroy(p->link_config);

        g_hash_table_destroy(p->netdev_vlan_config);
        g_hash_table_destroy(p->netdev_bond_config);

        free(p);
}

int yaml_manager_new(YAMLManager **ret) {
        _cleanup_(yaml_manager_freep) YAMLManager *m = NULL;
        int r;

        m = new(YAMLManager, 1);
        if (!m)
                return log_oom();

        *m = (YAMLManager) {
                 .match_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .network_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .address_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .route_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .routing_policy_rule_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .dhcp4_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .dhcp6_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .nameserver_config = g_hash_table_new(g_str_hash, g_str_equal),
        };

        if (!m->network_config || !m->address_config || !m->dhcp4_config ||
            !m->dhcp6_config || !m->nameserver_config || !m->route_config || !m->routing_policy_rule_config ||
            !m->nameserver_config)
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

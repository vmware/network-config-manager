/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "network-manager.h"
#include "network.h"
#include "networkd-api.h"
#include "parse-util.h"
#include "string-util.h"
#include "yaml-network-parser.h"
#include "yaml-link-parser.h"
#include "yaml-parser.h"

static int parse_link_config(YAMLManager *m, yaml_document_t *doc, yaml_node_t *node, NetDevLink *link) {
        yaml_node_pair_t *entry;

        assert(m);
        assert(doc);
        assert(node);

        for (entry = node->data.mapping.pairs.start; entry < node->data.mapping.pairs.top; entry++) {
                yaml_node_t *key, *value;
                ParserTable *p;
                void *v;

                key = yaml_document_get_node(doc, entry->key);
                value = yaml_document_get_node(doc, entry->value);

                p = g_hash_table_lookup(m->link_config, scalar(key));
                if (!p)
                        continue;

                v = (uint8_t *) link + p->offset;
                if (p->parser)
                        (void) p->parser(scalar(key), scalar(value), link, v, doc, value);
        }

        return true;
}

static int parse_link_yaml_node(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, NetDevLink *link) {
        yaml_node_item_t *i;
        yaml_node_pair_t *p;
        yaml_node_t *n;

        assert(m);
        assert(dp);
        assert(node);
        assert(link);

        switch (node->type) {
        case YAML_NO_NODE:
        case YAML_SCALAR_NODE:
                break;
        case YAML_SEQUENCE_NODE: {
                for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                        n = yaml_document_get_node(dp, *i);
                        if (n)
                                (void) parse_link_yaml_node(m, dp, n, link);
                }
        }
                break;
        case YAML_MAPPING_NODE:
                (void) parse_link_config(m, dp, node, link);

                for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                        n = yaml_document_get_node(dp, p->key);
                        if (n)
                                (void) parse_link_yaml_node(m, dp, n, link);

                        n = yaml_document_get_node(dp, p->value);
                        if (n)
                                (void) parse_link_yaml_node(m, dp, n, link);
                }
                break;
        default:
                log_warning("Failed to parse node type: '%d'", node->type);
                break;
        }

        return 0;
}

static int parse_link_yaml_document(YAMLManager *m, yaml_document_t *dp, NetDevLink *link) {
        assert(m);
        assert(dp);
        assert(link);

        return parse_link_yaml_node(m, dp, yaml_document_get_root_node(dp), link);
}

int parse_yaml_link_file(const char *yaml_file, NetDevLink **ret) {
        _cleanup_(yaml_manager_unrefp) YAMLManager *m = NULL;
        _cleanup_(netdev_link_unrefp) NetDevLink *link = NULL;
        _auto_cleanup_fclose_ FILE *f = NULL;
        yaml_document_t document;
        yaml_parser_t parser;
        bool done = false;
        int r = 0;

        assert(yaml_file);
        assert(ret);

        r = new_yaml_manager(&m);
        if (r < 0)
                return r;

        f = fopen(yaml_file, "r");
        if (!f) {
                log_warning("Failed to open yaml config file: %s", yaml_file);
                return -errno;
        }

        assert(yaml_parser_initialize(&parser));
        yaml_parser_set_input_file(&parser, f);

        r = netdev_link_new(&link);
        if (r < 0)
                return r;

        link->parser_type = PARSER_TYPE_YAML;

        for (;!done;) {
                if (!yaml_parser_load(&parser, &document)) {
                        r = -EINVAL;
                        break;
                }

                done = !yaml_document_get_root_node(&document);
                if (!done)
                        r = parse_link_yaml_document(m, &document, link);

                yaml_document_delete(&document);
        }

        yaml_parser_delete(&parser);

        if (r >= 0)
                *ret = steal_pointer(link);

        return r;
}

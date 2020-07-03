/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <assert.h>
#include <glib.h>
#include <net/if.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <yaml.h>

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
#include "yaml-parser.h"

int parse_yaml_bool(const char *key,
                    const char *value,
                    void *data,
                    void *userdata,
                    yaml_document_t *doc,
                    yaml_node_t *node) {
        int *p;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = userdata;

        r = parse_boolean(value);
        if (r < 0)
                return r;

        *p = r;

        return 0;
}

int parse_yaml_uint32(const char *key,
                      const char *value,
                      void *data,
                      void *userdata,
                      yaml_document_t *doc,
                      yaml_node_t *node) {
        uint32_t *p, k;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = userdata;

        r = parse_integer(value, (int *) &k);
        if (r < 0) {
                log_warning("Failed to parse MTU: %s", value);
                return r;
        }

        *p = k;

        return 0;
}

int parse_yaml_mac_address(const char *key,
                           const char *value,
                           void *data,
                           void *userdata,
                           yaml_document_t *doc,
                           yaml_node_t *node) {
        char **mac;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        mac = (char **) userdata;

        if (!parse_ether_address(value)) {
                log_warning("Failed to parse MAC address: %s", value);
                return -EINVAL;
        }

        *mac =  g_strdup(value);
        if (!*mac)
                return log_oom();

        return 0;
}

int parse_yaml_string(const char *key,
                      const char *value,
                      void *data,
                      void *userdata,
                      yaml_document_t *doc,
                      yaml_node_t *node) {
        char **p;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = (char **) userdata;

        *p = g_strdup(value);
        if (!*p)
                return log_oom();

        return 0;
}

int parse_yaml_auth_key_management_type(const char *key,
                                        const char *value,
                                        void *data,
                                        void *userdata,
                                        yaml_document_t *doc,
                                        yaml_node_t *node) {
        WiFiAccessPoint *p;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = data;
        p->auth->eap_method = auth_key_management_type_to_mode(value);

        return 0;
}

int parse_yaml_auth_eap_method(const char *key,
                               const char *value,
                               void *data,
                               void *userdata,
                               yaml_document_t *doc,
                               yaml_node_t *node) {
        WiFiAccessPoint *p;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = data;

        p->auth->key_management = auth_key_management_type_to_mode(key);
        switch (p->auth->key_management) {
        case AUTH_KEY_MANAGEMENT_NONE:
                p->auth->password = g_strdup(value);
                if (!p->auth->password)
                        return log_oom();
                break;
        case AUTH_KEY_MANAGEMENT_WPA_PSK:
                p->auth->password = g_strdup(value);
                if (!p->auth->password)
                        return log_oom();
                break;
        default:
                break;
        }

        return 0;
}

int parse_yaml_dhcp_client_identifier(const char *key,
                                      const char *value,
                                      void *data,
                                      void *userdata,
                                      yaml_document_t *doc,
                                      yaml_node_t *node) {
        Network *n;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        n->dhcp_client_identifier_type = dhcp_client_identifier_to_mode((char *) value);

        return 0;
}

int parse_yaml_dhcp_type(const char *key,
                         const char *value,
                         void *data,
                         void *userdata,
                         yaml_document_t *doc,
                         yaml_node_t *node) {
        Network *n;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        n->dhcp_type = dhcp_name_to_mode((char *) value);

        return 0;
}

int parse_yaml_link_local_type(const char *key,
                               const char *value,
                               void *data,
                               void *userdata,
                               yaml_document_t *doc,
                               yaml_node_t *node) {
        Network *n;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        n->link_local = link_local_address_type_to_mode((const char *) value);

        return 0;
}

int parse_yaml_address(const char *key,
                       const char *value,
                       void *data,
                       void *userdata,
                       yaml_document_t *doc,
                       yaml_node_t *node) {
        _auto_cleanup_ IPAddress *address = NULL;
        IPAddress **p = NULL;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        p = (IPAddress **) userdata;

        r = parse_ip_from_string(value, &address);
        if (r < 0) {
                log_warning("Failed to parse address : %s", value);
                return r;
        }

        *p = address;
        address = NULL;

        return 0;
}

int parse_yaml_addresses(const char *key,
                         const char *value,
                         void *data,
                         void *userdata,
                         yaml_document_t *doc,
                         yaml_node_t *node) {
        yaml_node_item_t *i;
        Network *network;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        network = data;
        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                if (string_equal("addresses", key))
                        r = parse_address_from_string_and_add(scalar(entry), network->addresses);
                else if (string_equal("nameservers", key))
                        r = parse_address_from_string_and_add(scalar(entry), network->nameservers);
                else if (string_equal("ntps", key))
                        r = parse_address_from_string_and_add(scalar(entry), network->ntps);
                else
                        continue;

                if (r < 0 && r != -EEXIST)
                        return r;
        }

        return 0;
}

int parse_yaml_routes(const char *key,
                      const char *value,
                      void *data,
                      void *userdata,
                      yaml_document_t *doc,
                      yaml_node_t *node) {
        _auto_cleanup_ IPAddress *address = NULL;
        static Route *route;
        Network *network;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        network = data;

        if (string_equal("to", key) || string_equal("via", key)) {
                r = parse_ip_from_string(value, &address);
                if (r < 0) {
                        log_warning("Failed to parse route address : %s", value);
                        return r;
                }

                if (string_equal("to", key)) {
                        if (!network->routes)
                                network->routes = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

                        r = route_new(&route);
                        if (r < 0)
                                return r;

                        route->destination = *address;

                        if (!g_hash_table_insert(network->routes, GUINT_TO_POINTER(route), route)) {
                                log_warning("Failed to add route: %s", value);
                                return false;
                        }
                } else
                        route->gw = *address;
        }

        if (string_equal("metric", key))
                parse_uint32(value, &route->metric);

        return 0;
}

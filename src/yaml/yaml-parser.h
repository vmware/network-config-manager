/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <yaml.h>

typedef enum ConfType {
        CONF_TYPE_NETWORK,
        CONF_TYPE_NETDEV,
        CONF_TYPE_WIFI,
        CONF_TYPE_ROUTE,
        CONF_TYPE_ROUTING_POLICY_RULE,
        CONF_TYPE_LINK,
        CONF_TYPE_NETDEV_VLAN,
        CONF_TYPE_NETDEV_BRIDGE,
        CONF_TYPE_NETDEV_BOND,
        CONF_TYPE_NETDEV_TUNNEL,
        CONF_TYPE_NETDEV_VRF,
        CONF_TYPE_NETDEV_VXLAN,
        CONF_TYPE_NETDEV_WIREGUARD,
        _CONF_TYPE_MAX,
        _CONF_TYPE_INVALID = -1,
} ConfType;

typedef struct ParserTable {
        const char *key;
        ConfType type;
        int (*parser) (const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
        const size_t offset;
} ParserTable;

int parse_yaml_bool(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_uint32(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_uint16(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_uint32_or_max(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_mac_address(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_string(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_scalar_or_sequence(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_sequence(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);

int parse_yaml_route(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_route_type(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_route_scope(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);

int parse_yaml_auth_key_management_type(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_auth_eap_method(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);

int parse_yaml_dhcp_client_identifier(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_dhcp_type(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_addresses(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_address(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_nameserver_addresses(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_domains(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_link_local_type(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_ipv6_address_generation_mode(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_ipv6_privacy_extensions(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_rf_online(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_activation_policy(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);

int parse_yaml_bond_mode(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);
int parse_yaml_vxlan_notifications(const char *key, const char *value, void *data, void *userdata, yaml_document_t *doc, yaml_node_t *node);

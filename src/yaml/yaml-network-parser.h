/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <yaml.h>

#include "yaml-manager.h"
#include "network.h"
#include "yaml-link-parser.h"

int yaml_network_new(const char *ifname, Network **ret);
int yaml_register_network(YAMLManager *p);

int parse_ethernet_config(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Networks *nets);
int parse_network(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network);

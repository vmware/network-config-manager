/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <yaml.h>

#include "yaml-manager.h"

int yaml_register_link(YAMLManager *m);

int yaml_parse_link_parameters(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network);
int parse_link(YAMLManager *m, yaml_document_t *dp, yaml_node_t *k, yaml_node_t *v, Network *network);

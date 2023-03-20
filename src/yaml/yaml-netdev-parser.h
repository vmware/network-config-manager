/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <yaml.h>

#include "yaml-manager.h"

int yaml_register_netdev(YAMLManager *p);

int parse_netdev_config(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Networks *nets);

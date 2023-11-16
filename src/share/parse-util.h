/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

int parse_int(const char *c, int *val);
int parse_uint64(const char *c, uint64_t *val);
int parse_uint32(const char *c, uint32_t *val);
int parse_uint16(const char *c, uint16_t *val);
int parse_link_queue(const char *c, unsigned *ret);
int parse_link_gso(const char *c, unsigned *ret);
int parse_link_macpolicy(const char *c);
int parse_link_namepolicy(const char *c);
int parse_link_name(const char *c);
int parse_link_altnamepolicy(const char *c);
int parse_link_bytes(const char *c);
int parse_link_duplex(const char *c);
int parse_link_wakeonlan(const char *c);
int parse_link_port(const char *c);
int parse_link_advertise(const char *c);
int parse_link_alias(const char *c);

int parse_bool(const char *v);
const char *parse_bool_or_ip_family(const char *v);

bool is_port_or_range(const char *c);
bool is_uint32_or_max(const char *c);

int parse_sriov_vlan_protocol(const char *c);


bool valid_address_label(char *c);

/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

void test_set_static_address_gw(void **state);
void test_set_static_address_gw_dns(void **state);
void test_set_static_address_gw_dns_keep_yes(void **state);
void test_set_dynamic_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier(void **state);
void test_set_dynamic_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier_dhcp_iaid(void **state);

void test_set_network_address_gw(void **state);
void test_set_network_address_gw_dns(void **state);
void test_set_network_address_gw_dns_keep_yes(void **state);

void test_set_network_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier_dhcp_iaid_static_address_gw_dns(void **state);

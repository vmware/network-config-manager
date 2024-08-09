/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

void test_set_ipv4_dhcp_yes_with_static(void **state);
void test_set_ipv4_dhcp_no_with_static(void **state);
void test_set_ipv4_dhcp_yes_with_static_address_static_dns(void **state);
void test_set_ipv4_dhcp_yes_with_static_address_static_dns_use_dns_no(void **state);
void test_set_ipv4_dhcp_yes_with_static_remove_static_automatic(void **state);
void test_set_ipv6_dhcp_yes_with_static_remove_static_automatic(void **state);
void test_set_ipv6_dhcp_no_with_static_remove_static_automatic(void **state);

void test_set_ipv6_dhcp_yes_accept_ra_yes(void **state);
void test_set_ipv6_dhcp_no_accept_ra_yes(void **state);

void test_set_static_address_gw(void **state);
void test_set_static_address_gw_dns(void **state);
void test_set_static_address_gw_dns_keep_yes(void **state);
void test_set_dynamic_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier(void **state);
void test_set_dynamic_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier_dhcp_iaid(void **state);

void test_set_network_address_gw(void **state);
void test_set_network_address_gw_dns(void **state);
void test_set_network_address_gw_dns_keep_yes(void **state);

void test_set_network_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier_dhcp_iaid(void **state);
void test_set_network_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier(void **state);
void test_set_network_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier_dhcp_iaid_static_address_gw_dns(void **state);


/* vami test cases */
void test_vami_set_network_autov6(void **state);
void test_vami_set_network_dhcpv4(void **state);
void test_vami_set_network_dhcpv6(void **state);
void test_vami_set_network_dhcpv4_and_dhcpv6(void **state);
void test_vami_set_network_ipv4_static_address_gw(void **state);
void test_vami_set_network_ipv6_static_address_gw(void **state);
void test_vami_set_network_ipv4_ipv6_static_address_gw(void **state);
void test_vami_set_network_dhcpv4_ipv6_static_address_gw(void **state);
void test_vami_set_network_static_ipv4_dhcp6(void **state);
void test_vami_set_network_dhcp4_autov6(void **state);
void test_vami_set_network_static_ipv4_autov6(void **state);

/* with set-static and set-dynamic */
void test_vami_set_dynamic_autov6(void **state);
void test_vami_set_dynamic_dhcpv4(void **state);
void test_vami_set_dynamic_dhcpv6(void **state);
void test_vami_set_dynamic_dhcpv4_and_dhcpv6(void **state);
void test_vami_set_dynamic_ipv4_static_address_gw(void **state);
void test_vami_set_static_ipv6_static_address_gw(void **state);
void test_vami_set_static_ipv4_ipv6_static_address_gw(void **state);

/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once


int network_parse_string(const char *key, char **state);
int network_parse_operational_state(char **state);
int network_parse_dns(char ***ret);
int network_parse_ntp(char ***ret);
int network_parse_search_domains(char ***ret);
int network_parse_route_domains(char ***ret);

int network_parse_link_setup_state(int ifindex, char **state);
int network_parse_link_network_file(int ifindex, char **filename);
int network_parse_link_address_state(int ifindex, char **state);
int network_parse_link_ipv4_state(int ifindex, char **state);
int network_parse_link_ipv6_state(int ifindex, char **state);
int network_parse_link_online_state(int ifindex, char **state);
int network_parse_link_required_for_online(int ifindex, char **state);
int network_parse_link_device_activation_policy(int ifindex, char **state);
int network_parse_link_operational_state(int ifindex, char **state);
int network_parse_link_llmnr(int ifindex, char **llmnr);
int network_parse_link_mdns(int ifindex, char **mdns);
int network_parse_link_dnssec(int ifindex, char **dnssec);
int network_parse_link_dnssec_negative_trust_anchors(int ifindex, char **nta);
int network_parse_link_timezone(int ifindex, char **ret);

int network_parse_link_dns(int ifindex, char ***ret);
int network_parse_link_ntp(int ifindex, char ***ret);
int network_parse_link_search_domains(int ifindex, char ***ret);
int network_parse_link_route_domains(int ifindex, char ***ret);
int network_parse_link_addresses(int ifindex, char ***ret);
int network_parse_link_dhcp6_client_duid(int ifindex, char **ret);
int network_parse_link_dhcp6_client_iaid(int ifindex, char **ret);

int network_parse_link_dhcp4_address(int ifindex, char **ret);
int network_parse_link_dhcp4_server_address(int ifindex, char **ret);
int network_parse_link_dhcp4_router(int ifindex, char **ret);
int network_parse_link_dhcp4_client_id(int ifindex, char **ret);
int network_parse_link_dhcp4_address_lifetime(int ifindex, char **ret);
int network_parse_link_dhcp4_address_lifetime_t1(int ifindex, char **ret);
int network_parse_link_dhcp4_address_lifetime_t2(int ifindex, char **ret);
int network_parse_link_dhcp4_dns(int ifindex, char ***ret);
int network_parse_link_dhcp4_search_domains(int ifindex, char ***ret);
int network_parse_link_dhcp4_ntp(int ifindex, char ***ret);

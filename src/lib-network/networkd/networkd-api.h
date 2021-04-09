/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2021 VMware, Inc.
 */

#pragma once

int network_parse_operational_state(char **state);
int network_parse_dns(char ***ret);
int network_parse_ntp(char ***ret);
int network_parse_search_domains(char ***ret);
int network_parse_route_domains(char ***ret);

int network_parse_link_setup_state(int ifindex, char **state);
int network_parse_link_network_file(int ifindex, char **filename);
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
int network_parse_link_dhcp4_addresses(int ifindex, char ***ret);

/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include <stdarg.h>

int add_dns_domains(int argc, char *argv[]);
int add_dns_server(int argc, char *argv[]);
int cli_run(int argc, char *argv[]);
int generate_networkd_config_from_command_line(int argc, char *argv[]);
int generate_networkd_config_from_yaml(int argc, char *argv[]);
int link_add_address(int argc, char *argv[]);
int link_add_default_gateway(int argc, char *argv[]);
int link_add_ntp(int argc, char *argv[]);
int link_add_route(int argc, char *argv[]);
int link_delete_address(int argc, char *argv[]);
int link_delete_gateway_or_route(int argc, char *argv[]);
int link_enable_ipv6(int argc, char *argv[]);
int link_reconfigure(int argc, char *argv[]);
int link_set_dhcp4_client_identifier(int argc, char *argv[]);
int link_set_dhcp4_section(int argc, char *argv[]);
int link_set_dhcp6_section(int argc, char *argv[]);
int link_set_dhcp_client_duid(int argc, char *argv[]);
int link_set_dhcp_client_iaid(int argc, char *argv[]);
int link_set_dhcp_mode(int argc, char *argv[]);
int link_set_mac(int argc, char *argv[]);
int link_set_mode(int argc, char *argv[]);
int link_set_mtu(int argc, char *argv[]);
int link_set_network_section_bool(int argc, char *argv[]);
int link_status(int argc, char *argv[]);
int link_update_state(int argc, char *argv[]);
int list_links(int argc, char *argv[]);
int list_one_link(char *argv[]);
int network_reload(int argc, char *argv[]);
int revert_resolve_link(int argc, char *argv[]);
int set_system_hostname(int argc, char *argv[]);
int show_dns_server(int argc, char *argv[]);
int show_dns_server_domains(int argc, char *argv[]);
int system_status(int argc, char *argv[]);

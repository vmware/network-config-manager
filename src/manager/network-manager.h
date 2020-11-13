/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include "dns.h"
#include "netdev.h"
#include "network.h"
#include "network-route.h"

int manager_set_link_mtu(const IfNameIndex *ifnameidx, uint32_t mtu);
int manager_set_link_mac_addr(const IfNameIndex *ifnameidx, const char *mac);

int manager_set_link_dhcp_mode(const IfNameIndex *ifnameidx, DHCPMode mode);
int manager_get_link_dhcp_mode(const IfNameIndex *ifnameidx, DHCPMode *mode);

int manager_set_link_mode(const IfNameIndex *ifnameidx, bool mode);
int manager_set_link_state(const IfNameIndex *ifnameidx, LinkState state);

int manager_set_link_dhcp_client_identifier(const IfNameIndex *ifnameidx, DHCPClientIdentifier identifier);
int manager_get_link_dhcp_client_identifier(const IfNameIndex *ifnameidx, DHCPClientIdentifier *ret);

int manager_set_link_dhcp_client_iaid(const IfNameIndex *ifnameidx, uint32_t v);
int manager_get_link_dhcp_client_iaid(const IfNameIndex *ifnameidx, uint32_t *iaid);

int manager_set_link_dhcp_client_duid(const IfNameIndex *ifnameidx, DHCPClientDUIDType duid, char *raw_data, bool system);

int manager_configure_link_address(const IfNameIndex *ifnameidx, IPAddress *address, IPAddress *peer);
int manager_delete_link_address(const IfNameIndex *ifnameidx);

int manager_configure_default_gateway(const IfNameIndex *ifnameidx, Route *rt);
int manager_configure_route(const IfNameIndex *ifnameidx, Route *rt);
int manager_remove_gateway_or_route(const IfNameIndex *ifnameidx, bool gateway);

int manager_add_dns_server(const IfNameIndex *ifnameidx, DNSServers *dns, bool system);
int manager_add_dns_server_domain(const IfNameIndex *ifnameidx, char **domains, bool system);
int manager_revert_dns_server_and_domain(const IfNameIndex *ifnameidx);
int manager_read_domains_from_system_config(char **domains);
int manager_add_ntp_addresses(const IfNameIndex *ifnameidx, char **ntps, bool add);
int manager_remove_ntp_addresses(const IfNameIndex *ifnameidx);
int manager_enable_ipv6(const IfNameIndex *ifnameidx, bool enable);
int manager_reload_network(void);
int manager_reconfigure_link(const IfNameIndex *ifnameidx);

int manager_set_network_section_bool(const IfNameIndex *ifnameidx, const char *k, bool v);
int manager_set_dhcp_section(const IfNameIndex *ifnameidx, const char *k, bool v, bool dhcp4);

int manager_create_vlan(const IfNameIndex *ifnameidx, const char *vlan, uint32_t id);

int manager_generate_network_config_from_yaml(const char *file);
int manager_write_wifi_config(const Network *n, const GString *config);

int manager_generate_networkd_config_from_command_line(const char *file, const char *command_line);

int manager_configure_additional_gw(const IfNameIndex *ifnameidx, Route *rt);

int manager_create_bridge(const char *bridge, char **interfaces);
int manager_create_bond(const char *bond, BondMode mode, char **interfaces);
int manager_create_vxlan(const char *vxlan, uint32_t vni, IPAddress *local,
                         IPAddress *remote, IPAddress *group, uint16_t port,
                         const char *dev, bool independent);

int manager_create_macvlan(const char *macvlan, const char *dev, MACVLanMode mode, bool kind);
int manager_create_ipvlan(const char *ipvlan, const char *dev, IPVLanMode mode, bool kind);
int manager_create_veth(const char *veth, const char *veth_peer);
int manager_create_tunnel(const char *tunnel, NetDevKind kind, IPAddress *local,
                          IPAddress *remote, const char *dev, bool independent);
int manager_create_vrf(const char *vrf, uint32_t table);
int manager_create_wireguard_tunnel(char *wireguard, char *private_key, char *public_key, char *preshared_key,
                                    char *endpoint, char *allowed_ips, uint16_t listen_port);

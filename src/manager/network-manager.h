/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "config-file.h"
#include "dns.h"
#include "netdev.h"
#include "network.h"
#include "network-route.h"

int manager_set_link_mtu(const IfNameIndex *ifnameidx, uint32_t mtu);
int manager_set_link_mac_addr(const IfNameIndex *ifnameidx, const char *mac);

int manager_set_link_dhcp_client(const IfNameIndex *ifnameidx, DHCPClient mode);
int manager_get_link_dhcp_client(const IfNameIndex *ifnameidx, DHCPClient *mode);

int manager_set_link_flag(const IfNameIndex *ifnameidx, const char *k, const char *v);
int manager_set_link_state(const IfNameIndex *ifnameidx, LinkState state);

int manager_set_link_group(const IfNameIndex *ifnameidx, uint32_t group);
int manager_set_link_rf_online(const IfNameIndex *ifnameidx, const char *addrfamily);
int manager_set_link_act_policy(const IfNameIndex *ifnameidx, const char *actpolicy);

int manager_set_link_dhcp4_client_identifier(const IfNameIndex *ifnameidx, DHCPClientIdentifier identifier);
int manager_get_link_dhcp4_client_identifier(const IfNameIndex *ifnameidx, DHCPClientIdentifier *ret);

int manager_set_link_dhcp_client_iaid(const IfNameIndex *ifnameidx, DHCPClient kind, uint32_t v);
int manager_get_link_dhcp_client_iaid(const IfNameIndex *ifnameidx, DHCPClient kind, uint32_t *iaid);

int manager_set_link_dhcp_client_duid(const IfNameIndex *ifnameidx, DHCPClientDUIDType duid, char *raw_data, bool system, DHCPClient kind);

int manager_configure_link_address(const IfNameIndex *ifnameidx,
                                   IPAddress *address,
                                   IPAddress *peer,
                                   char *scope,
                                   char *pref_lft,
                                   IPDuplicateAddressDetection dad,
                                   int prefix_route,
                                   const char *label);

int manager_delete_link_address(const IfNameIndex *ifnameidx, const char *a);

int manager_configure_default_gateway(const IfNameIndex *ifnameidx, Route *rt);

int manager_configure_route(const IfNameIndex *ifnameidx,
                            IPAddress *gateway,
                            IPAddress *destination,
                            IPAddress *source,
                            IPAddress *pref_source,
                            IPv6RoutePreference rt_pref,
                            RouteProtocol protocol,
                            RouteScope scope,
                            RouteType type,
                            RouteTable table,
                            uint32_t mtu,
                            int metric,
                            int onlink);

int manager_remove_gateway_or_route(const IfNameIndex *ifnameidx, bool gateway);

int manager_add_dns_server(const IfNameIndex *ifnameidx, DNSServers *dns, bool system, bool global);
int manager_add_dns_server_domain(const IfNameIndex *ifnameidx, char **domains, bool system, bool global);
int manager_revert_dns_server_and_domain(const IfNameIndex *ifnameidx);
int manager_read_domains_from_system_config(char **domains);
int manager_add_ntp_addresses(const IfNameIndex *ifnameidx, char **ntps, bool add);
int manager_remove_ntp_addresses(const IfNameIndex *ifnameidx);
int manager_enable_ipv6(const IfNameIndex *ifnameidx, bool enable);
int manager_reload_network(void);
int manager_reconfigure_link(const IfNameIndex *ifnameidx);

int manager_link_set_network_ipv6_mtu(const IfNameIndex *ifnameidx, uint32_t mtu);

int manager_network_section_configs_new(ConfigManager **ret);
int manager_network_dhcp4_section_configs_new(ConfigManager **ret);
int manager_network_dhcp6_section_configs_new(ConfigManager **ret);
int manager_network_link_section_configs_new(ConfigManager **ret);

int manager_set_link_local_address(const IfNameIndex *ifnameidx, const char *k, const char *v);
int manager_set_network_section_bool(const IfNameIndex *ifnameidx, const char *k, bool v);
int manager_set_dhcp_section(DHCPClient kind, const IfNameIndex *ifnameidx, const char *k, bool v);

int manager_create_vlan(const IfNameIndex *ifnameidx, const char *vlan, uint32_t id, const char *proto);

int manager_generate_network_config_from_yaml(const char *file);
int manager_write_wifi_config(const Network *n, const GString *config);

int manager_generate_networkd_config_from_command_line(const char *file, const char *command_line);

int manager_configure_additional_gw(const IfNameIndex *ifnameidx, Route *rt);
int manager_configure_routing_policy_rules(const IfNameIndex *ifnameidx,
                                           const IfNameIndex *iif,
                                           const IfNameIndex *oif,
                                           const IPAddress *to_addr,
                                           const IPAddress *from_addr,
                                           const uint32_t table,
                                           const uint32_t priority,
                                           const char *tos);

int manager_remove_routing_policy_rules(const IfNameIndex *ifnameidx);

int manager_configure_dhcpv4_server (const IfNameIndex *ifnameidx,
                                     const IPAddress *dns,
                                     const IPAddress *ntp,
                                     const uint32_t pool_offset,
                                     const uint32_t pool_size,
                                     const uint32_t default_lease_time,
                                     const uint32_t max_lease_time,
                                     const int emit_dns,
                                     const int emit_ntp,
                                     const int emit_router);

int manager_remove_dhcpv4_server(const IfNameIndex *ifnameidx);

int manager_configure_ipv6_router_advertisement(const IfNameIndex *p,
                                                const IPAddress *prefix,
                                                const IPAddress *route_prefix,
                                                const IPAddress *dns,
                                                const char *domain,
                                                const uint32_t pref_lifetime,
                                                const uint32_t valid_lifetime,
                                                const uint32_t dns_lifetime,
                                                const uint32_t route_lifetime,
                                                IPv6RAPreference preference,
                                                const int managed,
                                                const int other,
                                                const int emit_dns,
                                                const int emit_domain,
                                                const int assign);

int manager_remove_ipv6_router_advertisement(const IfNameIndex *ifnameidx);

int manager_create_bridge(const char *bridge, char **interfaces);
int manager_create_bond(const char *bond, const BondMode mode, char **interfaces);
int manager_create_vxlan(const char *vxlan,
                         const uint32_t vni,
                         const IPAddress *local,
                         const IPAddress *remote,
                         const IPAddress *group,
                         const uint16_t port,
                         const char *dev,
                         const bool independent);

int manager_create_macvlan(const char *macvlan, const char *dev, MACVLanMode mode, bool kind);
int manager_create_ipvlan(const char *ipvlan, const char *dev, IPVLanMode mode, bool kind);
int manager_create_veth(const char *veth, const char *veth_peer);
int manager_create_tunnel(const char *tunnel, NetDevKind kind, IPAddress *local,
                          IPAddress *remote, const char *dev, bool independent);
int manager_create_vrf(const char *vrf, const uint32_t table);
int manager_create_wireguard_tunnel(char *wireguard, char *private_key, char *public_key, char *preshared_key,
                                    char *endpoint, char *allowed_ips, uint16_t listen_port);

int manager_show_link_network_config(const IfNameIndex *ifnameidx, char **ret);
int manager_edit_link_network_config(const IfNameIndex *ifnameidx);

int manager_remove_netdev(const char *ifname, const char *kind);

int manager_configure_proxy(int enable,
                            const char *http,
                            const char *https,
                            const char *ftp,
                            const char *gopher,
                            const char *socks,
                            const char *socks5,
                            const char *no_proxy);

int manager_parse_proxy_config(GHashTable **c);

/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "config-file.h"
#include "dns.h"
#include "netdev.h"
#include "network.h"
#include "network-route.h"
#include "network-routing-policy-rule.h"

int manager_set_link_mtu(const IfNameIndex *ifidx, uint32_t mtu);
int manager_set_link_mac_addr(const IfNameIndex *ifidx, const char *mac);

int manager_set_link_dhcp_client(const IfNameIndex *ifidx, DHCPClient mode);
int manager_get_link_dhcp_client(const IfNameIndex *ifidx, DHCPClient *mode);

int manager_set_link_flag(const IfNameIndex *ifidx, const char *k, const char *v);
int manager_set_link_state(const IfNameIndex *ifidx, LinkState state);

int manager_set_link_group(const IfNameIndex *ifidx, uint32_t group);
int manager_set_link_rf_online(const IfNameIndex *ifidx, const char *addrfamily);
int manager_set_link_act_policy(const IfNameIndex *ifidx, const char *actpolicy);

int manager_set_link_dhcp4_client_identifier(const IfNameIndex *ifidx, const DHCPClientIdentifier identifier);
int manager_get_link_dhcp4_client_identifier(const IfNameIndex *ifidx, DHCPClientIdentifier *ret);

int manager_set_link_ipv6_dad(const IfNameIndex *ifidx, int dad);
int manager_set_link_ipv6_link_local_address_generation_mode(const IfNameIndex *ifidx, int mode);

int manager_get_link_dns(const IfNameIndex *ifidx, char ***ret);
int manager_get_all_link_dns(char ***ret);
int manager_get_all_link_dhcp_lease_dns(char ***ret);

bool manager_is_link_static_address(const IfNameIndex *ifidx);

int manager_set_link_dhcp_client_iaid(const IfNameIndex *ifidx, DHCPClient kind, const char *iaid);
int manager_get_link_dhcp_client_iaid(const IfNameIndex *ifidx, DHCPClient kind, uint32_t *iaid);

int manager_set_link_dhcp_client_duid(const IfNameIndex *ifidx,
                                      const DHCPClientDUIDType duid,
                                      const char *raw_data,
                                      const bool system,
                                      const DHCPClient kind);

int manager_configure_link_address(const IfNameIndex *ifidx,
                                   const IPAddress *address,
                                   const IPAddress *peer,
                                   const char *scope,
                                   const char *pref_lft,
                                   const IPDuplicateAddressDetection dad,
                                   const int prefix_route,
                                   const char *label);

int manager_delete_link_address(const IfNameIndex *ifidx, const char *a);

int manager_configure_default_gateway(const IfNameIndex *ifidx, Route *rt);

int manager_configure_route(const IfNameIndex *ifidx,
                            const IPAddress *gateway,
                            const IPAddress *destination,
                            const IPAddress *source,
                            const IPAddress *pref_source,
                            const IPv6RoutePreference rt_pref,
                            const RouteProtocol protocol,
                            const RouteScope scope,
                            const RouteType type,
                            const RouteTable table,
                            const uint32_t mtu,
                            const int metric,
                            const int onlink,
                            const bool b);

int manager_remove_gateway_or_route(const IfNameIndex *ifidx, bool gateway);

int manager_add_dns_server(const IfNameIndex *ifidx, DNSServers *dns, bool system, bool global);
int manager_add_dns_server_domain(const IfNameIndex *ifidx, char **domains, bool system, bool global);
int manager_revert_dns_server_and_domain(const IfNameIndex *ifidx);
int manager_read_domains_from_system_config(char **domains);
int manager_add_ntp_addresses(const IfNameIndex *ifidx, char **ntps, bool add);
int manager_remove_ntp_addresses(const IfNameIndex *ifidx);
int manager_enable_ipv6(const IfNameIndex *ifidx, bool enable);
int manager_reload_network(void);
int manager_reconfigure_link(const IfNameIndex *ifidx);

int manager_link_set_network_ipv6_mtu(const IfNameIndex *ifidx, uint32_t mtu);

int manager_network_section_configs_new(ConfigManager **ret);
int manager_network_dhcp4_section_configs_new(ConfigManager **ret);
int manager_network_dhcp6_section_configs_new(ConfigManager **ret);
int manager_network_link_section_configs_new(ConfigManager **ret);

int manager_set_link_local_address(const IfNameIndex *ifidx, const char *k, const char *v);
int manager_set_network_section_bool(const IfNameIndex *ifidx, const char *k, bool v);
int manager_set_network_section(const IfNameIndex *ifidx, const char *k, const char *v);
int manager_set_dhcp_section(DHCPClient kind, const IfNameIndex *ifidx, const char *k, bool v);

int manager_create_vlan(const IfNameIndex *ifidx, const char *ifname, VLan *v);

int manager_generate_network_config_from_yaml(const char *file);
int manager_write_wifi_config(const Network *n, const GString *config);

int manager_generate_networkd_config_from_command_line(const char *file, const char *command_line);

int manager_configure_additional_gw(const IfNameIndex *ifidx, const IPAddress *a, const Route *rt);
int manager_configure_routing_policy_rules(const IfNameIndex *ifidx, RoutingPolicyRule *rule);

int manager_remove_routing_policy_rules(const IfNameIndex *ifidx);

int manager_configure_dhcpv4_server (const IfNameIndex *ifidx,
                                     const IPAddress *dns,
                                     const IPAddress *ntp,
                                     const uint32_t pool_offset,
                                     const uint32_t pool_size,
                                     const uint32_t default_lease_time,
                                     const uint32_t max_lease_time,
                                     const int emit_dns,
                                     const int emit_ntp,
                                     const int emit_router);

int manager_remove_dhcpv4_server(const IfNameIndex *ifidx);

int manager_add_dhcpv4_server_static_address(const IfNameIndex *i, const IPAddress *addr, const char *mac);
int manager_remove_dhcpv4_server_static_address(const IfNameIndex *i, const IPAddress *addr, const char *mac);

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

int manager_remove_ipv6_router_advertisement(const IfNameIndex *ifidx);

int manager_show_link_network_config(const IfNameIndex *ifidx, char **ret);
int manager_edit_link_network_config(const IfNameIndex *ifidx);
int manager_edit_link_config(const IfNameIndex *ifidx);

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

int manager_write_network_config(const Network *n, const GString *config);

bool manager_config_exists(const char *section, const char *k, const char *v);

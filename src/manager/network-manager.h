/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "config-file.h"
#include "dns.h"
#include "netdev.h"
#include "network.h"
#include "network-route.h"
#include "network-routing-policy-rule.h"

int manager_set_link_mtu(const IfNameIndex *p, uint32_t mtu);
int manager_set_link_mac_addr(const IfNameIndex *p, const char *mac);

int manager_set_link_dhcp_client(const IfNameIndex *p,
                                 DHCPClient mode,
                                 int use_dns_ipv4,
                                 int use_dns_ipv6,
                                 int use_domains_ipv4,
                                 int use_domains_ipv6,
                                 int send_release_ipv4,
                                 int send_release_ipv6);

int manager_acquire_link_dhcp_client_kind(const IfNameIndex *p, DHCPClient *mode);

int manager_set_link_dynamic_conf(const IfNameIndex *p,
                                  int accept_ra,
                                  DHCPClient mode,
                                  int use_dns_ipv4,
                                  int use_dns_ipv6,
                                  int use_domains_ipv4,
                                  int use_domains_ipv6,
                                  int send_release_ipv4,
                                  int send_release_ipv6,
                                  const DHCPClientIdentifier identifier,
                                  const char *iaid,
                                  const char *iaid6,
                                  int lla,
                                  bool keep);

int manager_set_link_static_conf(const IfNameIndex *p, char **addrs, char **gws, char **dns, int lla, bool keep);

int manager_set_link_network_conf(const IfNameIndex *p,
                                  int accept_ra,
                                  DHCPClient dhcp_kind,
                                  int use_dns_ipv4,
                                  int use_dns_ipv6,
                                  int use_domains_ipv4,
                                  int use_domains_ipv6,
                                  int send_release_ipv4,
                                  int send_release_ipv6,
                                  const DHCPClientIdentifier dhcp4_identifier,
                                  const char *iaid4,
                                  const char *iaid6,
                                  char **addrs,
                                  char **gws,
                                  char **dns,
                                  int lla,
                                  bool keep);

int manager_set_link_flag(const IfNameIndex *p, const char *k, const char *v);
int manager_set_link_state(const IfNameIndex *p, LinkState state);

int manager_set_link_group(const IfNameIndex *p, uint32_t group);
int manager_set_link_rf_online(const IfNameIndex *p, const char *addrfamily);
int manager_set_link_act_policy(const IfNameIndex *p, const char *actpolicy);

int manager_set_link_dhcp4_client_identifier(const IfNameIndex *p, const DHCPClientIdentifier identifier);
int manager_acquire_link_dhcp4_client_identifier(const IfNameIndex *p, DHCPClientIdentifier *ret);

int manager_set_link_ipv6_dad(const IfNameIndex *p, int dad);
int manager_set_link_ipv6_link_local_address_generation_mode(const IfNameIndex *p, int mode);

int manager_parse_link_dns_servers(const IfNameIndex *p, char ***ret);
int manager_acquire_all_link_dns(char ***ret);

int manager_parse_link_ntp_servers(const IfNameIndex *p, char ***ret);
int manager_acquire_all_link_ntp(char ***ret);

int manager_acquire_all_link_dhcp_lease_dns(char ***ret);

bool manager_link_has_static_address(const IfNameIndex *p);

int manager_set_link_dhcp_client_iaid(const IfNameIndex *p, DHCPClient kind, const char *iaid);
int manager_acquire_link_dhcp_client_iaid(const IfNameIndex *p, DHCPClient kind, char **iaid);


int manager_acquire_link_dhcp_client_duid(const IfNameIndex *p, const DHCPClient kind, char **duid_kind, char **raw_data);

int manager_set_link_dhcp_client_duid(const IfNameIndex *p,
                                      const char *duid,
                                      const char *raw_data,
                                      const bool system,
                                      const DHCPClient kind);

int manager_configure_link_address(const IfNameIndex *p,
                                   const IPAddress *address,
                                   const IPAddress *peer,
                                   const char *scope,
                                   const char *pref_lft,
                                   const IPDuplicateAddressDetection dad,
                                   const int prefix_route,
                                   const char *label,
                                   char **many);

int manager_remove_link_address(const IfNameIndex *p, char **addresses, AddressFamily family);
int manager_replace_link_address(const IfNameIndex *p, char **many, AddressFamily family);
int manager_replace_link_address_internal(KeyFile *key_file, char **many, AddressFamily family);

int manager_configure_default_gateway(const IfNameIndex *p, Route *rt, bool keep);
int manager_configure_default_gateway_full(const IfNameIndex *p, Route *rt4, Route *rt6);

int manager_configure_route(const IfNameIndex *p,
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

int manager_remove_gateway_or_route_full_internal(KeyFile *key_file, bool gateway, AddressFamily family);
int manager_remove_gateway_or_route_full(const char *network, bool gateway, AddressFamily family);
int manager_remove_gateway_or_route(const IfNameIndex *p, bool gateway, AddressFamily family);

int manager_set_dns_server(const IfNameIndex *i, char **dns, int ipv4, int ipv6, bool keep);

int manager_set_dns_server_domain(const IfNameIndex *p, char **domains, bool keep);
int manager_revert_dns_server_and_domain(const IfNameIndex *p, bool dns, bool domain);
int manager_read_domains_from_system_config(char **domains);
int manager_set_ntp_servers(const IfNameIndex *p, char **ntp, bool keep);
int manager_remove_ntp_addresses(const IfNameIndex *p);
int manager_enable_ipv6(const IfNameIndex *p, bool enable);
int manager_reload_network(void);
int manager_reconfigure_link(const IfNameIndex *p);

int manager_link_set_network_ipv6_mtu(const IfNameIndex *p, uint32_t mtu);

int manager_network_section_configs_new(ConfigManager **ret);
int manager_network_dhcp4_section_configs_new(ConfigManager **ret);
int manager_network_dhcp6_section_configs_new(ConfigManager **ret);
int manager_network_link_section_configs_new(ConfigManager **ret);

int manager_acquire_link_local_addressing_kind(const IfNameIndex *p, LinkLocalAddress *lla_mode);
int manager_set_link_local_address(const IfNameIndex *p, const char *k, const char *v);
int manager_set_network_section_bool(const IfNameIndex *p, const char *k, bool v);
int manager_set_network_section(const IfNameIndex *p, const char *k, const char *v);
int manager_set_dhcp_section(DHCPClient kind, const IfNameIndex *p, const char *k, bool v);

int manager_create_vlan(const IfNameIndex *p, const char *ifname, VLan *v);

int manager_generate_network_config_from_yaml(const char *file);

int manager_generate_networkd_config_from_command_line(const char *file, const char *command_line);

int manager_configure_routing_policy_rule(const IfNameIndex *p, const IPAddress *a, const Route *rt, bool keep);
int manager_configure_routing_policy_rules(const IfNameIndex *p, RoutingPolicyRule *rule);

int manager_remove_routing_policy_rules(const IfNameIndex *p);

int manager_configure_dhcpv4_server (const IfNameIndex *p,
                                     const IPAddress *dns,
                                     const IPAddress *ntp,
                                     const uint32_t pool_offset,
                                     const uint32_t pool_size,
                                     const uint32_t default_lease_time,
                                     const uint32_t max_lease_time,
                                     const int emit_dns,
                                     const int emit_ntp,
                                     const int emit_router);

int manager_remove_dhcpv4_server(const IfNameIndex *p);

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

int manager_remove_ipv6_router_advertisement(const IfNameIndex *p);

int manager_show_link_network_config(const IfNameIndex *p, char **ret);
int manager_edit_link_network_config(const IfNameIndex *p);
int manager_edit_link_config(const IfNameIndex *p);

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

int manager_set_ipv6(const IfNameIndex *p,
                     const int dhcp,
                     const int accept_ra,
                     int lla,
                     char **addrs,
                     Route *rt6,
                     char **dns,
                     char **domains,
                     const int use_dns,
                     UseDomains use_domains,
                     const int send_release,
                     const bool keep);

int manager_set_ipv4(const IfNameIndex *p,
                     const int lla,
                     const int dhcp,
                     char **addrs,
                     Route *rt4,
                     char **dns,
                     char **domains,
                     const DHCPClientIdentifier client_id,
                     const int use_dns,
                     UseDomains use_domains,
                     const int send_release,
                     bool keep);

int manager_write_networkd_debug_config(void);
int manager_remove_networkd_debug_config(void);


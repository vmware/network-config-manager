/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "netdev.h"

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
int manager_create_tun_tap(const NetDevKind kind,
                           const char *ifname,
                           const char *user,
                           const char *group,
                           const int packet_info,
                           const int vnet_hdr,
                           const int keep_carrier,
                           const int multi_queue);

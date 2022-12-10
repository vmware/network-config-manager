/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "netdev.h"

int manager_create_bridge(const char *ifname, Bridge *b, char **interfaces);
int manager_create_bond(const char *ifname, Bond *b, char **interfaces);
int manager_create_vxlan(const char *ifname, const char *dev, VxLan *v);

int manager_create_macvlan(const char *ifname, const char *dev, MACVLan *m, bool kind);
int manager_create_ipvlan(const char *ipvlan, const char *dev, IPVLanMode mode, bool kind);
int manager_create_veth(const char *ifname, Veth *v);
int manager_create_tunnel(const char *tunnel, NetDevKind kind, const char *dev, Tunnel *t);
int manager_create_vrf(const char *ifname, VRF *vrf);
int manager_create_wireguard(const char *ifname, WireGuard *wg);
int manager_create_tun_tap(const char *ifname, const NetDevKind kind, TunTap *t);

/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <linux/if_link.h>

#include "config-file.h"
#include "network-util.h"

typedef enum NetDevKind {
        NETDEV_KIND_VLAN,
        NETDEV_KIND_BRIDGE,
        NETDEV_KIND_BOND,
        NETDEV_KIND_VXLAN,
        NETDEV_KIND_MACVLAN,
        NETDEV_KIND_MACVTAP,
        NETDEV_KIND_IPVLAN,
        NETDEV_KIND_IPVTAP,
        NETDEV_KIND_VRF,
        NETDEV_KIND_TUN,
        NETDEV_KIND_TAP,
        NETDEV_KIND_VETH,
        NETDEV_KIND_IPIP_TUNNEL,
        NETDEV_KIND_SIT_TUNNEL,
        NETDEV_KIND_GRE_TUNNEL,
        NETDEV_KIND_VTI_TUNNEL,
        NETDEV_KIND_WIREGUARD,
        _NETDEV_KIND_MAX,
        _NETDEV_KIND_INVALID = -EINVAL
} NetDevKind;

typedef enum BondMode {
        BOND_MODE_ROUNDROBIN,
        BOND_MODE_ACTIVEBACKUP,
        BOND_MODE_XOR,
        BOND_MODE_BROADCAST,
        BOND_MODE_8023AD,
        BOND_MODE_TLB,
        BOND_MODE_ALB,
        _BOND_MODE_MAX,
        _BOND_MODE_INVALID = -EINVAL
} BondMode;

typedef enum MACVLanMode {
        MAC_VLAN_MODE_PRIVATE,
        MAC_VLAN_MODE_VEPA,
        MAC_VLAN_MODE_BRIDGE,
        MAC_VLAN_MODE_PASSTHRU,
        MAC_VLAN_MODE_SOURCE,
        _MAC_VLAN_MODE_MAX,
        _MAC_VLAN_MODE_INVALID = -EINVAL
} MACVLanMode;

typedef enum IPVLanMode {
        IP_VLAN_MODE_L2,
        IP_VLAN_MODE_L3,
        IP_VLAN_MODE_L3S,
        _IP_VLAN_MODE_MAX,
        _IP_VLAN_MODE_INVALID = -EINVAL
} IPVLanMode;

typedef struct TunTap {
        char *user;
        char *group;

        int multi_queue;
        int packet_info;
        int vnet_hdr;
        int keep_carrier;
} TunTap;

typedef struct VLan {
        uint32_t id;
        char *proto;

        int gvrp;
        int mvrp;
        int loose_binding;
        int reorder_header;
} VLan;

typedef struct WireGuard {
        char *private_key;
        char *private_key_file;
        char *public_key;
        char *preshared_key;
        char *preshared_key_file;
        char *endpoint;      /* ip:port */
        char *allowed_ips;

        uint16_t listen_port;
        int persistent_keep_alive;
} WireGuard;

typedef struct VxLan {
        uint32_t vni;

        IPAddress local;
        IPAddress remote;
        IPAddress group;

        uint16_t destination_port;

        bool independent;
} VxLan;

typedef struct Tunnel {
         bool independent;

        IPAddress local;
        IPAddress remote;

} Tunnel;

typedef struct NetDev {
        char *ifname;
        char *peer;
        char *mac;

        uint32_t id;
        uint32_t table;

        TunTap *tun_tap;
        VLan *vlan;
        WireGuard *wg;
        VxLan *vxlan;
        Tunnel *tunnel;

        NetDevKind kind;
        BondMode bond_mode;
        MACVLanMode macvlan_mode;
        IPVLanMode ipvlan_mode;
} NetDev;

int netdev_new(NetDev **ret);
void netdev_unref(NetDev *n);
DEFINE_CLEANUP(NetDev*, netdev_unref);

int vlan_new(VLan **ret);
void vlan_unref(VLan *n);
DEFINE_CLEANUP(VLan*, vlan_unref);

int wireguard_new(WireGuard **ret);
void wireguard_unref(WireGuard *wg);
DEFINE_CLEANUP(WireGuard*, wireguard_unref);

int vxlan_new(VxLan **ret);
void vxlan_unref(VxLan *v);
DEFINE_CLEANUP(VxLan*, vxlan_unref);

int tunnel_new(Tunnel **ret);
void tunnel_unref(Tunnel *v);
DEFINE_CLEANUP(Tunnel*, tunnel_unref);

int tuntap_new(TunTap **ret);
void tuntap_unref(TunTap *t);
DEFINE_CLEANUP(TunTap*, tuntap_unref);

int generate_netdev_config(NetDev *n);
int create_netdev_conf_file(const char *ifnameidx, char **ret);

const char *netdev_kind_to_name(NetDevKind id);
int netdev_name_to_kind(const char *name);

const char *bond_mode_to_name(BondMode id);
int bond_name_to_mode(const char *name);

const char *macvlan_mode_to_name(MACVLanMode id);
int macvlan_name_to_mode(const char *name);

const char *ipvlan_mode_to_name(IPVLanMode id);
int ipvlan_name_to_mode(const char *name);

int netdev_ctl_name_to_configs_new(ConfigManager **ret);

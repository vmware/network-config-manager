/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <netinet/in.h>
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

typedef enum BondXmitHashPolicy {
        BOND_XMIT_POLICY_LAYER2,
        BOND_XMIT_POLICY_LAYER34,
        BOND_XMIT_POLICY_LAYER23,
        BOND_XMIT_POLICY_ENCAP23,
        BOND_XMIT_POLICY_ENCAP34,
        BOND_XMIT_POLICY_VLAN_SRCMAC,
        _BOND_XMIT_HASH_POLICY_MAX,
        _BOND_XMIT_HASH_POLICY_INVALID = -EINVAL,
} BondXmitHashPolicy;

typedef enum BondLacpRate {
        BOND_LACP_RATE_SLOW,
        BOND_LACP_RATE_FAST,
        _BOND_LACP_RATE_MAX,
        _BOND_LACP_RATE_INVALID = -EINVAL,
} BondLacpRate;

typedef enum BondArpValidate {
        BOND_ARP_VALIDATE_NONE,
        BOND_ARP_VALIDATE_ACTIVE,
        BOND_ARP_VALIDATE_BACKUP,
        BOND_ARP_VALIDATE_ALL,
        _BOND_ARP_VALIDATE_MAX,
        _BOND_ARP_VALIDATE_INVALID = -EINVAL,
} BondArpValidate;

typedef enum BondFailOverMac {
        BOND_FAIL_OVER_MAC_NONE,
        BOND_FAIL_OVER_MAC_ACTIVE,
        BOND_FAIL_OVER_MAC_FOLLOW,
        _BOND_FAIL_OVER_MAC_MAX,
        _BOND_FAIL_OVER_MAC_INVALID = -EINVAL,
} BondFailOverMac;

typedef enum BondAdSelect {
        BOND_AD_SELECT_STABLE,
        BOND_AD_SELECT_BANDWIDTH,
        BOND_AD_SELECT_COUNT,
        _BOND_AD_SELECT_MAX,
        _BOND_AD_SELECT_INVALID = -EINVAL,
} BondAdSelect;

typedef enum BondPrimaryReselect {
        BOND_PRIMARY_RESELECT_ALWAYS,
        BOND_PRIMARY_RESELECT_BETTER,
        BOND_PRIMARY_RESELECT_FAILURE,
        _BOND_PRIMARY_RESELECT_MAX,
        _BOND_PRIMARY_RESELECT_INVALID = -EINVAL,
} BondPrimaryReselect;

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
        char *master;

        int gvrp;
        int mvrp;
        int loose_binding;
        int reorder_header;
} VLan;

typedef struct WireGuardPeer{
        char *public_key;
        char *preshared_key_file;

        char *preshared_key;
        char *endpoint;      /* ip:port */
        char **allowed_ips;

        int persistent_keep_alive;
} WireGuardPeer;

typedef struct WireGuard {
        char *private_key;
        char *private_key_file;
        uint16_t listen_port;
        uint32_t fwmark;

        GList *peers;
} WireGuard;

typedef struct VxLan {
        uint32_t vni;

        IPAddress local;
        IPAddress remote;
        IPAddress group;

        uint16_t destination_port;
        uint16_t low_port;
        uint16_t high_port;

        unsigned tos;
        unsigned ttl;
        unsigned max_fdb;
        unsigned flow_label;

        uint64_t fdb_ageing;

        int learning;
        int arp_proxy;
        int route_short_circuit;
        int l2miss;
        int l3miss;
        int udpcsum;
        int udp6zerocsumtx;
        int udp6zerocsumrx;
        int remote_csum_tx;
        int remote_csum_rx;
        int group_policy;
        int generic_protocol_extension;
        int inherit;
        int df;
        int independent;


        char *master;
} VxLan;

typedef struct Tunnel {
        bool independent;

        unsigned ttl;
        unsigned tos;
        unsigned flags;

        uint32_t key;
        uint32_t ikey;
        uint32_t okey;

        IPAddress local;
        IPAddress remote;
} Tunnel;

typedef struct Bond {
        BondMode mode;
        BondXmitHashPolicy xmit_hash_policy;
        BondLacpRate lacp_rate;
        BondArpValidate arp_validate;
        BondFailOverMac fail_over_mac;
        BondAdSelect ad_select;
        BondPrimaryReselect primary_reselect;

        uint64_t mii_monitor_interval;
        uint64_t arp_interval;
        uint64_t up_delay;
        uint64_t down_delay;
        uint64_t lp_interval;

        uint32_t min_links;
        uint32_t resend_igmp;
        unsigned packets_per_slave;
        unsigned ngrat_arp;

        int all_slaves_active;
        char **arp_ip_targets;
        char **interfaces;
} Bond;

typedef struct Bridge {
        int mcast_querier;
        int mcast_snooping;
        int vlan_filtering;
        int vlan_protocol;
        int stp;

        uint16_t priority;
        uint16_t group_fwd_mask;
        uint16_t default_pvid;
        uint8_t igmp_version;

        uint64_t forward_delay;
        uint64_t hello_time;
        uint64_t max_age;
        uint64_t ageing_time;

        char **interfaces;
} Bridge;

typedef struct VRF {
        uint32_t table;

        char **interfaces;
} VRF;

typedef struct Veth {
        char *peer;
} Veth;

typedef struct MACVLan {
         char *master;
         MACVLanMode mode;
} MACVLan;

typedef struct IPVLan {
        IPVLanMode mode;
} IPVLan;

typedef struct NetDev {
        char *ifname;
        char *master;
        char *mac;

        /* NetDev */
        TunTap *tun_tap;
        VLan *vlan;
        WireGuard *wg;
        VxLan *vxlan;
        Tunnel *tunnel;
        Bond *bond;
        Bridge *bridge;
        VRF *vrf;
        Veth *veth;
        MACVLan *macvlan;
        IPVLan *ipvlan;

        NetDevKind kind;
} NetDev;

int netdev_new(NetDev **ret);
void netdev_free(NetDev *n);
DEFINE_CLEANUP(NetDev*, netdev_free);

int ipvlan_new(IPVLan **ret);
void ipvlan_free(IPVLan *v);
DEFINE_CLEANUP(IPVLan*, ipvlan_free);

int veth_new(Veth **ret);
void veth_free(Veth *v);
DEFINE_CLEANUP(Veth*, veth_free);

int macvlan_new(MACVLan **ret);
void macvlan_free(MACVLan *v);
DEFINE_CLEANUP(MACVLan*, macvlan_free);

int vrf_new(VRF **ret);
void vrf_free(VRF *v);
DEFINE_CLEANUP(VRF*, vrf_free);

int vlan_new(VLan **ret);
void vlan_free(VLan *n);
DEFINE_CLEANUP(VLan*, vlan_free);

int wireguard_new(WireGuard **ret);
void wireguard_free(WireGuard *wg);
DEFINE_CLEANUP(WireGuard*, wireguard_free);

int wireguard_peer_new(WireGuardPeer **ret);
void wireguard_peer_free(void *wg);
DEFINE_CLEANUP(WireGuardPeer*, wireguard_peer_free);

int vxlan_new(VxLan **ret);
void vxlan_free(VxLan *v);
DEFINE_CLEANUP(VxLan*, vxlan_free);

int tunnel_new(Tunnel **ret);
void tunnel_free(Tunnel *v);
DEFINE_CLEANUP(Tunnel*, tunnel_free);

int tuntap_new(TunTap **ret);
void tuntap_free(TunTap *t);
DEFINE_CLEANUP(TunTap*, tuntap_free);

int bond_new(Bond **ret);
void bond_free(Bond *t);
DEFINE_CLEANUP(Bond*, bond_free);

int bridge_new(Bridge **ret);
void bridge_free(Bridge *b);
DEFINE_CLEANUP(Bridge*, bridge_free);

int generate_netdev_config(NetDev *n);
int create_netdev_conf_file(const char *p, char **ret);

const char *netdev_kind_to_name(NetDevKind id);
int netdev_name_to_kind(const char *name);

const char *bond_mode_to_name(BondMode id);
int bond_name_to_mode(const char *name);

const char *macvlan_mode_to_name(MACVLanMode id);
int macvlan_name_to_mode(const char *name);

const char *ipvlan_mode_to_name(IPVLanMode id);
int ipvlan_name_to_mode(const char *name);

const char *bond_xmit_hash_policy_to_name(BondXmitHashPolicy id);
int bond_xmit_hash_policy_name_to_mode(const char *name);

const char *bond_lacp_rate_to_name(BondLacpRate id);
int bond_lacp_rate_to_mode(const char *name);

const char *bond_arp_validate_mode_to_name(BondArpValidate id);
int bond_arp_validate_table_name_to_mode(const char *name);

const char *bond_fail_over_mac_mode_to_name(BondFailOverMac id);
int bond_fail_over_mac_name_to_mode(const char *name);

const char *bond_ad_select_mode_to_name(BondAdSelect id);
int bond_ad_select_name_to_mode(const char *name);

const char *bond_primary_reselect_mode_to_name(BondPrimaryReselect id);
int bond_primary_reselect_name_to_mode(const char *name);

int netdev_ctl_name_to_configs_new(ConfigManager **ret);

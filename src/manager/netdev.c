/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "config-parser.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "parse-util.h"
#include "string-util.h"
#include "netdev.h"

#define RESEND_IGMP_MAX           255
#define PACKETS_PER_SLAVE_MAX     65535
#define GRATUITOUS_ARP_MAX        255

static const char *const netdev_kind_table[_NETDEV_KIND_MAX] = {
        [NETDEV_KIND_VLAN]        = "vlan",
        [NETDEV_KIND_BRIDGE]      = "bridge",
        [NETDEV_KIND_BOND]        = "bond",
        [NETDEV_KIND_VXLAN]       = "vxlan",
        [NETDEV_KIND_MACVLAN]     = "macvlan",
        [NETDEV_KIND_MACVTAP]     = "macvtap",
        [NETDEV_KIND_IPVLAN]      = "ipvlan",
        [NETDEV_KIND_IPVTAP]      = "ipvtap",
        [NETDEV_KIND_VRF]         = "vrf",
        [NETDEV_KIND_VETH]        = "veth",
        [NETDEV_KIND_TUN]         = "tun",
        [NETDEV_KIND_TAP]         = "tap",
        [NETDEV_KIND_IPIP_TUNNEL] = "ipip",
        [NETDEV_KIND_SIT_TUNNEL]  = "sit",
        [NETDEV_KIND_GRE_TUNNEL]  = "gre",
        [NETDEV_KIND_VTI_TUNNEL]  = "vti",
        [NETDEV_KIND_WIREGUARD]   = "wireguard",
};

const char *netdev_kind_to_name(NetDevKind id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(netdev_kind_table))
                return NULL;

        return netdev_kind_table[id];
}

int netdev_name_to_kind(const char *name) {
        assert(name);

        for (size_t i = NETDEV_KIND_VLAN; i < (int) ELEMENTSOF(netdev_kind_table); i++)
                if (netdev_kind_table[i] && string_equal_fold(name, netdev_kind_table[i]))
                        return i;

        return _NETDEV_KIND_INVALID;
}

static const char *const bond_mode_table[_BOND_MODE_MAX] = {
        [BOND_MODE_ROUNDROBIN]   = "balance-rr",
        [BOND_MODE_ACTIVEBACKUP] = "active-backup",
        [BOND_MODE_XOR]          = "balance-xor",
        [BOND_MODE_BROADCAST]    = "broadcast",
        [BOND_MODE_8023AD]       = "802.3ad",
        [BOND_MODE_TLB]          = "balance-tlb",
        [BOND_MODE_ALB]          = "balance-alb",
};

const char *bond_mode_to_name(BondMode id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(bond_mode_table))
                return NULL;

        return bond_mode_table[id];
}

int bond_name_to_mode(const char *name) {
        assert(name);

        for (size_t i = BOND_MODE_ROUNDROBIN; i < (size_t) ELEMENTSOF(bond_mode_table); i++)
                if (bond_mode_table[i] && string_equal_fold(name, bond_mode_table[i]))
                        return i;

        return _BOND_MODE_INVALID;
}

static const char* const bond_xmit_hash_policy_table[_BOND_XMIT_HASH_POLICY_MAX] = {
        [BOND_XMIT_POLICY_LAYER2]      = "layer2",
        [BOND_XMIT_POLICY_LAYER34]     = "layer3+4",
        [BOND_XMIT_POLICY_LAYER23]     = "layer2+3",
        [BOND_XMIT_POLICY_ENCAP23]     = "encap2+3",
        [BOND_XMIT_POLICY_ENCAP34]     = "encap3+4",
        [BOND_XMIT_POLICY_VLAN_SRCMAC] = "vlan+srcmac",
};

const char *bond_xmit_hash_policy_to_name(BondXmitHashPolicy id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(bond_xmit_hash_policy_table))
                return NULL;

        return bond_xmit_hash_policy_table[id];
}

int bond_xmit_hash_policy_to_mode(const char *name) {
        assert(name);

        for (size_t i = BOND_XMIT_POLICY_LAYER2; i < (size_t) ELEMENTSOF(bond_xmit_hash_policy_table); i++)
                if (bond_xmit_hash_policy_table[i] && string_equal_fold(name, bond_xmit_hash_policy_table[i]))
                        return i;

        return _BOND_XMIT_HASH_POLICY_INVALID;
}

static const char* const bond_lacp_rate_table[_BOND_LACP_RATE_MAX] = {
        [BOND_LACP_RATE_SLOW] = "slow",
        [BOND_LACP_RATE_FAST] = "fast",
};

const char *bond_lacp_rate_to_name(BondLacpRate id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(bond_lacp_rate_table))
                return NULL;

        return bond_lacp_rate_table[id];
}

int bond_lacp_rate_to_mode(const char *name) {
        assert(name);

        for (size_t i = BOND_LACP_RATE_SLOW; i < (size_t) ELEMENTSOF(bond_lacp_rate_table); i++)
                if (bond_lacp_rate_table[i] && string_equal_fold(name, bond_lacp_rate_table[i]))
                        return i;

        return _BOND_LACP_RATE_INVALID;
}

static const char *const macvlan_mode_table[_MAC_VLAN_MODE_MAX] = {
        [MAC_VLAN_MODE_PRIVATE]  = "private",
        [MAC_VLAN_MODE_VEPA]     = "vepa",
        [MAC_VLAN_MODE_BRIDGE]   = "bridge",
        [MAC_VLAN_MODE_PASSTHRU] = "passthru",
        [MAC_VLAN_MODE_SOURCE]   = "source",
};

const char *macvlan_mode_to_name(MACVLanMode id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(macvlan_mode_table))
                return NULL;

        return macvlan_mode_table[id];
}

int macvlan_name_to_mode(const char *name) {
        assert(name);

        for (size_t i= MAC_VLAN_MODE_PRIVATE; i < (size_t) ELEMENTSOF(macvlan_mode_table); i++)
                if (macvlan_mode_table[i] && string_equal_fold(name, macvlan_mode_table[i]))
                        return i;

        return _MAC_VLAN_MODE_INVALID;
}

static const char *const bond_arp_validate_table[_BOND_ARP_VALIDATE_MAX] = {
        [BOND_ARP_VALIDATE_NONE]   = "none",
        [BOND_ARP_VALIDATE_ACTIVE] = "active",
        [BOND_ARP_VALIDATE_BACKUP] = "backup",
        [BOND_ARP_VALIDATE_ALL]    = "all",
};

const char *bond_arp_validate_mode_to_name(BondArpValidate id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(bond_arp_validate_table))
                return NULL;

        return bond_arp_validate_table[id];
}

int bond_arp_validate_table_name_to_mode(const char *name) {
        assert(name);

        for (size_t i= BOND_ARP_VALIDATE_NONE; i < (size_t) ELEMENTSOF(bond_arp_validate_table); i++)
                if (bond_arp_validate_table[i] && string_equal_fold(name, bond_arp_validate_table[i]))
                        return i;

        return _BOND_ARP_VALIDATE_INVALID;
}

static const char *const ipvlan_mode_table[_IP_VLAN_MODE_MAX] = {
        [IP_VLAN_MODE_L2]  = "L2",
        [IP_VLAN_MODE_L3]  = "L3",
        [IP_VLAN_MODE_L3S] = "L3S",
};

const char *ipvlan_mode_to_name(IPVLanMode id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(ipvlan_mode_table))
                return NULL;

        return ipvlan_mode_table[id];
}

int ipvlan_name_to_mode(const char *name) {
        assert(name);

        for (size_t i = IP_VLAN_MODE_L2; i < (int) ELEMENTSOF(ipvlan_mode_table); i++)
                if (ipvlan_mode_table[i] && string_equal_fold(name, ipvlan_mode_table[i]))
                        return i;

        return _IP_VLAN_MODE_INVALID;
}

static const Config netdev_ctl_name_to_config_table[] = {
                { "vlan",    "VLAN"},
                { "bridge",  "Bridge"},
                { "bond",    "Bond"},
                { "vxlan",   "VXLAN"},
                { "macvlan", "MACVLAN"},
                { "macvtap", "MACVLAN"},
                { "vrf",     "VRF"},
                { "ipvlan",  "IPVLAN"},
                { "ipvtap",  "IPVTAP"},
                { "veth",    "Peer"},
                { "ipip",    "Tunnel"},
                { "gre",     "Tunnel"},
                { "sit",     "Tunnel"},
                { "vti",     "Tunnel"},
                { "tun",     "Tun"},
                { "tap",     "Tap"},
                {},
};

int netdev_ctl_name_to_configs_new(ConfigManager **ret) {
        ConfigManager *m;
        int r;

        r = config_manager_new(netdev_ctl_name_to_config_table, &m);
        if (r < 0)
                return r;

        *ret = steal_pointer(m);
        return 0;
}

static int create_or_parse_netdev_conf_file(const char *ifname, KeyFile **ret) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_ char *file = NULL, *netdev = NULL;
        int r;

        assert(ifname);

        file = string_join("-", "10", ifname, NULL);
        if (!file)
                return log_oom();

        r = create_conf_file("/etc/systemd/network", file, "netdev", &netdev);
        if (r < 0)
                return r;

        r = parse_key_file(netdev, &key_file);
        if (r < 0)
                return r;

        *ret = steal_pointer(key_file);
        return 0;
}

int netdev_new(NetDev **ret) {
        _auto_cleanup_ NetDev *n;

        n = new(NetDev, 1);
        if (!n)
                return log_oom();

        *n = (NetDev) {
                .kind = _NETDEV_KIND_INVALID,
        };

        *ret = steal_pointer(n);
        return 0;
}

void netdev_free(NetDev *n) {
        if (!n)
                return;

        free(n->ifname);
        free(n->mac);
        free(n->master);

        free(n);
}

int vlan_new(VLan **ret) {
        _auto_cleanup_ VLan *v = NULL;

        v = new(VLan, 1);
        if (!v)
                return log_oom();

        *v = (VLan) {
            .gvrp = -1,
            .mvrp = -1,
            .loose_binding = -1,
            .reorder_header = -1,
        };

        *ret = steal_pointer(v);
        return 0;

}

void vlan_free(VLan *v) {
        if (!v)
                return;

        free(v->proto);
        free(v->master);
        free(v);
}

int vxlan_new(VxLan **ret) {
        _auto_cleanup_ VxLan *v = NULL;

        v = new(VxLan, 1);
        if (!v)
                return log_oom();

        *v = (VxLan) {
                .learning = -1,
                .arp_proxy = -1,
                .l2miss = -1,
                .l3miss = -1,
                .udpcsum = -1,
                .udp6zerocsumtx = -1,
                .udp6zerocsumrx = -1,
                .remote_csum_tx = -1,
                .remote_csum_rx = -1,
                .route_short_circuit = -1,
                .df = -1,
                .flow_label = G_MAXUINT,
             };

        *ret = steal_pointer(v);
        return 0;
}

void vxlan_free(VxLan *v) {
        if (!v)
                return;

        free(v->master);
        free(v);
}

int bond_new(Bond **ret) {
        _auto_cleanup_ Bond *b = NULL;

        b = new(Bond, 1);
        if (!b)
                return log_oom();

        *b = (Bond) {
                .mode = BOND_MODE_ROUNDROBIN,
                .xmit_hash_policy = _BOND_XMIT_HASH_POLICY_INVALID,
                .arp_validate = _BOND_ARP_VALIDATE_INVALID,
                .lacp_rate = _BOND_LACP_RATE_INVALID,
                .mii_monitor_interval = UINT64_MAX,
                .resend_igmp = RESEND_IGMP_MAX + 1,
                .packets_per_slave = PACKETS_PER_SLAVE_MAX + 1,
                .ngrat_arp = GRATUITOUS_ARP_MAX + 1,
                .all_slaves_active = -1,
          };

        *ret = steal_pointer(b);
        return 0;
}

void bond_free(Bond *b) {
        if (!b)
                return;

        strv_free(b->arp_ip_targets);
        strv_free(b->interfaces);
        free(b);
}

int wireguard_peer_new(WireGuardPeer **ret) {
        _auto_cleanup_ WireGuardPeer *wg = NULL;

        wg = new0(WireGuardPeer, 1);
        if (!wg)
                return log_oom();

        *ret = steal_pointer(wg);
        return 0;
}

void wireguard_peer_free(WireGuardPeer *wg) {
        if (!wg)
                return;

        free(wg->public_key);
        free(wg->preshared_key);
        free(wg->preshared_key_file);
        free(wg->endpoint);

        strv_free(wg->allowed_ips);

        free(wg);
}

int wireguard_new(WireGuard **ret) {
        _auto_cleanup_ WireGuard *wg = NULL;

        wg = new0(WireGuard, 1);
        if (!wg)
                return log_oom();

        *ret = steal_pointer(wg);
        return 0;
}

void wireguard_free(WireGuard *wg) {
        if (!wg)
                return;

        free(wg->private_key);
        free(wg->private_key_file);

        g_list_free_full(g_list_first(wg->peers), free);
        free(wg);
}

int tunnel_new(Tunnel **ret) {
        Tunnel *t;

        t = new0(Tunnel, 1);
        if (!t)
                return log_oom();

        *ret = steal_pointer(t);
        return 0;
}

void tunnel_free(Tunnel *t) {
        if (!t)
                return;

        free(t);
}

int bridge_new(Bridge **ret) {
        Bridge *t;

        t = new(Bridge, 1);
        if (!t)
                return log_oom();

        *t = (Bridge) {
              .mcast_querier = -1,
              .mcast_snooping = -1,
              .vlan_filtering = -1,
              .vlan_protocol = -1,
              .stp = -1,
              .forward_delay = UINT64_MAX,
              .hello_time = UINT64_MAX,
              .max_age = UINT64_MAX,
              .ageing_time = UINT64_MAX,
          };

        *ret = steal_pointer(t);
        return 0;
}

void bridge_free(Bridge *b) {
        if (!b)
                return;

        strv_free(b->interfaces);
        free(b);
}

int tuntap_new(TunTap **ret) {
        TunTap *t = NULL;

        t = new(TunTap, 1);
        if (!t)
                return log_oom();

        *t = (TunTap) {
            .packet_info = -1,
            .vnet_hdr = -1,
            .keep_carrier = -1,
            .multi_queue = -1,
        };

        *ret = steal_pointer(t);
        return 0;
}

void tuntap_free(TunTap *t) {
        if (!t)
                return;

        free(t->user);
        free(t->group);
        free(t);
}

int vrf_new(VRF **ret) {
        VRF *v;

        v = new0(VRF, 1);
        if (!v)
                return -ENOMEM;

        *ret = v;
        return 0;
}

void vrf_free(VRF *v) {
        if (!v)
                return;

        strv_free(v->interfaces);
        free(v);
}

int veth_new(Veth **ret) {
        Veth *v;

        v = new0(Veth, 1);
        if (!v)
                return log_oom();

        *ret = v;
        return 0;
}

void veth_free(Veth *v) {
        if (!v)
                return;

        free(v->peer);
        free(v);
}

int macvlan_new(MACVLan **ret) {
        MACVLan *m;

        m = new(MACVLan, 1);
        if (!m)
                return log_oom();

        *m = (MACVLan) {
                      .mode = _MAC_VLAN_MODE_INVALID,
             };

        *ret = m;
        return 0;
}

void macvlan_free(MACVLan *m) {
        if (!m)
                return;

        free(m);
}

int ipvlan_new(IPVLan **ret) {
        IPVLan *v;

        v = new(IPVLan, 1);
        if (!v)
                return -ENOMEM;

        *v = (IPVLan) {
                     .mode = _IP_VLAN_MODE_INVALID,
             };

        *ret = v;
        return 0;
}

void ipvlan_free(IPVLan *v) {
        if (!v)
                return;

        free(v);
}

int generate_netdev_config(NetDev *n) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert(n);

        r = create_or_parse_netdev_conf_file(n->ifname, &key_file);
        if (r < 0)
                return 0;

        r = key_file_set_string(key_file, "NetDev", "Name", n->ifname);
        if (r < 0)
                return r;

        r = key_file_set_string(key_file, "NetDev", "Kind", netdev_kind_to_name(n->kind));
        if (r < 0)
                return r;

        switch (n->kind) {
                case NETDEV_KIND_BRIDGE:
                        if (n->bridge->mcast_querier >= 0) {
                                r = key_file_set_string(key_file, "Bridge", "MulticastQuerier", bool_to_string(n->bridge->mcast_querier));
                                if (r < 0)
                                        return r;
                        }
                        if (n->bridge->mcast_snooping >= 0) {
                                r = key_file_set_string(key_file, "Bridge", "MulticastSnooping", bool_to_string(n->bridge->mcast_snooping));
                                if (r < 0)
                                        return r;
                        }
                        if (n->bridge->vlan_filtering >= 0) {
                                r = key_file_set_string(key_file, "Bridge", "VLANFiltering", bool_to_string(n->bridge->vlan_filtering));
                                if (r < 0)
                                        return r;
                        }
                        if (n->bridge->vlan_protocol >= 0) {
                                r = key_file_set_string(key_file, "Bridge", "VLANProtocol", bool_to_string(n->bridge->vlan_protocol));
                                if (r < 0)
                                        return r;
                        }
                        if (n->bridge->stp >= 0) {
                                r = key_file_set_string(key_file, "Bridge", "STP", bool_to_string(n->bridge->stp));
                                if (r < 0)
                                        return r;
                        }

                        if (n->bridge->forward_delay != UINT64_MAX) {
                                r = key_file_set_uint(key_file, "Bridge", "ForwardDelaySec", n->bridge->forward_delay);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bridge->hello_time != UINT64_MAX) {
                                r = key_file_set_uint(key_file, "Bridge", "HelloTimeSec", n->bridge->hello_time);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bridge->ageing_time != UINT64_MAX) {
                                r = key_file_set_uint(key_file, "Bridge", "AgeingTimeSec", n->bridge->ageing_time);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bridge->max_age != UINT64_MAX) {
                                r = key_file_set_uint(key_file, "Bridge", "MaxAgeSec", n->bridge->max_age);
                                if (r < 0)
                                        return r;
                        }

                        break;
                case NETDEV_KIND_VLAN:
                        r = key_file_set_uint(key_file, "VLAN", "Id", n->vlan->id);
                        if (r < 0)
                                return r;

                        if (n->vlan->proto) {
                                r = key_file_set_string(key_file, "VLAN", "Protocol", n->vlan->proto);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vlan->gvrp >= 0) {
                                r = key_file_set_string(key_file, "VLAN", "GVRP", bool_to_string(n->vlan->gvrp));
                                if (r < 0)
                                        return r;
                        }

                        if (n->vlan->mvrp >= 0) {
                                r = key_file_set_string(key_file, "VLAN", "MVRP", bool_to_string(n->vlan->mvrp));
                                if (r < 0)
                                        return r;
                        }

                        if (n->vlan->loose_binding >= 0) {
                                r = key_file_set_string(key_file, "VLAN", "LooseBinding", bool_to_string(n->vlan->loose_binding));
                                if (r < 0)
                                        return r;
                        }

                        if (n->vlan->reorder_header >= 0) {
                                r = key_file_set_string(key_file, "VLAN", "ReorderHeader", bool_to_string(n->vlan->reorder_header));
                                if (r < 0)
                                        return r;
                        }

                        break;

                case NETDEV_KIND_BOND:
                        r = key_file_set_string(key_file, "Bond", "Mode", bond_mode_to_name(n->bond->mode));
                        if (r < 0)
                                return r;

                        if (n->bond->xmit_hash_policy != _BOND_XMIT_HASH_POLICY_INVALID) {
                                r = key_file_set_string(key_file, "Bond", "TransmitHashPolicy", bond_xmit_hash_policy_to_name(n->bond->xmit_hash_policy));
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->lacp_rate != _BOND_LACP_RATE_INVALID) {
                                r = key_file_set_string(key_file, "Bond", "LACPTransmitRate", bond_lacp_rate_to_name(n->bond->lacp_rate));
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->arp_validate != _BOND_ARP_VALIDATE_INVALID) {
                                r = key_file_set_string(key_file, "Bond", "ARPValidate", bond_arp_validate_mode_to_name(n->bond->arp_validate));
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->mii_monitor_interval != UINT64_MAX) {
                                r = key_file_set_uint(key_file, "Bond", "MIIMonitorSec", n->bond->mii_monitor_interval);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->min_links > 0) {
                                r = key_file_set_uint(key_file, "Bond", "MinLinks", n->bond->min_links);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->arp_interval > 0) {
                                r = key_file_set_uint(key_file, "Bond", "ARPIntervalSec", n->bond->arp_interval);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->up_delay > 0) {
                                r = key_file_set_uint(key_file, "Bond", "UpDelaySec", n->bond->up_delay);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->down_delay > 0) {
                                r = key_file_set_uint(key_file, "Bond", "DownDelaySec", n->bond->down_delay);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->lp_interval > 0) {
                                r = key_file_set_uint(key_file, "Bond", "LearnPacketIntervalSec", n->bond->lp_interval);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->resend_igmp <= RESEND_IGMP_MAX) {
                                r = key_file_set_uint(key_file, "Bond", "ResendIGMP", n->bond->resend_igmp);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->packets_per_slave <= PACKETS_PER_SLAVE_MAX) {
                                r = key_file_set_uint(key_file, "Bond", "PacketsPerSlave", n->bond->packets_per_slave);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->ngrat_arp <= GRATUITOUS_ARP_MAX) {
                                r = key_file_set_uint(key_file, "Bond", "GratuitousARP", n->bond->ngrat_arp);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->all_slaves_active >= 0) {
                                r = key_file_set_bool(key_file, "Bond", "AllSlavesActive", n->bond->all_slaves_active);
                                if (r < 0)
                                        return r;
                        }

                        if (n->bond->arp_ip_targets && strv_length(n->bond->arp_ip_targets) > 0) {
                                _cleanup_(g_string_unrefp) GString *c = NULL;
                                char **d;

                                c = g_string_new(NULL);
                                if (!c)
                                        return log_oom();

                                strv_foreach(d,n->bond->arp_ip_targets) {
                                        g_string_append_printf(c, "%s ", *d);
                                }

                                r = key_file_set_string(key_file, "Bond", "ARPIPTargets", c->str);
                                if (r < 0)
                                        return r;
                        }

                        break;

                case NETDEV_KIND_VXLAN: {
                        _auto_cleanup_ char *local = NULL, *remote = NULL, *group = NULL;

                        r = key_file_set_uint(key_file, "VXLAN", "VNI", n->vxlan->vni);
                        if (r <0)
                                return r;

                        if (!ip_is_null(&n->vxlan->local)) {
                                (void) ip_to_string(n->vxlan->local.family, &n->vxlan->local, &local);
                                r = key_file_set_string(key_file, "VXLAN", "Local", local);
                                if (r < 0)
                                        return r;
                        }

                        if (!ip_is_null(&n->vxlan->remote)) {
                                (void) ip_to_string(n->vxlan->remote.family, &n->vxlan->remote, &remote);
                                r = key_file_set_string(key_file, "VXLAN", "Remote", remote);
                                if (r < 0)
                                        return r;
                        }

                        if (!ip_is_null(&n->vxlan->group)) {
                                (void) ip_to_string(n->vxlan->group.family, &n->vxlan->group, &group);
                                r = key_file_set_string(key_file, "VXLAN", "Group", group);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->destination_port > 0) {
                                r = key_file_set_uint(key_file, "VXLAN", "DestinationPort", n->vxlan->destination_port);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->independent)  {
                                r = key_file_set_bool(key_file, "VXLAN", "Independent", n->vxlan->independent);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->tos > 0)  {
                                r = key_file_set_uint(key_file, "VXLAN", "TOS", n->vxlan->tos);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->learning != -1)  {
                                r = key_file_set_bool(key_file, "VXLAN", "MacLearning", n->vxlan->learning);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->arp_proxy >= -1)  {
                                r = key_file_set_bool(key_file, "VXLAN", "ReduceARPProxy", n->vxlan->arp_proxy);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->fdb_ageing > 0)  {
                                r = key_file_set_uint(key_file, "VXLAN", "FDBAgeingSec", n->vxlan->fdb_ageing);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->flow_label != G_MAXUINT)  {
                                r = key_file_set_uint(key_file, "VXLAN", "FlowLabel", n->vxlan->flow_label);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->max_fdb > 0)  {
                                r = key_file_set_uint(key_file, "VXLAN", "MaximumFDBEntries", n->vxlan->max_fdb);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->df >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "IPDoNotFragment", n->vxlan->df);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->l2miss >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "L2MissNotification", n->vxlan->l2miss);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->l3miss >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "L3MissNotification", n->vxlan->l2miss);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->route_short_circuit >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "RouteShortCircuit", n->vxlan->route_short_circuit);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->udpcsum >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "UDPChecksum", n->vxlan->udpcsum);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->udp6zerocsumtx >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "UDP6ZeroChecksumTx", n->vxlan->udp6zerocsumtx);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->udp6zerocsumrx >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "UDP6ZeroChecksumRx", n->vxlan->udp6zerocsumrx);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->remote_csum_tx >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "RemoteChecksumTx", n->vxlan->remote_csum_tx);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->remote_csum_rx >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "RemoteChecksumRx", n->vxlan->remote_csum_rx);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->group_policy >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "GroupPolicyExtension", n->vxlan->group_policy);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->generic_protocol_extension >= 0)  {
                                r = key_file_set_bool(key_file, "VXLAN", "GenericProtocolExtension", n->vxlan->generic_protocol_extension);
                                if (r < 0)
                                        return r;
                        }

                        if (n->vxlan->high_port > n->vxlan->low_port)  {
                                _cleanup_(g_string_unrefp) GString *v = NULL;

                                v = g_string_new(NULL);
                                if (!v)
                                        return -ENOMEM;

                                g_string_append_printf(v, "%u-%u", n->vxlan->low_port, n->vxlan->high_port);

                                r = key_file_set_string(key_file, "VXLAN", "PortRange", v->str);
                                if (r < 0)
                                        return r;
                        }

                }
                        break;

                case NETDEV_KIND_MACVLAN:
                        r = key_file_set_string(key_file, "MACVLAN", "Mode", macvlan_mode_to_name(n->macvlan->mode));
                        if (r < 0)
                                return r;

                        break;

                case NETDEV_KIND_MACVTAP:
                        r = key_file_set_string(key_file, "MACVTAP", "Mode", macvlan_mode_to_name(n->macvlan->mode));
                        if (r < 0)
                                return r;

                        break;

                case NETDEV_KIND_IPVLAN:
                        r = key_file_set_string(key_file, "IPVLAN", "Mode", ipvlan_mode_to_name(n->ipvlan->mode));
                        if (r < 0)
                                return r;

                        break;

                case NETDEV_KIND_IPVTAP:
                        r = key_file_set_string(key_file, "IPVTAP", "Mode", ipvlan_mode_to_name(n->ipvlan->mode));
                        if (r < 0)
                                return r;

                        break;

                case NETDEV_KIND_VETH:
                        if (n->veth && n->veth->peer) {
                                r = key_file_set_string(key_file, "Peer", "Name", n->veth->peer);
                                if (r < 0)
                                        return r;
                        }
                        break;

                case NETDEV_KIND_VRF:
                        r = key_file_set_uint(key_file, "VRF", "Table", n->vrf->table);
                        if (r < 0)
                                return r;

                        break;
                case NETDEV_KIND_TUN:
                case NETDEV_KIND_TAP:
                        if (n->tun_tap->user) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "User", n->tun_tap->user);
                                if (r < 0)
                                        return r;
                        }

                        if (n->tun_tap->group) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "Group", n->tun_tap->group);
                                if (r < 0)
                                        return r;
                        }

                        if (n->tun_tap->packet_info >= 0) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "PacketInfo", bool_to_string(n->tun_tap->packet_info));
                                if (r < 0)
                                        return r;
                        }

                        if (n->tun_tap->vnet_hdr >= 0) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "VNetHeader", bool_to_string(n->tun_tap->vnet_hdr));
                                if (r < 0)
                                        return r;
                        }

                        if (n->tun_tap->keep_carrier >= 0) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "KeepCarrier", bool_to_string(n->tun_tap->keep_carrier));
                                if (r < 0)
                                        return r;
                        }

                        if (n->tun_tap->multi_queue >= 0) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "MultiQueue", bool_to_string(n->tun_tap->multi_queue));
                                if (r < 0)
                                        return r;
                        }

                        break;

                case NETDEV_KIND_IPIP_TUNNEL:
                case NETDEV_KIND_SIT_TUNNEL:
                case NETDEV_KIND_GRE_TUNNEL:
                case NETDEV_KIND_VTI_TUNNEL: {
                        _auto_cleanup_ char *local = NULL, *remote = NULL;

                        if (n->tunnel->independent) {
                                r = key_file_set_bool(key_file, "Tunnel", "Independent", n->tunnel->independent);
                                if (r < 0)
                                        return r;
                        }

                        if (!ip_is_null(&n->tunnel->local)) {
                                (void) ip_to_string(n->tunnel->local.family, &n->tunnel->local, &local);
                                r = key_file_set_string(key_file, "Tunnel", "Local", local);
                                if (r < 0)
                                        return r;
                        }

                        if (!ip_is_null(&n->tunnel->remote)) {
                                (void) ip_to_string(n->tunnel->remote.family, &n->tunnel->remote, &remote);
                                r = key_file_set_string(key_file, "Tunnel", "Remote", remote);
                                if (r < 0)
                                        return r;
                        }

                        if (n->tunnel->key > 0) {
                                r = key_file_set_uint(key_file, "Tunnel", "Key", n->tunnel->key);
                                if (r < 0)
                                        return r;
                        }

                        if (n->tunnel->ikey > 0) {
                                r = key_file_set_uint(key_file, "Tunnel", "InputKey", n->tunnel->ikey);
                                if (r < 0)
                                        return r;
                        }

                        if (n->tunnel->okey > 0) {
                                r = key_file_set_uint(key_file, "Tunnel", "OutputKey", n->tunnel->okey);
                                if (r < 0)
                                        return r;
                        }

                        if (n->tunnel->ttl > 0) {
                                r = key_file_set_uint(key_file, "Tunnel", "TTL", n->tunnel->ttl);
                                if (r < 0)
                                        return r;
                        }
                }
                        break;

                case NETDEV_KIND_WIREGUARD: {
                        GList *iter;

                        if (n->wg->private_key) {
                                r = key_file_set_string(key_file, "WireGuard", "PrivateKey", n->wg->private_key);
                                if (r < 0)
                                        return r;
                        }

                        if (n->wg->private_key_file) {
                                r = key_file_set_string(key_file, "WireGuard", "PrivateKeyFile", n->wg->private_key_file);
                                if (r < 0)
                                        return r;
                        }

                        if (n->wg->listen_port > 0) {
                                r = key_file_set_uint(key_file, "WireGuard", "ListenPort", n->wg->listen_port);
                                if (r < 0)
                                        return r;
                        }

                        for (iter = n->wg->peers; iter; iter = g_list_next (iter)) {
                                WireGuardPeer *peer = (WireGuardPeer *) iter->data;
                                _cleanup_(section_freep) Section *section = NULL;

                                r = section_new("WireGuardPeer", &section);
                                if (r < 0)
                                        return r;

                                if (peer->public_key) {
                                        r = add_key_to_section(section, "PublicKey", peer->public_key);
                                        if (r < 0)
                                                return r;
                                }

                                if (peer->endpoint) {
                                        r = add_key_to_section(section, "Endpoint", peer->endpoint);
                                        if (r < 0)
                                                return r;
                                }

                                if (peer->preshared_key) {

                                        r = add_key_to_section(section, "PresharedKey", peer->preshared_key);
                                        if (r < 0)
                                                return r;
                                }

                                if (peer->preshared_key_file) {
                                        r = add_key_to_section(section, "PresharedKeyFile", peer->preshared_key_file);
                                        if (r < 0)
                                                return r;
                                }

                                if (peer->allowed_ips) {
                                        _cleanup_(g_string_unrefp) GString *c = NULL;
                                        char **d;

                                        c = g_string_new(NULL);
                                        if (!c)
                                                return log_oom();

                                        strv_foreach(d, peer->allowed_ips) {
                                                g_string_append_printf(c, "%s ", *d);
                                        }

                                        r = add_key_to_section(section, "AllowedIPs", c->str);
                                        if (r < 0)
                                                return r;
                                }

                                if (peer->persistent_keep_alive > 0) {
                                        r = add_key_to_section_uint(section, "PersistentKeepalive", peer->persistent_keep_alive);
                                        if (r < 0)
                                                return r;
                                }

                                r = add_section_to_key_file(key_file, section);
                                if (r < 0)
                                        return r;

                                steal_pointer(section);
                        }
                }

                        break;
                default:
                        break;
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return set_file_permisssion(key_file->name, "systemd-network");
}

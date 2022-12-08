/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "config-parser.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "netdev.h"
#include "parse-util.h"
#include "string-util.h"

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

        n = new0(NetDev, 1);
        if (!n)
                return log_oom();

        *n = (NetDev) {
                .kind = _NETDEV_KIND_INVALID,
                .tun_tap.packet_info = -1,
                .tun_tap.vnet_hdr = -1,
                .tun_tap.keep_carrier = -1,
                .tun_tap.multi_queue = -1,
        };

        *ret = steal_pointer(n);
        return 0;
}

void netdev_unref(NetDev *n) {
        if (!n)
                return;

        free(n->ifname);
        free(n->peer);
        free(n->mac);

        free(n->tun_tap.user);
        free(n->tun_tap.group);

        free(n);
}

int vlan_new(VLan **ret) {
        _auto_cleanup_ VLan *v = NULL;

        v = new0(VLan, 1);
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

void vlan_unref(VLan *v) {
        if (!v)
                return;

        free(v->proto);
        free(v);
}

int vxlan_new(VxLan **ret) {
        _auto_cleanup_ VxLan *v = NULL;

        v = new0(VxLan, 1);
        if (!v)
                return log_oom();

        *ret = steal_pointer(v);
        return 0;

}

void vxlan_unref(VxLan *v) {
        if (!v)
                return;

        free(v);
}

int wireguard_new(WireGuard **ret) {
        _auto_cleanup_ WireGuard *wg = NULL;

        wg = new0(WireGuard, 1);
        if (!wg)
                return log_oom();

        *ret = steal_pointer(wg);
        return 0;

}

void wireguard_unref(WireGuard *wg) {
        if (!wg)
                return;

        free(wg->private_key);
        free(wg->private_key_file);
        free(wg->public_key);
        free(wg->preshared_key);
        free(wg->preshared_key_file);
        free(wg->endpoint);
        free(wg->allowed_ips);
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

void tunnel_unref(Tunnel *t) {
        if (!t)
                return;

        free(t);
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
                case NETDEV_KIND_VLAN:
                        r = key_file_set_uint(key_file, "VLAN", "Id", n->vlan->id);
                        if (r < 0)
                                return r;

                        if (n->vlan->proto) {
                                r = key_file_set_string(key_file, "VLAN", "Protocol", n->vlan->proto);
                                if (r < 0)
                                        return r;
                        }
                        if (n->vlan->gvrp != -1) {
                                r = key_file_set_string(key_file, "VLAN", "GVRP", bool_to_string(n->vlan->gvrp));
                                if (r < 0)
                                        return r;
                        }
                        if (n->vlan->mvrp != -1) {
                                r = key_file_set_string(key_file, "VLAN", "MVRP", bool_to_string(n->vlan->mvrp));
                                if (r < 0)
                                        return r;
                        }

                        if (n->vlan->loose_binding != -1) {
                                r = key_file_set_string(key_file, "VLAN", "LooseBinding", bool_to_string(n->vlan->loose_binding));
                                if (r < 0)
                                        return r;
                        }
                        if (n->vlan->reorder_header != -1) {
                                r = key_file_set_string(key_file, "VLAN", "ReorderHeader", bool_to_string(n->vlan->reorder_header));
                                if (r < 0)
                                        return r;
                        }

                        break;

                case NETDEV_KIND_BOND:
                        r = key_file_set_string(key_file, "Bond", "Mode", bond_mode_to_name(n->bond_mode));
                        if (r < 0)
                                return r;

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
                }
                        break;

                case NETDEV_KIND_MACVLAN:
                        r = key_file_set_string(key_file, "MACVLAN", "Mode", macvlan_mode_to_name(n->macvlan_mode));
                        if (r < 0)
                                return r;

                        break;

                case NETDEV_KIND_MACVTAP:
                        r = key_file_set_string(key_file, "MACVTAP", "Mode", macvlan_mode_to_name(n->macvlan_mode));
                        if (r < 0)
                                return r;

                        break;

                case NETDEV_KIND_IPVLAN:
                        r = key_file_set_string(key_file, "IPVLAN", "Mode", ipvlan_mode_to_name(n->ipvlan_mode));
                        if (r < 0)
                                return r;

                        break;

                case NETDEV_KIND_IPVTAP:
                        r = key_file_set_string(key_file, "IPVTAP", "Mode", ipvlan_mode_to_name(n->ipvlan_mode));
                        if (r < 0)
                                return r;

                        break;

                case NETDEV_KIND_VETH:
                        if (n->peer) {
                                r = key_file_set_string(key_file, "Peer", "Name", n->peer);
                                if (r < 0)
                                        return r;
                        }
                        break;

                case NETDEV_KIND_VRF:
                        r = key_file_set_uint(key_file, "VRF", "Table", n->table);
                        if (r < 0)
                                return r;

                        break;
                case NETDEV_KIND_TUN:
                case NETDEV_KIND_TAP:
                        if (n->tun_tap.user) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "User", n->tun_tap.user);
                                if (r < 0)
                                        return r;
                        }

                        if (n->tun_tap.group) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "Group", n->tun_tap.group);
                                if (r < 0)
                                        return r;
                        }

                        if (n->tun_tap.packet_info != -1) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "PacketInfo", bool_to_string(n->tun_tap.packet_info));
                                if (r < 0)
                                        return r;
                        }

                        if (n->tun_tap.vnet_hdr != -1) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "VNetHeader", bool_to_string(n->tun_tap.vnet_hdr));
                                if (r < 0)
                                        return r;
                        }

                        if (n->tun_tap.keep_carrier != -1) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "KeepCarrier", bool_to_string(n->tun_tap.keep_carrier));
                                if (r < 0)
                                        return r;
                        }

                        if (n->tun_tap.multi_queue != -1) {
                                r = key_file_set_string(key_file, n->kind == NETDEV_KIND_TUN ? "Tun" : "Tap", "MultiQueue", bool_to_string(n->tun_tap.multi_queue));
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
                }
                        break;

                case NETDEV_KIND_WIREGUARD:
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

                        if (n->wg->public_key) {
                                r = key_file_set_string(key_file, "WireGuardPeer", "PublicKey", n->wg->public_key);
                                if (r < 0)
                                        return r;
                        }

                        if (n->wg->endpoint) {
                                r = key_file_set_string(key_file, "WireGuardPeer", "Endpoint", n->wg->endpoint);
                                if (r < 0)
                                        return r;
                        }

                        if (n->wg->preshared_key) {
                                r = key_file_set_string(key_file, "WireGuardPeer", "PresharedKey", n->wg->preshared_key);
                                if (r < 0)
                                        return r;
                        }

                        if (n->wg->preshared_key_file) {
                                r = key_file_set_string(key_file, "WireGuardPeer", "PresharedKeyFile", n->wg->preshared_key_file);
                                if (r < 0)
                                        return r;
                        }

                        if (n->wg->allowed_ips) {
                                r = key_file_set_string(key_file, "WireGuardPeer", "AllowedIPs", n->wg->allowed_ips);
                                if (r < 0)
                                        return r;
                        }

                        if (n->wg->persistent_keep_alive > 0) {
                                r = key_file_set_uint(key_file, "WireGuardPeer", "PersistentKeepalive", n->wg->persistent_keep_alive);
                                if (r < 0)
                                        return r;
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

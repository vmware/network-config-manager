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

static const char *const netdev_kind_table[_NET_DEV_KIND_MAX] = {
        [NET_DEV_KIND_VLAN]        = "vlan",
        [NET_DEV_KIND_BRIDGE]      = "bridge",
        [NET_DEV_KIND_BOND]        = "bond",
        [NET_DEV_KIND_VXLAN]       = "vxlan",
        [NET_DEV_KIND_MACVLAN]     = "macvlan",
        [NET_DEV_KIND_MACVTAP]     = "macvtap",
        [NET_DEV_KIND_IPVLAN]      = "ipvlan",
        [NET_DEV_KIND_IPVTAP]      = "ipvtap",
        [NET_DEV_KIND_VRF]         = "vrf",
        [NET_DEV_KIND_VETH]        = "veth",
        [NET_DEV_KIND_IPIP_TUNNEL] = "ipip",
        [NET_DEV_KIND_SIT_TUNNEL]  = "sit",
        [NET_DEV_KIND_GRE_TUNNEL]  = "gre",
        [NET_DEV_KIND_VTI_TUNNEL]  = "vti",
        [NET_DEV_KIND_WIREGUARD]   = "wireguard",
};

const char *netdev_kind_to_name(NetDevKind id) {
        if (id < 0)
                return "n/a";

        if ((size_t) id >= ELEMENTSOF(netdev_kind_table))
                return NULL;

        return netdev_kind_table[id];
}

int netdev_name_to_kind(const char *name) {
        assert(name);

        for (size_t i = NET_DEV_KIND_VLAN; i < (int) ELEMENTSOF(netdev_kind_table); i++)
                if (netdev_kind_table[i] && string_equal_fold(name, netdev_kind_table[i]))
                        return i;

        return _NET_DEV_KIND_INVALID;
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
                return "n/a";

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
                return "n/a";

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
                return "n/a";

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
                { "ipip",    "Tunnel"},
                { "gre",     "Tunnel"},
                { "sit",     "Tunnel"},
                { "vti",     "Tunnel"},
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
                .kind = _NET_DEV_KIND_INVALID,
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

        free(n->wg_private_key);
        free(n->wg_public_key);
        free(n->wg_preshared_key);
        free(n->wg_endpoint);
        free(n->wg_allowed_ips);
        free(n->wg_allowed_ips);

        free(n->proto);

        free(n);
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
                case NET_DEV_KIND_VLAN:
                        r = key_file_set_uint(key_file, "VLAN", "Id", n->id);
                        if (r < 0)
                                return r;

                        if (n->proto) {
                                r = key_file_set_string(key_file, "VLAN", "Protocol", n->proto);
                                if (r < 0)
                                        return r;
                        }
                        break;

                case NET_DEV_KIND_BOND:
                        r = key_file_set_string(key_file, "Bond", "Mode", bond_mode_to_name(n->bond_mode));
                        if (r < 0)
                                return r;

                        break;

                case NET_DEV_KIND_VXLAN: {
                        _auto_cleanup_ char *local = NULL, *remote = NULL, *group = NULL;

                        r = key_file_set_uint(key_file, "VXLAN", "VNI", n->id);
                        if (r < 0)
                                return r;

                        if (!ip_is_null(&n->local)) {
                                (void) ip_to_string(n->local.family, &n->local, &local);
                                r = key_file_set_string(key_file, "VXLAN", "Local", local);
                                if (r < 0)
                                        return r;
                        }

                        if (!ip_is_null(&n->remote)) {
                                (void) ip_to_string(n->remote.family, &n->remote, &remote);
                                r = key_file_set_string(key_file, "VXLAN", "Remote", remote);
                                if (r < 0)
                                        return r;
                        }

                        if (!ip_is_null(&n->group)) {
                                (void) ip_to_string(n->group.family, &n->group, &group);
                                r = key_file_set_string(key_file, "VXLAN", "Group", group);
                                if (r < 0)
                                        return r;
                        }

                        if (n->destination_port > 0) {
                                r = key_file_set_uint(key_file, "VXLAN", "DestinationPort", n->destination_port);
                                if (r < 0)
                                        return r;
                        }

                        if (n->independent)  {
                                r = key_file_set_bool(key_file, "VXLAN", "Independent", n->independent);
                                if (r < 0)
                                        return r;
                        }
                }
                        break;

                case NET_DEV_KIND_MACVLAN:
                        r = key_file_set_string(key_file, "MACVLAN", "Mode", macvlan_mode_to_name(n->macvlan_mode));
                        if (r < 0)
                                return r;

                        break;

                case NET_DEV_KIND_MACVTAP:
                        r = key_file_set_string(key_file, "MACVTAP", "Mode", macvlan_mode_to_name(n->macvlan_mode));
                        if (r < 0)
                                return r;

                        break;

                case NET_DEV_KIND_IPVLAN:
                        r = key_file_set_string(key_file, "IPVLAN", "Mode", ipvlan_mode_to_name(n->ipvlan_mode));
                        if (r < 0)
                                return r;

                        break;

                case NET_DEV_KIND_IPVTAP:
                        r = key_file_set_string(key_file, "IPVTAP", "Mode", ipvlan_mode_to_name(n->ipvlan_mode));
                        if (r < 0)
                                return r;

                        break;

                case NET_DEV_KIND_VETH:
                        if (n->peer) {
                                r = key_file_set_string(key_file, "Peer", "Name", n->peer);
                                if (r < 0)
                                        return r;
                        }
                        break;

                case NET_DEV_KIND_VRF:
                        r = key_file_set_uint(key_file, "VRF", "Table", n->table);
                        if (r < 0)
                                return r;

                        break;

                case NET_DEV_KIND_IPIP_TUNNEL:
                case NET_DEV_KIND_SIT_TUNNEL:
                case NET_DEV_KIND_GRE_TUNNEL:
                case NET_DEV_KIND_VTI_TUNNEL: {
                        _auto_cleanup_ char *local = NULL, *remote = NULL;

                        if (n->independent) {
                                r = key_file_set_bool(key_file, "Tunnel", "Independent", n->independent);
                                if (r < 0)
                                        return r;
                        }

                        if (!ip_is_null(&n->local)) {
                                (void) ip_to_string(n->local.family, &n->local, &local);
                                r = key_file_set_string(key_file, "Tunnel", "Local", local);
                                if (r < 0)
                                        return r;
                        }

                        if (!ip_is_null(&n->remote)) {
                                (void) ip_to_string(n->remote.family, &n->remote, &remote);
                                r = key_file_set_string(key_file, "Tunnel", "Remote", remote);
                                if (r < 0)
                                        return r;
                        }
                }
                        break;

                case NET_DEV_KIND_WIREGUARD:
                        r = key_file_set_string(key_file, "WireGuard", "PrivateKey", n->wg_private_key);
                        if (r < 0)
                                return r;

                        if (n->listen_port > 0) {
                                r = key_file_set_uint(key_file, "WireGuard", "ListenPort", n->listen_port);
                                if (r < 0)
                                        return r;
                        }

                        r = key_file_set_string(key_file, "WireGuard", "PublicKey", n->wg_public_key);
                        if (r < 0)
                                return r;

                        if (n->wg_endpoint) {
                                r = key_file_set_string(key_file, "WireGuard", "Endpoint", n->wg_endpoint);
                                if (r < 0)
                                        return r;
                        }
                        if (n->wg_preshared_key) {
                                r = key_file_set_string(key_file, "WireGuard", "PresharedKey", n->wg_preshared_key);
                                if (r < 0)
                                        return r;
                        }
                        if (n->wg_allowed_ips) {
                                r = key_file_set_string(key_file, "WireGuard", "AllowedIPs", n->wg_allowed_ips);
                                if (r < 0)
                                        return r;
                        }
                        break;
                default:
                        break;
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, g_strerror(-r));
                return r;
        }

        r = set_file_permisssion(key_file->name, "systemd-network");
        if (r < 0)
                return r;

        return 0;
}

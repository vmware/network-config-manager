/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
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

        *ret = m;
        return 0;
}

int create_netdev_conf_file(const char *ifname, char **ret) {
        _auto_cleanup_ char *file = NULL, *netdev = NULL;
        int r;

        assert(ifname);

        file = string_join("-", "10", ifname, NULL);
        if (!file)
                return log_oom();

        r = create_conf_file("/etc/systemd/network", file, "netdev", &netdev);
        if (r < 0)
                return r;

        *ret = steal_pointer(netdev);
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

int generate_netdev_config(NetDev *n, GString **ret) {
        _cleanup_(g_string_unrefp) GString *config = NULL;

        assert(n);

        if (!netdev_kind_to_name(n->kind))
                return -EINVAL;

        config = g_string_new(NULL);
        if (!config)
                return log_oom();

        g_string_append(config, "[NetDev]\n");
        if (n->ifname)
                g_string_append_printf(config, "Name=%s\n", n->ifname);

        g_string_append_printf(config, "Kind=%s\n\n", netdev_kind_to_name(n->kind));

        switch (n->kind) {
                case NET_DEV_KIND_VLAN:
                        g_string_append(config, "[VLAN]\n");
                        g_string_append_printf(config, "Id=%d\n", n->id);

                        if (n->proto)
                                g_string_append_printf(config, "Protocol=%s\n", n->proto);

                        break;

                case NET_DEV_KIND_BOND:
                        g_string_append(config, "[Bond]\n");
                        g_string_append_printf(config, "Mode=%s\n", bond_mode_to_name(n->bond_mode));

                        break;

                case NET_DEV_KIND_VXLAN: {
                        _auto_cleanup_ char *local = NULL, *remote = NULL, *group = NULL;

                        g_string_append(config, "[VXLAN]\n");
                        g_string_append_printf(config, "VNI=%d\n", n->id);

                        if (!ip_is_null(&n->local)) {
                                (void) ip_to_string(n->local.family, &n->local, &local);
                                g_string_append_printf(config, "Local=%s\n", local);
                        }

                        if (!ip_is_null(&n->remote)) {
                                (void) ip_to_string(n->remote.family, &n->remote, &remote);
                                g_string_append_printf(config, "Remote=%s\n", remote);
                        }

                        if (!ip_is_null(&n->group)) {
                                (void) ip_to_string(n->group.family, &n->group, &group);
                                g_string_append_printf(config, "Group=%s\n", group);
                        }

                        if (n->destination_port > 0)
                                g_string_append_printf(config, "DestinationPort=%d\n", n->destination_port);
                }
                        break;

                case NET_DEV_KIND_MACVLAN:
                        g_string_append(config, "[MACVLAN]\n");
                        g_string_append_printf(config, "Mode=%s\n", macvlan_mode_to_name(n->macvlan_mode));

                        break;

                case NET_DEV_KIND_MACVTAP:
                        g_string_append(config, "[MACVTAP]\n");
                        g_string_append_printf(config, "Mode=%s\n", macvlan_mode_to_name(n->macvlan_mode));

                        break;

                case NET_DEV_KIND_IPVLAN:
                        g_string_append(config, "[IPVLAN]\n");
                        g_string_append_printf(config, "Mode=%s\n", ipvlan_mode_to_name(n->ipvlan_mode));

                        break;

                case NET_DEV_KIND_IPVTAP:
                        g_string_append(config, "[IPVTAP]\n");
                        g_string_append_printf(config, "Mode=%s\n", ipvlan_mode_to_name(n->ipvlan_mode));

                        break;

                case NET_DEV_KIND_VETH:
                        if (n->peer) {
                                g_string_append(config, "[Peer]\n");
                                g_string_append_printf(config, "Name=%s\n", n->peer);
                        }
                        break;

                case NET_DEV_KIND_VRF:
                        g_string_append(config, "[VRF]\n");
                        g_string_append_printf(config, "Table=%d\n", n->table);

                        break;

                case NET_DEV_KIND_IPIP_TUNNEL:
                case NET_DEV_KIND_SIT_TUNNEL:
                case NET_DEV_KIND_GRE_TUNNEL:
                case NET_DEV_KIND_VTI_TUNNEL: {
                        _auto_cleanup_ char *local = NULL, *remote = NULL;

                        g_string_append(config, "[Tunnel]\n");

                        if (!ip_is_null(&n->local)) {
                                (void) ip_to_string(n->local.family, &n->local, &local);
                                g_string_append_printf(config, "Local=%s\n", local);
                        }

                        if (!ip_is_null(&n->remote)) {
                                (void) ip_to_string(n->remote.family, &n->remote, &remote);
                                g_string_append_printf(config, "Remote=%s\n", remote);
                        }
                }
                        break;

                case NET_DEV_KIND_WIREGUARD:
                        g_string_append(config, "[WireGuard]\n");
                        g_string_append_printf(config, "PrivateKey=%s\n", n->wg_private_key);

                        if (n->listen_port > 0)
                                g_string_append_printf(config, "ListenPort=%d\n\n", n->listen_port);

                        g_string_append(config, "[WireGuardPeer]\n");
                        g_string_append_printf(config, "PublicKey=%s\n", n->wg_public_key);

                        if (n->wg_endpoint)
                                g_string_append_printf(config, "Endpoint=%s\n", n->wg_endpoint);

                        if (n->wg_preshared_key)
                                g_string_append_printf(config, "PresharedKey=%s\n", n->wg_preshared_key);

                        if (n->wg_allowed_ips)
                                g_string_append_printf(config, "AllowedIPs=%s\n\n", n->wg_allowed_ips);
                        break;
                default:
                        break;
        }

        *ret = steal_pointer(config);
        return 0;
}

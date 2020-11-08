/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include "alloc-util.h"
#include "file-util.h"
#include "macros.h"
#include "netdev.h"
#include "parse-util.h"
#include "string-util.h"
#include "log.h"

static const char *const netdev_kind[_NET_DEV_KIND_MAX] = {
        [NET_DEV_KIND_VLAN]    = "vlan",
        [NET_DEV_KIND_BRIDGE]  = "bridge",
        [NET_DEV_KIND_BOND]    = "bond",
        [NET_DEV_KIND_VXLAN]   = "vxlan",
        [NET_DEV_KIND_MACVLAN] = "macvlan",
        [NET_DEV_KIND_MACVTAP] = "macvtap",
};

const char *netdev_kind_to_name(NetDevKind id) {
        if (id < 0)
                return "n/a";

        if ((size_t) id >= ELEMENTSOF(netdev_kind))
                return NULL;

        return netdev_kind[id];
}

int netdev_name_to_kind(const char *name) {
        int i;

        assert(name);

        for (i = NET_DEV_KIND_VLAN; i < (int) ELEMENTSOF(netdev_kind); i++)
                if (netdev_kind[i] && string_equal_fold(name, netdev_kind[i]))
                        return i;

        return _NET_DEV_KIND_INVALID;
}

static const char *const bond_mode[_BOND_MODE_MAX] = {
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

        if ((size_t) id >= ELEMENTSOF(bond_mode))
                return NULL;

        return bond_mode[id];
}

int bond_name_to_mode(const char *name) {
        int i;

        assert(name);

        for (i = BOND_MODE_ROUNDROBIN; i < (int) ELEMENTSOF(bond_mode); i++)
                if (bond_mode[i] && string_equal_fold(name, bond_mode[i]))
                        return i;

        return _BOND_MODE_INVALID;
}

static const char *const macvlan_mode[_MAC_VLAN_MODE_MAX] = {
        [MAC_VLAN_MODE_PRIVATE]  = "private",
        [MAC_VLAN_MODE_VEPA]     = "vepa",
        [MAC_VLAN_MODE_BRIDGE]   = "bridge",
        [MAC_VLAN_MODE_PASSTHRU] = "passthru",
        [MAC_VLAN_MODE_SOURCE]   = "source",
};

const char *macvlan_mode_to_name(MACVLanMode id) {
        if (id < 0)
                return "n/a";

        if ((size_t) id >= ELEMENTSOF(macvlan_mode))
                return NULL;

        return macvlan_mode[id];
}

int macvlan_name_to_mode(const char *name) {
        int i;

        assert(name);

        for (i = MAC_VLAN_MODE_PRIVATE; i < (int) ELEMENTSOF(macvlan_mode); i++)
                if (macvlan_mode[i] && string_equal_fold(name, macvlan_mode[i]))
                        return i;

        return _MAC_VLAN_MODE_INVALID;
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

void netdev_unrefp(NetDev **n) {
        if (n && *n) {
                g_free((*n)->ifname);
                g_free(*n);
        }
}

int generate_netdev_config(NetDev *n, GString **ret) {
        _cleanup_(g_string_unrefp) GString *config = NULL;
        _auto_cleanup_ char *gateway = NULL;

        assert(n);

        config = g_string_new(NULL);
        if (!config)
                return log_oom();

        g_string_append(config, "[NetDev]\n");
        if (n->ifname)
                g_string_append_printf(config, "Name=%s\n", n->ifname);

        g_string_append_printf(config, "Kind=%s\n\n", netdev_kind_to_name(n->kind));

        if (n->kind == NET_DEV_KIND_VLAN) {
                g_string_append(config, "[VLAN]\n");
                g_string_append_printf(config, "Id=%d\n", n->id);
        }

        if (n->kind == NET_DEV_KIND_BOND) {
                g_string_append(config, "[Bond]\n");
                g_string_append_printf(config, "Mode=%s\n", bond_mode_to_name(n->bond_mode));
        }

        if (n->kind == NET_DEV_KIND_VXLAN) {
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

        if (n->kind == NET_DEV_KIND_MACVLAN) {
                g_string_append(config, "[MACVLAN]\n");
                g_string_append_printf(config, "Mode=%s\n", macvlan_mode_to_name(n->macvlan_mode));
        }

        if (n->kind == NET_DEV_KIND_MACVTAP) {
                g_string_append(config, "[MACVTAP]\n");
                g_string_append_printf(config, "Mode=%s\n", macvlan_mode_to_name(n->macvlan_mode));
        }

        *ret = steal_pointer(config);
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

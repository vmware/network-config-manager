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
        [NET_DEV_KIND_VLAN]   = "vlan",
};

const char *netdev_kind_to_name(NetDevKind id) {
        if (id < 0)
                return "n/a";

        if ((size_t) id >= ELEMENTSOF(netdev_kind))
                return NULL;

        return netdev_kind[id];
}

int netdev_kind_to_id(const char *name) {
        int i;

        assert(name);

        for (i = NET_DEV_KIND_VLAN; i < (int) ELEMENTSOF(netdev_kind); i++)
                if (netdev_kind[i] && string_equal_fold(name, netdev_kind[i]))
                        return i;

        return _NET_DEV_KIND_INVALID;
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

        *ret = steal_pointer(config);

        return 0;
}

int create_netdev_conf_file(const IfNameIndex *ifnameidx, char **ret) {
        _auto_cleanup_ char *file = NULL, *netdev = NULL;
        int r;

        assert(ifnameidx);

        file = string_join("-", "10", ifnameidx->ifname, NULL);
        if (!file)
                return log_oom();

        r = create_conf_file("/etc/systemd/network", file, "netdev", &netdev);
        if (r < 0)
                return r;

        *ret = steal_pointer(netdev);
        return 0;
}

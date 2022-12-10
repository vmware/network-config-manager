/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "arphrd-to-name.h"
#include "config-parser.h"
#include "dbus.h"
#include "dns.h"
#include "log.h"
#include "file-util.h"
#include "macros.h"
#include "netdev-manager.h"
#include "network-address.h"
#include "network-link.h"
#include "network-manager.h"
#include "network-util.h"
#include "parse-util.h"

int manager_remove_netdev(const char *ifname, const char *kind) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        assert(ifname);

        /* remove .netdev file  */
        (void) remove_config_files_glob("/etc/systemd/network/*.netdev", "NetDev", "Name", ifname);
        (void) remove_config_files_glob("/lib/systemd/network/*.netdev", "NetDev", "Name", ifname);

        /* remove .network */
        (void) remove_config_files_glob("/etc/systemd/network/*.network", "Match", "Name", ifname);
        (void) remove_config_files_glob("/lib/systemd/network/*.network", "Match", "Name", ifname);

        /* Remove [Network] section */
        if (kind) {
                (void) remove_config_files_section_glob("/etc/systemd/network/*.network", "Network", kind, ifname);
                (void) remove_config_files_section_glob("/lib/systemd/network/*.network", "Network", kind, ifname);
        }

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return r;

        /* Finally remove the link */
        r = link_remove(p);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_create_vlan(const IfNameIndex *ifnameidx, const char *ifname, VLan *v) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *n= NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);
        assert(ifname);
        assert(v);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .ifname = strdup(ifname),
                        .kind = NETDEV_KIND_VLAN,
                        .vlan = v,
        };
        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&n);
        if (r < 0)
                return r;

        n->ifname = strdup(ifname);
        if (!n->ifname)
                return log_oom();

        r = generate_network_config(n);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", strerror(-r));
                return r;
        }

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = add_key_to_section_string(network, "Network", "VLAN", ifname);
        if (r < 0)
                return r;

        steal_pointer(netdev->vlan);
        return 0;
}

int manager_create_bridge(const char *ifname, Bridge *b, char **interfaces) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        char **s;
        int r;

        assert(ifname);
        assert(b);
        assert(interfaces);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .ifname = strdup(ifname),
                        .kind = NETDEV_KIND_BRIDGE,
                        .bridge = b,
                  };
        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(ifname);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", strerror(-r));
                return r;
        }

        strv_foreach(s, interfaces) {
                _auto_cleanup_ IfNameIndex *p = NULL;
                _auto_cleanup_ char *network = NULL;

                r = parse_ifname_or_index(*s, &p);
                if (r < 0)
                        return r;

                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "Bridge", ifname);
                if (r < 0)
                        return r;
        }

        return 0;
}

int manager_create_bond(const char *ifname, Bond *b, char **interfaces) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *n = NULL;
        char **s;
        int r;

        assert(ifname);
        assert(b);
        assert(interfaces);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .ifname = strdup(ifname),
                        .kind = NETDEV_KIND_BOND,
                        .bond = b,
                  };

        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&n);
        if (r < 0)
                return r;

        n->ifname = strdup(ifname);
        if (!n->ifname)
                return log_oom();

        r = generate_network_config(n);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", strerror(-r));
                return r;
        }

        strv_foreach(s, interfaces) {
                _auto_cleanup_ char *network = NULL;

                r = create_network_conf_file(*s, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "Bond", ifname);
                if (r < 0)
                        return r;
        }

        return 0;
}

int manager_create_vxlan(const char *ifname, const char *dev, VxLan *v) {

        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *n = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifname);
        assert(v);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                      .ifname = strdup(ifname),
                      .kind = NETDEV_KIND_VXLAN,
                      .vxlan = v,
                  };

        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&n);
        if (r < 0)
                return r;

        n->ifname = strdup(ifname);
        if (!n->ifname)
                return log_oom();

        r = generate_network_config(n);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", strerror(-r));
                return r;
        }

        if (!v->independent) {
                _auto_cleanup_ IfNameIndex *p = NULL;

                r = parse_ifname_or_index(dev, &p);
                if (r < 0)
                        return r;

                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "VXLAN", ifname);
                if (r < 0)
                        return r;
        }

        steal_pointer(netdev->vxlan);
        return 0;
}

int manager_create_macvlan(const char *ifname, const char *dev, MACVLan *m, bool kind) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifname);
        assert(m);
        assert(dev);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                       .ifname = strdup(ifname),
                       .kind = kind ? NETDEV_KIND_MACVLAN : NETDEV_KIND_MACVTAP,
                       .macvlan = m,
                };
        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(ifname);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration : %s", strerror(-r));
                return r;
        }

        r = parse_ifname_or_index(dev, &p);
        if (r < 0)
                return r;

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        if (kind)
                r = add_key_to_section_string(network, "Network", "MACVLAN", ifname);
        else
                r = add_key_to_section_string(network, "Network", "MACVTAP", ifname);

        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_create_ipvlan(const char *ifname, const char *dev, IPVLan *m, bool kind) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifname);
        assert(dev);
        assert(m);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                          .ifname = strdup(ifname),
                          .kind = kind ? NETDEV_KIND_IPVLAN : NETDEV_KIND_IPVTAP,
                          .ipvlan = m,
                 };

        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(ifname);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration : %s", strerror(-r));
                return r;
        }

        r = parse_ifname_or_index(dev, &p);
        if (r < 0)
                return r;

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        if (kind)
                r = add_key_to_section_string(network, "Network", "IPVLAN", ifname);
        else
                r = add_key_to_section_string(network, "Network", "IPVTAP", ifname);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_create_veth(const char *ifname, Veth *v) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *n = NULL;
        int r;

        assert(ifname);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                       .ifname = strdup(ifname),
                       .kind = NETDEV_KIND_VETH,
                       .veth = v,
                  };
        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&n);
        if (r < 0)
                return r;

        n->ifname = strdup(ifname);
        if (!n->ifname)
                return log_oom();

        r = generate_network_config(n);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", strerror(-r));
                return r;
        }

        return 0;
}

int manager_create_tunnel(const char *ifname, NetDevKind kind, const char *dev, Tunnel *t) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(t);
        assert(ifname);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                .ifname = strdup(ifname),
                .kind = kind,
                .tunnel = t,
        };

        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(ifname);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", strerror(-r));
                return r;
        }

        if (!t->independent) {
                _auto_cleanup_ IfNameIndex *p = NULL;

                r = parse_ifname_or_index(dev, &p);
                if (r < 0)
                        return r;

                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "Tunnel", ifname);
                if (r < 0)
                        return r;
        }

        return 0;
}

int manager_create_vrf(const char *ifname, VRF *vrf) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *n = NULL;
        int r;

        assert(vrf);
        assert(ifname);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .ifname = strdup(ifname),
                        .kind = NETDEV_KIND_VRF,
                        .vrf = vrf,
                };
        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&n);
        if (r < 0)
                return r;

        n->ifname = strdup(ifname);
        if (!n->ifname)
                return log_oom();

        r = generate_network_config(n);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", strerror(-r));
                return r;
        }

        return 0;
}

int manager_create_wireguard(const char *ifname, WireGuard *wg) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *n = NULL;
        int r;

        assert(wg);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                         .ifname = strdup(ifname),
                         .kind = NETDEV_KIND_WIREGUARD,
                         .wg = wg,
                 };

        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&n);
        if (r < 0)
                return r;

        n->ifname = strdup(ifname);
        if (!n->ifname)
                return log_oom();

        r = generate_network_config(n);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", strerror(-r));
                return r;
        }

        return 0;
}

int manager_create_tun_tap(const char *ifname, const NetDevKind kind, TunTap *t) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *n = NULL;
        int r;

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                         .ifname = strdup(ifname),
                         .kind = kind,
                         .tun_tap = t,
                 };
        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&n);
        if (r < 0)
                return r;

        n->ifname = strdup(ifname);
        if (!n->ifname)
                return log_oom();

        r = generate_network_config(n);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", strerror(-r));
                return r;
        }

        return 0;
}

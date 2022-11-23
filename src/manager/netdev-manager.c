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

int manager_create_vlan(const IfNameIndex *ifnameidx, const char *vlan, uint32_t id, const char *proto) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);
        assert(vlan);
        assert(id > 0);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .id = id,
                        .ifname = strdup(vlan),
                        .kind = NET_DEV_KIND_VLAN,
        };
        if (!netdev->ifname)
                return log_oom();

        if (proto) {
                netdev->proto = strdup(proto);
                if (!netdev->proto)
                        return log_oom();
        }

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(vlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        return add_key_to_section_string(network, "Network", "VLAN", vlan);
}

int manager_create_bridge(const char *bridge, char **interfaces) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        char **s;
        int r;

        assert(bridge);
        assert(interfaces);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .ifname = strdup(bridge),
                        .kind = NET_DEV_KIND_BRIDGE,
                  };
        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(bridge);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
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

                r = add_key_to_section_string(network, "Network", "Bridge", bridge);
                if (r < 0)
                        return r;
        }

        return 0;
}

int manager_create_bond(const char *bond, const BondMode mode, char **interfaces) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        char **s;
        int r;

        assert(bond);
        assert(interfaces);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .ifname = strdup(bond),
                        .kind = NET_DEV_KIND_BOND,
                        .bond_mode = mode,
                  };

        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(bond);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        strv_foreach(s, interfaces) {
                _auto_cleanup_ char *network = NULL;

                r = create_network_conf_file(*s, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "Bond", bond);
                if (r < 0)
                        return r;
        }

        return 0;
}

int manager_create_vxlan(const char *vxlan,
                         const uint32_t vni,
                         const IPAddress *local,
                         const IPAddress *remote,
                         const IPAddress *group,
                         const uint16_t port,
                         const char *dev,
                         const bool independent) {

        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(vxlan);
        assert(vni > 0);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                      .ifname = strdup(vxlan),
                      .kind = NET_DEV_KIND_VXLAN,
                      .id = vni,
                      .destination_port = port,
                      .independent = independent,
                  };

        if (!netdev->ifname)
                return log_oom();

        if (local)
                netdev->local = *local;
        if (remote)
                netdev->remote = *remote;
        if (group)
                netdev->group = *group;

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(vxlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        if (!independent) {
                _auto_cleanup_ IfNameIndex *p = NULL;

                r = parse_ifname_or_index(dev, &p);
                if (r < 0)
                        return r;

                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "VXLAN", vxlan);
                if (r < 0)
                        return r;
        }

        return 0;
}

int manager_create_macvlan(const char *macvlan, const char *dev, MACVLanMode mode, bool kind) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(macvlan);
        assert(dev);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                       .ifname = strdup(macvlan),
                       .kind = kind ? NET_DEV_KIND_MACVLAN : NET_DEV_KIND_MACVTAP,
                       .macvlan_mode = mode,
                };
        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(macvlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration : %s", g_strerror(-r));
                return r;
        }

        r = parse_ifname_or_index(dev, &p);
        if (r < 0)
                return r;

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        if (kind)
                r = add_key_to_section_string(network, "Network", "MACVLAN", macvlan);
        else
                r = add_key_to_section_string(network, "Network", "MACVTAP", macvlan);

        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_create_ipvlan(const char *ipvlan, const char *dev, IPVLanMode mode, bool kind) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ipvlan);
        assert(dev);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                          .ifname = strdup(ipvlan),
                          .kind = kind ? NET_DEV_KIND_IPVLAN : NET_DEV_KIND_IPVTAP,
                          .ipvlan_mode = mode,
                 };

        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(ipvlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration : %s", g_strerror(-r));
                return r;
        }

        r = parse_ifname_or_index(dev, &p);
        if (r < 0)
                return r;

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        if (kind)
                r = add_key_to_section_string(network, "Network", "IPVLAN", ipvlan);
        else
                r = add_key_to_section_string(network, "Network", "IPVTAP", ipvlan);

        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_create_veth(const char *veth, const char *veth_peer) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        int r;

        assert(veth);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                       .ifname = strdup(veth),
                       .peer = veth_peer ? strdup(veth_peer) : NULL,
                       .kind = NET_DEV_KIND_VETH,
                  };
        if (!netdev->ifname)
                return log_oom();

        if (veth_peer && !netdev->peer)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(veth);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

int manager_create_tunnel(const char *tunnel,
                          NetDevKind kind,
                          IPAddress *local,
                          IPAddress *remote,
                          const char *dev,
                          bool independent) {

        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(tunnel);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                .ifname = strdup(tunnel),
                .kind = kind,
                .independent = independent,
        };

        if (!netdev->ifname)
                return log_oom();

        if (local)
                netdev->local = *local;
        if (remote)
                netdev->remote = *remote;

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(tunnel);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        if (!independent) {
                _auto_cleanup_ IfNameIndex *p = NULL;

                r = parse_ifname_or_index(dev, &p);
                if (r < 0)
                        return r;

                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "Tunnel", tunnel);
                if (r < 0)
                        return r;
        }

        return 0;
}

int manager_create_vrf(const char *vrf, const uint32_t table) {
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        int r;

        assert(vrf);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .ifname = strdup(vrf),
                        .kind = NET_DEV_KIND_VRF,
                        .table = table
                };
        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(vrf);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

int manager_create_wireguard_tunnel(const char *wireguard,
                                    const char *private_key,
                                    const char *public_key,
                                    const char *preshared_key,
                                    const char *endpoint,
                                    const char *allowed_ips,
                                    const uint16_t listen_port) {

        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        int r;

        assert(wireguard);
        assert(private_key);
        assert(public_key);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                         .ifname = strdup(wireguard),
                         .kind = NET_DEV_KIND_WIREGUARD,
                         .wg_private_key = private_key ? strdup(private_key) : NULL,
                         .wg_public_key = public_key ? strdup(public_key) : NULL,
                         .listen_port = listen_port,
                 };
        if (!netdev->ifname || !netdev->wg_private_key || !netdev->wg_public_key)
                return log_oom();

        if (endpoint) {
                netdev->wg_endpoint = strdup(endpoint);
                if (!netdev->wg_endpoint)
                        return log_oom();
        }

        if (allowed_ips) {
                netdev->wg_allowed_ips = strdup(allowed_ips);
                if (!netdev->wg_allowed_ips)
                        return log_oom();
        }

        r = generate_netdev_config(netdev);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(wireguard);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

int manager_create_tun_tap(const NetDevKind kind,
                           const char *ifname,
                           const char *user,
                           const char *group,
                           const int packet_info,
                           const int vnet_hdr,
                           const int keep_carrier,
                           const int multi_queue) {

        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *n = NULL;
        int r;

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                         .ifname = strdup(ifname),
                         .kind = kind,
                         .tun_tap.user = user ? strdup(user) : NULL,
                         .tun_tap.group = group ? strdup(group) : NULL,
                         .tun_tap.packet_info = packet_info,
                         .tun_tap.vnet_hdr = vnet_hdr,
                         .tun_tap.keep_carrier = keep_carrier,
                         .tun_tap.multi_queue = multi_queue,
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
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

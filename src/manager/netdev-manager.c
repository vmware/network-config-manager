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

static int manager_write_netdev_config(const NetDev *n, const GString *config) {
        _auto_cleanup_ char *netdev = NULL, *config_file = NULL;
        _auto_cleanup_close_ int fd = -1;
        int r;

        assert(n);
        assert(config);

        config_file = string_join("-", "10", n->ifname, NULL);
        if (!config_file)
                return log_oom();

        r = create_conf_file("/etc/systemd/network", config_file, "netdev", &netdev);
        if (r < 0)
                return r;

        r = open(netdev, O_WRONLY);
        if (r < 0) {
                log_warning("Failed to open netdev file '%s': %s", netdev, g_strerror(-r));
                return r;
        }

        fd = r;
        r = write(fd, config->str, config->len);
        if (r < 0)
                return -errno;

        (void) set_file_permisssion(netdev, "systemd-network");
        return 0;
}

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
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *vlan_network_config = NULL;
        _auto_cleanup_ char *vlan_network = NULL, *network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
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

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(vlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &vlan_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(ifnameidx->ifname, &vlan_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, vlan_network_config);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = add_key_to_section_string(network, "Network", "VLAN", vlan);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_create_bridge(const char *bridge, char **interfaces) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *bridge_network_config = NULL;
        _auto_cleanup_ char *bridge_netdev = NULL, *bridge_network = NULL;
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

        r = create_netdev_conf_file(bridge, &bridge_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(bridge);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &bridge_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(bridge, &bridge_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, bridge_network_config);

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

        return dbus_network_reload();
}

int manager_create_bond(const char *bond, const BondMode mode, char **interfaces) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *bond_network_config = NULL;
        _auto_cleanup_ char *bond_netdev = NULL, *bond_network = NULL;
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

        r = create_netdev_conf_file(bond, &bond_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(bond);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &bond_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(bond, &bond_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, bond_network_config);

        strv_foreach(s, interfaces) {
                _auto_cleanup_ char *network = NULL;

                r = create_network_conf_file(*s, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "Bond", bond);
                if (r < 0)
                        return r;
        }

        return dbus_network_reload();
}

int manager_create_vxlan(const char *vxlan,
                         const uint32_t vni,
                         const IPAddress *local,
                         const IPAddress *remote,
                         const IPAddress *group,
                         const uint16_t port,
                         const char *dev,
                         const bool independent) {

        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *vxlan_network_config = NULL;
        _auto_cleanup_ char *vxlan_netdev = NULL, *vxlan_network = NULL, *network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
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

        r = create_netdev_conf_file(vxlan, &vxlan_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(vxlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &vxlan_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(vxlan, &vxlan_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, vxlan_network_config);

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

        return dbus_network_reload();
}

int manager_create_macvlan(const char *macvlan, const char *dev, MACVLanMode mode, bool kind) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *macvlan_network_config = NULL;
        _auto_cleanup_ char *macvlan_netdev = NULL, *macvlan_network = NULL, *network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
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

        r = create_netdev_conf_file(macvlan, &macvlan_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(macvlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &macvlan_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration : %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(macvlan, &macvlan_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, macvlan_network_config);

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
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *ipvlan_network_config = NULL;
        _auto_cleanup_ char *ipvlan_netdev = NULL, *ipvlan_network = NULL, *network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
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

        r = create_netdev_conf_file(ipvlan, &ipvlan_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(ipvlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &ipvlan_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration : %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(ipvlan, &ipvlan_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, ipvlan_network_config);

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
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *veth_network_config = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ char *veth_network = NULL;
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

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(veth);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &veth_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(veth, &veth_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, veth_network_config);

        return dbus_network_reload();
}

int manager_create_tunnel(const char *tunnel,
                          NetDevKind kind,
                          IPAddress *local,
                          IPAddress *remote,
                          const char *dev,
                          bool independent) {

        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *tunnel_network_config = NULL;
        _auto_cleanup_ char *tunnel_netdev = NULL, *tunnel_network = NULL, *network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
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

        r = create_netdev_conf_file(tunnel, &tunnel_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(tunnel);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &tunnel_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(tunnel, &tunnel_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, tunnel_network_config);

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

        return dbus_network_reload();
}

int manager_create_vrf(const char *vrf, const uint32_t table) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *vrf_network_config = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ char *vrf_network = NULL;
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

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(vrf);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &vrf_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(vrf, &vrf_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, vrf_network_config);

        return dbus_network_reload();
}

int manager_create_wireguard_tunnel(char *wireguard,
                                    char *private_key,
                                    char *public_key,
                                    char *preshared_key,
                                    char *endpoint,
                                    char *allowed_ips,
                                    uint16_t listen_port) {

        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *wireguard_network_config = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _auto_cleanup_ char *wireguard_network = NULL;
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
                         .wg_private_key = private_key ? strdup(private_key) : private_key,
                         .wg_public_key = public_key ? strdup(public_key) : public_key,
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

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(wireguard);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &wireguard_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(wireguard, &wireguard_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, wireguard_network_config);

        return dbus_network_reload();
}

/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "alloc-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "parse-util.h"
#include "string-util.h"

static int link_add(const char *s) {
    _auto_cleanup_ char *c = NULL;

    c = strjoin(" ", "/usr/sbin/ip", "link", "add", "dev", s, "type", "dummy", NULL);
    if (!c)
        return -ENOMEM;

    system(c);

    return 0;
}

static int link_remove (const char *s) {
    _auto_cleanup_ char *c = NULL, *yaml_file = NULL;

    c = strjoin(" ", "/usr/sbin/ip", "link", "del", s, NULL);
    if (!c)
        return -ENOMEM;

    system(c);

    return 0;
}

static int apply_yaml_file(const char *y) {
    _auto_cleanup_ char *c = NULL, *yaml_file = NULL;

    assert(y);

    yaml_file = strjoin("", "/run/network-config-manager-ci/yaml/", y, NULL);
    if (!yaml_file)
        return -ENOMEM;

    c = strjoin(" ", "/usr/bin/nmctl", "apply-file", yaml_file, NULL);
    if (!c)
        return -ENOMEM;

    assert_true(system(c) >= 0);

    return 0;
}

static void multiple_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("multiple-address.yml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "1.1.1.1"));
    assert_true(g_strrstr(dns, "1.0.0.1"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.100/24"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.99/24"));
}

static void static_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("static-address.yml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "8.8.8.8"));
    assert_true(g_strrstr(dns, "192.168.1.1"));
    assert_true(g_strrstr(dns, "8.8.4.4"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.202/24"));

    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.101"));
    assert_true(key_file_config_exists(key_file, "Route", "Destination", "172.16.0.0/24"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.100"));
}

static void multiple_routes_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("multiple-rt.yml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "192.168.1.1"));
    assert_true(g_strrstr(dns, "8.8.4.4"));
    assert_true(g_strrstr(dns, "8.8.8.8"));

    assert_true(key_file_config_exists(key_file, "Network", "Domains", "testdomain1.com testdomain2.com"));
    assert_true(key_file_config_exists(key_file, "Network", "NTP", "ntp1.com ntp2.com"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "11.0.0.11/24"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.0.0.10/24"));

    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "10.0.0.1"));
    assert_true(key_file_config_exists(key_file, "Route", "RouteMetric", "200"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "11.0.0.1"));
    assert_true(key_file_config_exists(key_file, "Route", "RouteMetric", "300"));
}

static void source_routing(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("source-routing.yml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "172.31.24.153/20"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "172.31.28.195/20"));

    assert_true(key_file_config_exists(key_file, "Route", "Destination", "172.31.24.153"));
    assert_true(key_file_config_exists(key_file, "Route", "Table", "1000"));
    assert_true(key_file_config_exists(key_file, "Route", "Scope", "link"));

    assert_true(key_file_config_exists(key_file, "Route", "Destination", "0.0.0.0/0"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "172.31.16.1"));
    assert_true(key_file_config_exists(key_file, "Route", "Table", "1000"));

    assert_true(key_file_config_exists(key_file, "Route", "Destination", "172.31.28.195"));
    assert_true(key_file_config_exists(key_file, "Route", "Scope", "link"));
    assert_true(key_file_config_exists(key_file, "Route", "Table", "1000"));

    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "From", "172.31.28.195"));
    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "Table", "1000"));

    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "From", "172.31.24.153"));
    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "Table", "1000"));
}

static void wireguard_multiple_peers(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("wg.yml");

    r = parse_key_file("/etc/systemd/network/10-wg0.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "wg0"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "wireguard"));

    assert_true(key_file_config_exists(key_file, "WireGuard", "PrivateKeyFile", "/path/to/private.key"));
    assert_true(key_file_config_exists(key_file, "WireGuard", "ListenPort", "5182"));
    assert_true(key_file_config_exists(key_file, "WireGuard", "FwMark", "42"));

    assert_true(key_file_config_exists(key_file, "WireGuardPeer", "PublicKey", "rlbInAj0qV69CysWPQY7KEBnKxpYCpaWqOs/dLevdWc="));
    assert_true(key_file_config_exists(key_file, "WireGuardPeer", "Endpoint", "1.2.3.4:5"));
    assert_true(key_file_config_exists(key_file, "WireGuardPeer", "AllowedIPs", "0.0.0.0/0 2001:fe:ad:de:ad:be:ef:1/24"));
    assert_true(key_file_config_exists(key_file, "WireGuardPeer", "PersistentKeepalive", "23"));

    assert_true(key_file_config_exists(key_file, "WireGuardPeer", "Endpoint", "5.4.3.2:1"));
    assert_true(key_file_config_exists(key_file, "WireGuardPeer", "PresharedKey", "/some/shared.key"));
    assert_true(key_file_config_exists(key_file, "WireGuardPeer", "AllowedIPs", "10.10.10.20/24"));
    assert_true(key_file_config_exists(key_file, "WireGuardPeer", "PersistentKeepalive", "22"));
    assert_true(key_file_config_exists(key_file, "WireGuardPeer", "PublicKey", "M9nt4YujIOmNrRmpIRTmYSfMdrpvE7u6WkG8FY8WjG4="));

    system("nmctl remove-netdev wg0");
}

static void netdev_vlans(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL, *d = NULL;
    int r;

    apply_yaml_file("vlans.yml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Match", "MACAddress", "de:ad:be:ef:ca:fe"));

    assert_true(key_file_config_exists(key_file, "Network", "Domains", "example.com"));
    assert_true(key_file_config_exists(key_file, "Network", "VLAN", "vlan15"));
    assert_true(key_file_config_exists(key_file, "Network", "VLAN", "vlan10"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "8.8.4.4"));
    assert_true(g_strrstr(dns, "8.8.8.8"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.3.0.5/23"));
    assert_true(key_file_config_exists(key_file, "Route", "Destination", "0.0.0.0/0"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "10.3.0.1"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vlan15.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "vlan15"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "vlan"));
    assert_true(key_file_config_exists(key_file, "VLAN", "Id", "15"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vlan10.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "vlan10"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "vlan"));
    assert_true(key_file_config_exists(key_file, "VLAN", "Id", "10"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vlan15.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "vlan15"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.3.99.5/24"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vlan10.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "vlan10"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.3.98.5/24"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "127.0.0.1"));

    assert_true(d=key_file_config_get(key_file, "Network", "Domains"));
    assert_true(g_strrstr(d, "domain2.example.com"));
    assert_true(g_strrstr(d, "domain1.example.com"));

    system("nmctl remove-netdev vlan10 kind vlan");
    system("nmctl remove-netdev vlan15 kind vlan");
}

static void netdev_vrfs(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("vrfs.yml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "Network", "VRF", "vrf1005"));
    assert_true(key_file_config_exists(key_file, "Network", "VRF", "vrf1006"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-test98.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test98"));

    assert_true(key_file_config_exists(key_file, "Network", "VRF", "vrf1005"));
    assert_true(key_file_config_exists(key_file, "Network", "VRF", "vrf1006"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vrf1005.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "vrf1005"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "vrf"));
    assert_true(key_file_config_exists(key_file, "VRF", "Table", "1005"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vrf1006.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "vrf1006"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "vrf"));
    assert_true(key_file_config_exists(key_file, "VRF", "Table", "1006"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vrf1005.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "vrf1005"));

    assert_true(key_file_config_exists(key_file, "Route", "Destination", "0.0.0.0/0"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "1.2.3.4"));

    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "From", "2.3.4.5"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vrf1006.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "vrf1006"));

    assert_true(key_file_config_exists(key_file, "Route", "Destination", "0.0.0.0/0"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "2.3.4.5"));

    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "From", "3.4.5.6"));

    system("nmctl remove-netdev vrf1005 kind vrf");
    system("nmctl remove-netdev vrf1006 kind vrf");
}

static void netdev_vxlans(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("vxlans.yml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "Network", "VXLAN", "vxlan1"));
    assert_true(key_file_config_exists(key_file, "Network", "VXLAN", "vxlan2"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vxlan1.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "vxlan1"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "vxlan"));

    assert_true(key_file_config_exists(key_file, "VXLAN", "VNI", "1"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "Local", "192.168.1.34"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "Remote", "192.168.1.35"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "TOS", "11"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "MacLearning", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "ReduceARPProxy", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "FDBAgeingSec", "300"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "FlowLabel", "5555"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "MaximumFDBEntries", "20"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "IPDoNotFragment", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "L2MissNotification", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "L3MissNotification", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "RouteShortCircuit", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "UDPChecksum", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "UDP6ZeroChecksumTx", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "UDP6ZeroChecksumRx", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "RemoteChecksumTx", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "RemoteChecksumRx", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "GroupPolicyExtension", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "GenericProtocolExtension", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "PortRange", "42-442"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vxlan2.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "vxlan2"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "vxlan"));

    assert_true(key_file_config_exists(key_file, "VXLAN", "VNI", "2"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "Local", "192.168.1.35"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "Remote", "192.168.1.36"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "TOS", "12"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "MacLearning", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "ReduceARPProxy", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "FDBAgeingSec", "400"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "FlowLabel", "6666"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "MaximumFDBEntries", "30"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "IPDoNotFragment", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "L2MissNotification", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "RouteShortCircuit", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "UDPChecksum", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "RemoteChecksumTx", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "RemoteChecksumRx", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "GroupPolicyExtension", "yes"));
    assert_true(key_file_config_exists(key_file, "VXLAN", "PortRange", "43-444"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vxlan1.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "vxlan1"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vxlan2.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "vxlan2"));

    system("nmctl remove-netdev vxlan1 kind vxlan");
    system("nmctl remove-netdev vxlan2 kind vxlan");
}

static void additional_gw_source_routing(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl add-addl-gw dev test99 address 192.168.10.5/24 dest 0.0.0.0 gw 172.16.85.1 table 100") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.10.5/24"));

    assert_true(key_file_config_exists(key_file, "Route", "Destination", "0.0.0.0"));
    assert_true(key_file_config_exists(key_file, "Route", "Table", "100"));
    assert_true(key_file_config_exists(key_file, "Route", "PreferredSource", "192.168.10.5/24"));

    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "172.16.85.1"));
    assert_true(key_file_config_exists(key_file, "Route", "Table", "100"));

    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "From", "192.168.10.5/24"));
    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "Table", "100"));

    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "To", "192.168.10.5/24"));
    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "Table", "100"));
}

static void netdev_vlan(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *domains = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("vlan.yml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "8.8.8.8"));
    assert_true(g_strrstr(dns, "8.8.4.4"));

    assert_true(key_file_config_exists(key_file, "Network", "Domains", "example.com"));
    assert_true(key_file_config_exists(key_file, "Network", "VLAN", "vlan-98"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.3.0.5/23"));

    assert_true(key_file_config_exists(key_file, "Route", "Destination", "0.0.0.0/0"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "10.3.0.1"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-vlan-98.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "vlan-98"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "127.0.0.1"));

    assert_true(domains=key_file_config_get(key_file, "Network", "Domains"));
    assert_true(g_strrstr(domains, "domain1.example.com"));
    assert_true(g_strrstr(domains, "domain2.example.com"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.3.98.5/24"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.3.98.5/24"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-vlan-98.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "vlan-98"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "vlan"));
    assert_true(key_file_config_exists(key_file, "VLAN", "Id", "10"));

    system("nmctl remove-netdev vlan-98 kind vlan");
}

static void netdev_bond_parametres(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("bond.yml");

    r = parse_key_file("/etc/systemd/network/10-bond0.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "bond0"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "bond"));

    assert_true(key_file_config_exists(key_file, "Bond", "Mode", "active-backup"));
    assert_true(key_file_config_exists(key_file, "Bond", "TransmitHashPolicy", "layer3+4"));
    assert_true(key_file_config_exists(key_file, "Bond", "LACPTransmitRate", "fast"));
    assert_true(key_file_config_exists(key_file, "Bond", "ARPValidate", "active"));
    assert_true(key_file_config_exists(key_file, "Bond", "FailOverMACPolicy", "active"));
    assert_true(key_file_config_exists(key_file, "Bond", "AdSelect", "bandwidth"));
    assert_true(key_file_config_exists(key_file, "Bond", "PrimaryReselectPolicy", "better"));
    assert_true(key_file_config_exists(key_file, "Bond", "MIIMonitorSec", "300"));
    assert_true(key_file_config_exists(key_file, "Bond", "MinLinks", "3"));
    assert_true(key_file_config_exists(key_file, "Bond", "ARPIntervalSec", "30"));
    assert_true(key_file_config_exists(key_file, "Bond", "UpDelaySec", "12"));
    assert_true(key_file_config_exists(key_file, "Bond", "DownDelaySec", "15"));
    assert_true(key_file_config_exists(key_file, "Bond", "LearnPacketIntervalSec", "32"));
    assert_true(key_file_config_exists(key_file, "Bond", "ResendIGMP", "45"));
    assert_true(key_file_config_exists(key_file, "Bond", "PacketsPerSlave", "11"));
    assert_true(key_file_config_exists(key_file, "Bond", "GratuitousARP", "15"));
    assert_true(key_file_config_exists(key_file, "Bond", "AllSlavesActive", "yes"));
    assert_true(key_file_config_exists(key_file, "Bond", "ARPIPTargets", "192.168.5.1 192.168.5.34"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-bond0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "bond0"));

    assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));

    system("nmctl remove-netdev bond0 kind bond");
}

static int setup(void **state) {
    link_add("test99");
    return 0;
}

static int teardown (void **state) {
    link_remove("test99");
    return 0;
}

int main(void) {
    const struct CMUnitTest tests [] = {
        cmocka_unit_test (multiple_address),
        cmocka_unit_test (multiple_routes_address),
        cmocka_unit_test (source_routing),
        cmocka_unit_test (additional_gw_source_routing),
        cmocka_unit_test (wireguard_multiple_peers),
        cmocka_unit_test (static_address),
        cmocka_unit_test (netdev_vlans),
        cmocka_unit_test (netdev_vlan),
        cmocka_unit_test (netdev_vrfs),
        cmocka_unit_test (netdev_bond_parametres),
        cmocka_unit_test (netdev_vxlans),
    };

    int count_fail_tests = cmocka_run_group_tests (tests, setup, teardown);

    return count_fail_tests;
}

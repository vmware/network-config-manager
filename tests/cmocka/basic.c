/* Copyright 2024 VMware, Inc.
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
    _auto_cleanup_ char *c = NULL;

    c = strjoin(" ", "/usr/sbin/ip", "link", "del", s, NULL);
    if (!c)
        return -ENOMEM;

    system(c);

    return 0;
}

static int reload_networkd (const char *s) {
    _auto_cleanup_ char *c = NULL;

    system("systemctl restart systemd-networkd");
    system("sleep 30");

    c = strjoin(" ", "/lib/systemd/systemd-networkd-wait-online", "-i", s, NULL);
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

static void test_multiple_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("multiple-address.yaml");

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

static void test_static_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("static-address.yaml");

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

static void test_multiple_routes_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("multiple-rt.yaml");

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

static void test_dhcp6_overrides(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("dhcp6-overrides.yaml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "DHCPv6", "SendRelease", "no"));
    assert_true(key_file_config_exists(key_file, "DHCPv6", "WithoutRA", "solicit"));
    assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDNS", "yes"));
    assert_true(key_file_config_exists(key_file, "DHCPv6", "UseNTP", "yes"));
    assert_true(key_file_config_exists(key_file, "DHCPv6", "UseHostname", "yes"));
    assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDomains", "yes"));
    assert_true(key_file_config_exists(key_file, "DHCPv6", "RapidCommit", "no"));
    assert_true(key_file_config_exists(key_file, "DHCPv6", "UseAddress", "yes"));
}

static void test_ipv6_ra_overrides(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("ipv6-ra-overrides.yaml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "IPv6AcceptRA", "Token", "eui64"));
    assert_true(key_file_config_exists(key_file, "IPv6AcceptRA", "UseDNS", "yes"));
    assert_true(key_file_config_exists(key_file, "IPv6AcceptRA", "UseMTU", "yes"));
    assert_true(key_file_config_exists(key_file, "IPv6AcceptRA", "UseDomains", "yes"));
    assert_true(key_file_config_exists(key_file, "IPv6AcceptRA", "UseGateway", "yes"));
    assert_true(key_file_config_exists(key_file, "IPv6AcceptRA", "UseRoutePrefix", "yes"));
    assert_true(key_file_config_exists(key_file, "IPv6AcceptRA", "UseAutonomousPrefix", "yes"));
    assert_true(key_file_config_exists(key_file, "IPv6AcceptRA", "UseOnLinkPrefix", "yes"));
}

static void test_source_routing(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("source-routing.yaml");

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

static void test_wireguard_multiple_peers(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("wg.yaml");

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

static void test_netdev_vlans(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL, *d = NULL;
    int r;

    apply_yaml_file("vlans.yaml");

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

static void test_netdev_vrfs(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("vrfs.yaml");

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

static void test_netdev_vxlans(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("vxlans.yaml");

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

static void test_set_dns(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-dns dev test99 dns 192.168.1.5,192.168.1.4") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "Network", "DNS", "192.168.1.5 192.168.1.4"));
}

static void test_revert_dns(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file1 = NULL, *key_file2 = NULL;
    int r;

    assert_true(system("nmctl set-dns dev test99 dns 192.168.1.5,192.168.1.4") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file1);
    assert_true(r >= 0);

    display_key_file(key_file1);
    assert_true(key_file_config_exists(key_file1, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file1, "Network", "DNS", "192.168.1.5 192.168.1.4"));

    assert_true(system("nmctl revert-resolve-link dev test99") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file2);
    assert_true(r >= 0);

    display_key_file(key_file2);
    assert_true(!key_file_config_exists(key_file2, "Network", "DNS", "192.168.1.5 192.168.1.4"));
}

static void test_revert_dns_with_parametre(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file1 = NULL, *key_file2 = NULL;
    int r;

    assert_true(system("nmctl set-dns dev test99 dns 192.168.1.5,192.168.1.4") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file1);
    assert_true(r >= 0);

    display_key_file(key_file1);
    assert_true(key_file_config_exists(key_file1, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file1, "Network", "DNS", "192.168.1.5 192.168.1.4"));

    assert_true(system("nmctl revert-resolve-link dev test99 dns yes") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file2);
    assert_true(r >= 0);

    display_key_file(key_file2);
    assert_true(!key_file_config_exists(key_file2, "Network", "DNS", "192.168.1.5 192.168.1.4"));
}

static void test_add_remove_multiple_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file1 = NULL, *key_file2 = NULL;
    int r;

    assert_true(system("nmctl add-addr dev test99 a 192.168.1.5") >= 0);
    assert_true(system("nmctl add-addr dev test99 a 192.168.1.6") >= 0);
    assert_true(system("nmctl add-addr dev test99 a 192.168.1.7") >= 0);
    assert_true(system("nmctl add-addr dev test99 a 192.168.1.8") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file1);
    assert_true(r >= 0);

    display_key_file(key_file1);
    assert_true(key_file_config_exists(key_file1, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file1, "Address", "Address", "192.168.1.5"));
    assert_true(key_file_config_exists(key_file1, "Address", "Address", "192.168.1.6"));
    assert_true(key_file_config_exists(key_file1, "Address", "Address", "192.168.1.7"));
    assert_true(key_file_config_exists(key_file1, "Address", "Address", "192.168.1.8"));

    assert_true(system("nmctl remove-addr dev test99 a 192.168.1.8 192.168.1.7 192.168.1.6 192.168.1.5") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file2);
    assert_true(r >= 0);

    display_key_file(key_file2);
    assert_true(!key_file_config_exists(key_file2, "Address", "Address", "192.168.1.5"));
    assert_true(!key_file_config_exists(key_file2, "Address", "Address", "192.168.1.6"));
    assert_true(!key_file_config_exists(key_file2, "Address", "Address", "192.168.1.7"));
    assert_true(!key_file_config_exists(key_file2, "Address", "Address", "192.168.1.8"));
}

static void test_set_gw_keep(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-gw dev test99 gw 192.168.1.1") >= 0);
    assert_true(system("nmctl set-gw dev test99 gw 192.168.1.2 keep yes") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.2"));
}

static void test_set_gw_family(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-gw-family dev test99 gw6 ::1 gw4 192.168.1.1") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "::1"));
}

static void test_remove_gw_family(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl remove-gw dev test99 family ipv4 family ipv6") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(!key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));
    assert_true(!key_file_config_exists(key_file, "Route", "Gateway", "::1"));
}

static void test_set_static_address_gw(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-static dev test99 a 192.168.1.12/24 gw 192.168.1.1 a 192.168.1.13/24 gw 192.168.1.2") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.12/24"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.13/24"));

    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.2"));
}

static void test_set_static_address_gw_dns(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-static dev test99 a 192.168.1.12/24 gw 192.168.1.1 a 192.168.1.13/24 gw 192.168.1.2 dns 192.168.1.2,192.168.1.1") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "Network", "DNS", "192.168.1.2 192.168.1.1"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.12/24"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.13/24"));

    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.2"));
}

static void test_set_static_address_gw_dns_keep_yes(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-static dev test99 a 192.168.1.12/24 gw 192.168.1.1 a 192.168.1.13/24 gw 192.168.1.2 dns 192.168.1.2,192.168.1.1") >= 0);
    assert_true(system("nmctl set-static dev test99 a 192.168.1.14/24 a 192.168.1.15/24 dns 192.168.1.4,192.168.1.5 keep yes") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "Network", "DNS", "192.168.1.4 192.168.1.5 192.168.1.2 192.168.1.1"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.12/24"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.13/24"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.14/24"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.15/24"));

    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.2"));
}

static void test_additional_gw_source_routing(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl add-addl-gw dev test99 address 192.168.10.5/24 dest default gw 172.16.85.1 table 100") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.10.5/24"));

    assert_true(key_file_config_exists(key_file, "Route", "Destination", "0.0.0.0/0"));
    assert_true(key_file_config_exists(key_file, "Route", "Table", "100"));
    assert_true(key_file_config_exists(key_file, "Route", "PreferredSource", "192.168.10.5/24"));

    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "172.16.85.1"));
    assert_true(key_file_config_exists(key_file, "Route", "Table", "100"));

    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "From", "192.168.10.5/24"));
    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "Table", "100"));

    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "To", "192.168.10.5/24"));
    assert_true(key_file_config_exists(key_file, "RoutingPolicyRule", "Table", "100"));
}

static void test_add_dhcp4_server_static_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl adhcp4-srv-sa dev test99 a 192.168.1.21/24 mac 00:0c:29:5f:d1:41") >= 0);
    system("sleep 1");
    assert_true(system("nmctl adhcp4-srv-sa dev test99 a 192.168.1.22/24 mac 00:0c:29:5f:d1:42") >= 0);
    system("sleep 1");
    assert_true(system("nmctl adhcp4-srv-sa dev test99 a 192.168.1.23/24 mac 00:0c:29:5f:d1:43") >= 0);
    system("sleep 1");
    assert_true(system("nmctl adhcp4-srv-sa dev test99 a 192.168.1.24/24 mac 00:0c:29:5f:d1:44") >= 0);
    system("sleep 1");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:41"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:42"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:43"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:44"));

    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.21/24"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.22/24"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.23/24"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.24/24"));

    unlink("/etc/systemd/network/10-test99.network");
}

static void test_remove_dhcp4_server_static_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl adhcp4-srv-sa dev test99 a 192.168.1.21/23 mac 00:0c:29:5f:d1:41") >= 0);
    system("sleep 1");
    assert_true(system("nmctl adhcp4-srv-sa dev test99 a 192.168.1.22/23 mac 00:0c:29:5f:d1:42") >= 0);
    system("sleep 1");
    assert_true(system("nmctl adhcp4-srv-sa dev test99 a 192.168.1.23/23 mac 00:0c:29:5f:d1:43") >= 0);
    system("sleep 1");
    assert_true(system("nmctl adhcp4-srv-sa dev test99 a 192.168.1.24/23 mac 00:0c:29:5f:d1:44") >= 0);
    system("sleep 1");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:41"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:42"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:43"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:44"));

    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.21/23"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.22/23"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.23/23"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.24/23"));

    key_file_free(key_file);

    assert_true(system("nmctl rdhcp4-srv-sa dev test99 a 192.168.1.21/23 mac 00:0c:29:5f:d1:41") >= 0);
    assert_true(system("nmctl rdhcp4-srv-sa dev test99 a 192.168.1.22/23 mac 00:0c:29:5f:d1:42") >= 0);
    assert_true(system("nmctl rdhcp4-srv-sa dev test99 a 192.168.1.23/23 mac 00:0c:29:5f:d1:43") >= 0);
    assert_true(system("nmctl rdhcp4-srv-sa dev test99 a 192.168.1.24/23 mac 00:0c:29:5f:d1:44") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(!key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:41"));
    assert_true(!key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:42"));
    assert_true(!key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:43"));
    assert_true(!key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:44"));

    assert_true(!key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.21/23"));
    assert_true(!key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.22/23"));
    assert_true(!key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.23/23"));
    assert_true(!key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "192.168.1.24/23"));
    unlink("/etc/systemd/network/10-test99.network");
}

static void test_yaml_add_dhcp4_server_static_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("dhcp4-server.yaml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "DHCPServer", "PoolOffset", "0"));
    assert_true(key_file_config_exists(key_file, "DHCPServer", "PoolSize", "200"));
    assert_true(key_file_config_exists(key_file, "DHCPServer", "EmitDNS", "yes"));
    assert_true(key_file_config_exists(key_file, "DHCPServer", "DNS", "8.8.8.8"));
    assert_true(key_file_config_exists(key_file, "DHCPServer", "DefaultLeaseTimeSec", "12h"));
    assert_true(key_file_config_exists(key_file, "DHCPServer", "MaxLeaseTimeSec", "24h"));

    assert_true(key_file_config_exists(key_file, "Network", "DHCPServer", "yes"));
    assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "no"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.100.1.1/24"));


    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:41"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:42"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "MACAddress", "00:0c:29:5f:d1:43"));

    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "10.100.1.2"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "10.100.1.3"));
    assert_true(key_file_config_exists(key_file, "DHCPServerStaticLease", "Address", "10.100.1.4"));

    unlink("/etc/systemd/network/10-test99.network");
}

static void test_yaml_add_sriov(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("sriov.yaml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "SR-IOV", "VirtualFunction", "0"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "VirtualFunction", "1"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "VLANId", "1"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "VLANId", "2"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "QualityOfService", "101"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "QualityOfService", "102"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "VLANProtocol", "802.1Q"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "VLANProtocol", "802.1Q"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "LinkState", "yes"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "LinkState", "yes"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "MACAddress", "00:11:22:33:44:55"));
    assert_true(key_file_config_exists(key_file, "SR-IOV", "MACAddress", "00:11:22:33:44:56"));
}

static void test_netdev_vlan(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *domains = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("vlan.yaml");

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

static void test_netdev_bond_parametres(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("bond.yaml");

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

static void test_netdev_bond(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("bond-interface.yaml");

    r = parse_key_file("/etc/systemd/network/10-bond0.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "bond0"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "bond"));

    assert_true(key_file_config_exists(key_file, "Bond", "Mode", "802.3ad"));
    assert_true(key_file_config_exists(key_file, "Bond", "LACPTransmitRate", "fast"));
    assert_true(key_file_config_exists(key_file, "Bond", "PrimaryReselectPolicy", "always"));
    assert_true(key_file_config_exists(key_file, "Bond", "MIIMonitorSec", "100"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-bond0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "bond0"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "89.207.130.252"));
    assert_true(g_strrstr(dns, "89.207.128.252"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "78.41.207.45/24"));

    reload_networkd("bond0");
    system("nmctl remove-netdev bond0 kind bond");
}

static void test_network_infiband(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("infiband.yaml");

    r = parse_key_file("/etc/systemd/network/10-ib0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "ib0"));
    assert_true(key_file_config_exists(key_file, "Match", "MACAddress", "11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:00"));

    assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));
    assert_true(key_file_config_exists(key_file, "IPoIB", "Mode", "connected"));
}

static void test_link_driver(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *driver = NULL;
    int r;

    apply_yaml_file("link-driver.yaml");

    r = parse_key_file("/etc/systemd/network/10-test99.link", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "OriginalName", "test99"));

    assert_true(driver=key_file_config_get(key_file, "Match", "Driver"));
    assert_true(g_strrstr(driver, "e1000"));
    assert_true(g_strrstr(driver, "ixgbe"));

    assert_true(key_file_config_exists(key_file, "Link", "ReceiveChecksumOffload", "yes"));
    assert_true(key_file_config_exists(key_file, "Link", "TransmitChecksumOffload", "yes"));
    assert_true(key_file_config_exists(key_file, "Link", "TCPSegmentationOffload", "yes"));
    assert_true(key_file_config_exists(key_file, "Link", "TCP6SegmentationOffload", "yes"));
    assert_true(key_file_config_exists(key_file, "Link", "GenericSegmentationOffload", "yes"));
    assert_true(key_file_config_exists(key_file, "Link", "GenericReceiveOffload", "yes"));
    assert_true(key_file_config_exists(key_file, "Link", "LargeReceiveOffload", "yes"));
}

static void test_link_wakeonlan(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("wakeonlan.yaml");

    r = parse_key_file("/etc/systemd/network/10-test99.link", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "OriginalName", "test99"));

    assert_true(key_file_config_exists(key_file, "Link", "WakeOnLan", "off"));
}

static void test_link_mtu(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("mtu.yaml");

    r = parse_key_file("/etc/systemd/network/10-test99.link", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "OriginalName", "test99"));

    assert_true(key_file_config_exists(key_file, "Link", "MTUBytes", "1600"));
}

static void test_netdev_bridges(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("bridges.yaml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "Network", "Bridge", "br0"));
    assert_true(key_file_config_exists(key_file, "Network", "Bridge", "br1"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-br0.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "br0"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "bridge"));

    assert_true(key_file_config_exists(key_file, "Bridge", "STP", "yes"));
    assert_true(key_file_config_exists(key_file, "Bridge", "ForwardDelaySec", "12"));
    assert_true(key_file_config_exists(key_file, "Bridge", "HelloTimeSec", "6"));
    assert_true(key_file_config_exists(key_file, "Bridge", "AgeingTimeSec", "50"));
    assert_true(key_file_config_exists(key_file, "Bridge", "MaxAgeSec", "24"));
    assert_true(key_file_config_exists(key_file, "Bridge", "Priority", "1000"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-br1.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "br1"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "bridge"));

    assert_true(key_file_config_exists(key_file, "Bridge", "STP", "yes"));
    assert_true(key_file_config_exists(key_file, "Bridge", "ForwardDelaySec", "13"));
    assert_true(key_file_config_exists(key_file, "Bridge", "HelloTimeSec", "7"));
    assert_true(key_file_config_exists(key_file, "Bridge", "AgeingTimeSec", "60"));
    assert_true(key_file_config_exists(key_file, "Bridge", "MaxAgeSec", "25"));
    assert_true(key_file_config_exists(key_file, "Bridge", "Priority", "2000"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-br0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "br0"));
    assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-br1.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "br1"));
    assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));

    system("nmctl remove-netdev br0 kind bridge");
    system("nmctl remove-netdev br1 kind bridge");
}

static void test_netdev_bridge_cost_network_file(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("bridge-cost.yaml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(key_file_config_exists(key_file, "Network", "Bridge", "br1"));
    assert_true(key_file_config_exists(key_file, "Bridge", "Cost" , "70"));
    assert_true(key_file_config_exists(key_file, "Bridge", "Priority" , "14"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-br1.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "br1"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "bridge"));

    assert_true(key_file_config_exists(key_file, "Bridge", "STP", "yes"));
    assert_true(key_file_config_exists(key_file, "Bridge", "ForwardDelaySec", "13"));
    assert_true(key_file_config_exists(key_file, "Bridge", "HelloTimeSec", "7"));
    assert_true(key_file_config_exists(key_file, "Bridge", "AgeingTimeSec", "60"));
    assert_true(key_file_config_exists(key_file, "Bridge", "MaxAgeSec", "25"));
    assert_true(key_file_config_exists(key_file, "Bridge", "Priority", "2000"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-br1.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "br1"));
    assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));

    system("nmctl remove-netdev br1 kind bridge");
}

static void test_netdev_vlan_bridge(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    apply_yaml_file("vlan-bridge.yaml");

    r = parse_key_file("/etc/systemd/network/10-br0.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "br0"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "bridge"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vlan15.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "vlan15"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "vlan"));

    assert_true(key_file_config_exists(key_file, "VLAN", "Id", "15"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-br0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "br0"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.3.99.25/24"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-vlan15.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "vlan15"));
    assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "no"));
    assert_true(key_file_config_exists(key_file, "Network", "Bridge", "br0"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));
    assert_true(key_file_config_exists(key_file, "Network", "VLAN", "vlan15"));

    system("nmctl remove-netdev br0 kind bridge");
    system("nmctl remove-netdev vlan15 kind vlan");
}

static void test_netdev_macvlans(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("macvlans.yaml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Match", "MACAddress", "de:ad:be:ef:ca:fe"));

    assert_true(key_file_config_exists(key_file, "Network", "Domains", "example.com"));
    assert_true(key_file_config_exists(key_file, "Network", "MACVLAN", "macvlan1"));
    assert_true(key_file_config_exists(key_file, "Network", "MACVLAN", "macvlan2"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "8.8.4.4"));
    assert_true(g_strrstr(dns, "8.8.8.8"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.3.0.5/23"));
    assert_true(key_file_config_exists(key_file, "Route", "Destination", "0.0.0.0/0"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "10.3.0.1"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-macvlan1.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "macvlan1"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "macvlan"));
    assert_true(key_file_config_exists(key_file, "MACVLAN", "Mode", "private"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-macvlan2.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "macvlan2"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "macvlan"));
    assert_true(key_file_config_exists(key_file, "MACVLAN", "Mode", "source"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-macvlan1.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "macvlan1"));

    key_file_free(key_file);
    r = parse_key_file("/etc/systemd/network/10-macvlan2.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "macvlan2"));

    system("nmctl remove-netdev macvlan1 kind vlan");
    system("nmctl remove-netdev macvlan2 kind vlan");
}

static void test_netdev_bond_bridge(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("bonds.yaml");

    r = parse_key_file("/etc/systemd/network/10-bond-lan.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "bond-lan"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "bond"));

    assert_true(key_file_config_exists(key_file, "Bond", "Mode", "802.3ad"));
    assert_true(key_file_config_exists(key_file, "Bond", "PrimaryReselectPolicy", "always"));
    assert_true(key_file_config_exists(key_file, "Bond", "MIIMonitorSec", "1"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-bond-wan.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "bond-wan"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "bond"));

    assert_true(key_file_config_exists(key_file, "Bond", "Mode", "active-backup"));
    assert_true(key_file_config_exists(key_file, "Bond", "PrimaryReselectPolicy", "always"));
    assert_true(key_file_config_exists(key_file, "Bond", "MIIMonitorSec", "1"));
    assert_true(key_file_config_exists(key_file, "Bond", "GratuitousARP", "5"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-bond-conntrack.netdev", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "NetDev", "Name", "bond-conntrack"));
    assert_true(key_file_config_exists(key_file, "NetDev", "Kind", "bond"));

    assert_true(key_file_config_exists(key_file, "Bond", "Mode", "balance-rr"));
    assert_true(key_file_config_exists(key_file, "Bond", "PrimaryReselectPolicy", "always"));
    assert_true(key_file_config_exists(key_file, "Bond", "MIIMonitorSec", "1"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-bond-lan.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "bond-lan"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.93.2/24"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-bond-wan.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "bond-wan"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.252/24"));
    assert_true(key_file_config_exists(key_file, "Network", "Domains", "local"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "8.8.4.4"));
    assert_true(g_strrstr(dns, "8.8.8.8"));

    assert_true(key_file_config_exists(key_file, "Route", "Destination", "0.0.0.0/0"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-bond-conntrack.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "bond-conntrack"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.254.2/24"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-enp2s0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "enp2s0"));
    assert_true(key_file_config_exists(key_file, "Network", "Bond", "bond-lan"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-enp3s0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "enp3s0"));
    assert_true(key_file_config_exists(key_file, "Network", "Bond", "bond-lan"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-enp1s0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "enp1s0"));
    assert_true(key_file_config_exists(key_file, "Network", "Bond", "bond-wan"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-enp4s0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "enp4s0"));
    assert_true(key_file_config_exists(key_file, "Network", "Bond", "bond-wan"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-enp5s0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "enp5s0"));
    assert_true(key_file_config_exists(key_file, "Network", "Bond", "bond-conntrack"));

    key_file_free(key_file);

    r = parse_key_file("/etc/systemd/network/10-enp6s0.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "enp6s0"));
    assert_true(key_file_config_exists(key_file, "Network", "Bond", "bond-conntrack"));

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
        cmocka_unit_test (test_multiple_address),
        cmocka_unit_test (test_multiple_routes_address),
        cmocka_unit_test (test_set_dns),
        cmocka_unit_test (test_revert_dns),
        cmocka_unit_test (test_revert_dns_with_parametre),
        cmocka_unit_test (test_add_remove_multiple_address),
        cmocka_unit_test (test_set_gw_keep),
        cmocka_unit_test (test_set_gw_family),
        cmocka_unit_test (test_remove_gw_family),
        cmocka_unit_test (test_set_static_address_gw),
        cmocka_unit_test (test_set_static_address_gw_dns),
        cmocka_unit_test (test_set_static_address_gw_dns_keep_yes),
        cmocka_unit_test (test_source_routing),
        cmocka_unit_test (test_additional_gw_source_routing),
        cmocka_unit_test (test_wireguard_multiple_peers),
        cmocka_unit_test (test_static_address),
        cmocka_unit_test (test_netdev_vlans),
        cmocka_unit_test (test_netdev_vlan),
        cmocka_unit_test (test_netdev_vrfs),
        cmocka_unit_test (test_netdev_bond_parametres),
        cmocka_unit_test (test_netdev_vxlans),
        cmocka_unit_test (test_netdev_bond),
        cmocka_unit_test (test_netdev_bridges),
        cmocka_unit_test (test_netdev_bridge_cost_network_file),
        cmocka_unit_test (test_netdev_vlan_bridge),
        cmocka_unit_test (test_netdev_macvlans),
        cmocka_unit_test (test_netdev_bond_bridge),
        cmocka_unit_test (test_network_infiband),
        cmocka_unit_test (test_link_driver),
        cmocka_unit_test (test_link_wakeonlan),
        cmocka_unit_test (test_link_mtu),
        cmocka_unit_test (test_dhcp6_overrides),
        cmocka_unit_test (test_ipv6_ra_overrides),
        cmocka_unit_test (test_add_dhcp4_server_static_address),
        cmocka_unit_test (test_remove_dhcp4_server_static_address),
        cmocka_unit_test (test_yaml_add_dhcp4_server_static_address),
        cmocka_unit_test (test_yaml_add_sriov),
    };

    int count_fail_tests = cmocka_run_group_tests (tests, setup, teardown);

    return count_fail_tests;
}

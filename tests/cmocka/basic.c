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

static int apply_yaml_file(const char *y) {
    _auto_cleanup_ char *c = NULL, *yaml_file = NULL;

    assert(y);

    yaml_file = string_join("", "/run/network-config-manager-ci/yaml/", y, NULL);
    if (!yaml_file)
        return -ENOMEM;

    c = string_join(" ", "/usr/bin/nmctl", "apply-file", yaml_file, NULL);
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


static int setup(void **state) {
    system("/usr/sbin/ip link add dev test99 type dummy");

    return 0;
}

static int teardown (void **state) {
    system("/usr/sbin/ip link del test99 ");

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
    };

    int count_fail_tests = cmocka_run_group_tests (tests, setup, teardown);

    return count_fail_tests;
}

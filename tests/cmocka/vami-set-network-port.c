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
#include "set-network.h"
#include "shared.h"

void test_vami_set_network_autov6(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-network dev test99 accept-ra yes") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
    assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
}

void test_vami_set_network_dhcpv4(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-network dev test99 dhcp ipv4") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "no"));
    assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "no"));
    assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));
}

void test_vami_set_network_dhcpv6(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-network dev test99 dhcp ipv6") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
    assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
    assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv6"));
}

void test_vami_set_network_dhcpv4_and_dhcpv6(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-network dev test99 dhcp yes") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
    assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
    assert_true(key_file_config_exists(key_file, "Network", "DHCP", "yes"));
}

void test_vami_set_network_ipv4_static_address_gw(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-network dev test99 a 192.168.10.51/24 gw 192.168.10.1") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.10.51/24"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.10.1"));
}

void test_vami_set_network_ipv6_static_address_gw(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-network dev test99 a fe80::10/64 gw fe80::1") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "fe80::10/64"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "fe80::1"));
}

void test_vami_set_network_ipv4_ipv6_static_address_gw(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    int r;

    assert_true(system("nmctl set-network dev test99 a 192.168.10.51/24 gw 192.168.10.1 a fe80::10/64 gw fe80::1") >= 0);

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);

    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "fe80::10/64"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "fe80::1"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.10.51/24"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.10.1"));
}

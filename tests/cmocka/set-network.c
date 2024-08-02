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

void test_set_ipv4_dhcp_yes_with_static(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes send-release no a 192.168.1.14/24 gw 192.168.1.1") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "SendRelease", "no"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.14/24"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_ipv4_dhcp_no_with_static(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 dhcp no a 192.168.1.14/24 gw 192.168.1.1") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "no"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.14/24"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_ipv4_dhcp_yes_with_static_address_static_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        char *dns = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes a 192.168.1.14/24 gw 192.168.1.1 dns 192.168.1.1,192.168.1.2") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));

        assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
        assert_true(g_strrstr(dns, "192.168.1.1"));
        assert_true(g_strrstr(dns, "192.168.1.2"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.14/24"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_ipv4_dhcp_yes_with_static_address_static_dns_use_dns_no(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        char *dns = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes a 192.168.1.14/24 gw 192.168.1.1 dns 192.168.1.1,192.168.1.2 use-dns no") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
        assert_true(g_strrstr(dns, "192.168.1.1"));
        assert_true(g_strrstr(dns, "192.168.1.2"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDNS", "no"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.14/24"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_ipv4_dhcp_yes_with_static_remove_static_automatic(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes a 192.168.1.14/24 gw 192.168.1.1") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.14/24"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));

        /* Remove static conf automatically */
        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));

        assert_false(key_file_config_exists(key_file, "Address", "Address", "192.168.1.14/24"));
        assert_false(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_ipv6_dhcp_yes_accept_ra_yes(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv6 dev test99 dhcp yes accept-ra yes") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_ipv6_dhcp_no_accept_ra_yes(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv6 dev test99 dhcp no send-release no accept-ra yes") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "no"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "SendRelease", "no"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_ipv6_dhcp_yes_with_static_remove_static_automatic(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv6 dev test99 dhcp yes a fe80::4/64 gw fe80::1") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv6"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "fe80::4/64"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "fe80::1"));

        /* Remove static conf automatically */
        assert_true(system("nmctl set-ipv6 dev test99 dhcp yes") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv6"));

        assert_false(key_file_config_exists(key_file, "Address", "Address", "fe80::4/64"));
        assert_false(key_file_config_exists(key_file, "Route", "Gateway", "fe80::1"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_ipv6_dhcp_no_with_static_remove_static_automatic(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv6 dev test99 dhcp no accept-ra no lla no a fe80::4/64 gw fe80::1") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "no"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "no"));
        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "no"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "fe80::4/64"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "fe80::1"));

        /* Remove static conf automatically */
        assert_true(system("nmctl set-ipv6 dev test99 dhcp yes") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));

        assert_false(key_file_config_exists(key_file, "Address", "Address", "fe80::4/64"));
        assert_false(key_file_config_exists(key_file, "Route", "Gateway", "fe80::1"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_static_address_gw(void **state) {
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

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_network_address_gw(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-network dev test99 a 192.168.1.12/24 gw 192.168.1.1 a 192.168.1.13/24 gw 192.168.1.2") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.12/24"));
        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.13/24"));

        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.2"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_static_address_gw_dns(void **state) {
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

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_network_address_gw_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-network dev test99 a 192.168.1.12/24 gw 192.168.1.1 a 192.168.1.13/24 gw 192.168.1.2 dns 192.168.1.2,192.168.1.1") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DNS", "192.168.1.2 192.168.1.1"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.12/24"));
        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.13/24"));

        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.2"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_static_address_gw_dns_keep_yes(void **state) {
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

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_network_address_gw_dns_keep_yes(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-network dev test99 a 192.168.1.12/24 gw 192.168.1.1 a 192.168.1.13/24 gw 192.168.1.2 dns 192.168.1.2,192.168.1.1") >= 0);
        assert_true(system("nmctl set-network dev test99 a 192.168.1.14/24 a 192.168.1.15/24 dns 192.168.1.4,192.168.1.5 keep yes") >= 0);

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

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_dynamic_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-dynamic dev test99 dhcp yes dhcp4-client-id mac") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "ClientIdentifier", "mac"));

        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "yes"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_network_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-network dev test99 dhcp yes dhcp4-client-id mac") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "ClientIdentifier", "mac"));

        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "yes"));

        unlink("/etc/systemd/network/10-test99.network");
}


void test_set_dynamic_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier_dhcp_iaid(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-dynamic dev test99 dhcp yes dhcp4-client-id mac dhcp4-iaid 0x12345 dhcp6-iaid 0x12346") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "ClientIdentifier", "mac"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "IAID", "0x12345"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "IAID", "0x12346"));

        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "yes"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_network_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier_dhcp_iaid(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-network dev test99 dhcp yes dhcp4-client-id mac dhcp4-iaid 0x12345 dhcp6-iaid 0x12346") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "ClientIdentifier", "mac"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "IAID", "0x12345"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "IAID", "0x12346"));

        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "yes"));

        unlink("/etc/systemd/network/10-test99.network");
}

void test_set_network_dhcp_ipv4_ipv4_ra_dhcp4_client_identifier_dhcp_iaid_static_address_gw_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-network dev test99 dhcp yes dhcp4-client-id mac dhcp4-iaid 0x12345 dhcp6-iaid 0x12346 a 192.168.1.41/24 gw 192.168.1.1 dns 192.168.1.1,192.168.1.2") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "ClientIdentifier", "mac"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "IAID", "0x12345"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "IAID", "0x12346"));

        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "DNS", "192.168.1.1 192.168.1.2"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.41/24"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* DHCPv4 + DHCP-DNS */
void test_dhcp_ipv4_none_ipv6_dhcp_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes lla ipv4 send-release no use-domains yes cid mac domains eng.vmware.com,vmware.com") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv4"));
        assert_true(key_file_config_exists(key_file, "Network", "Domains", "eng.vmware.com vmware.com"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "SendRelease", "no"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDomains", "yes"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "ClientIdentifier", "mac"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* DHCPv4 */
void test_dhcp_ipv4_none_ipv6_none_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        /* Default value of UseDNS=true */
        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes lla ipv4 send-release no use-dns no domains eng.vmware.com,vmware.com") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv4"));
        assert_true(key_file_config_exists(key_file, "Network", "Domains", "eng.vmware.com vmware.com"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "SendRelease", "no"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDNS", "no"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* DHCPv4 + DHCPv6 + DHCP-DNS */
void test_dhcp_ipv4_dhcp_ipv6_dhcp_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes lla yes send-release no use-domains yes cid mac") >= 0);
        assert_true(system("nmctl set-ipv6 dev test99 dhcp yes use-domains yes send-release no") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "ClientIdentifier", "mac"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDomains", "yes"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "SendRelease", "no"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "SendRelease", "no"));
        assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDomains", "yes"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* DHCPv4 + AUTOv6 + DHCP-DNS */
void test_dhcp_ipv4_auto_ipv6_dhcp_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes lla yes send-release no use-domains yes cid mac") >= 0);
        assert_true(system("nmctl set-ipv6 dev test99 accept-ra yes use-domains yes") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "ClientIdentifier", "mac"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDomains", "yes"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "SendRelease", "no"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDomains", "yes"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* DHCPv4 + STATICv6 + STATIC-DNS */
void test_dhcp_ipv4_static_ipv6_static_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes lla ipv4 send-release no use-dns no use-domains yes cid mac dns 192.168.1.10,192.168.1.20") >= 0);
        assert_true(system("nmctl set-ipv6 dev test99 use-dns no use-domains yes accept-ra no addr fe80::10 gw fe80::1 dns fe80::4,fe80::5") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv4"));
        assert_true(key_file_config_exists(key_file, "Network", "DNS", "fe80::4 fe80::5 192.168.1.10 192.168.1.20"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "no"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "ClientIdentifier", "mac"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDomains", "yes"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDNS", "no"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "SendRelease", "no"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDomains", "yes"));
        assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDNS", "no"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "fe80::10"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "fe80::1"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* STATICv4 + STATIC-DNS */
void test_static_ipv4_none_ipv6_static_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 lla no use-dns no send-release no addr 192.168.1.101 gw 192.168.1.2 dns 192.168.1.10,192.168.1.20") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "no"));
        assert_true(key_file_config_exists(key_file, "Network", "DNS", "192.168.1.10 192.168.1.20"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDNS", "no"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "SendRelease", "no"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.101"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.2"));

        unlink("/etc/systemd/network/10-test99.network");

}

/* STATICv4 + DHCPv6 + STATIC-DNS */
void test_static_ipv4_dhcp_ipv6_static_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 use-dns no use-domains yes send-release no cid mac addr 192.168.1.101 gw 192.168.1.2 dns 192.168.1.10,192.168.1.20") >= 0);
        assert_true(system("nmctl set-ipv6 dev test99 dhcp yes use-dns no use-domains yes send-release no dns fe80::4,fe80::5") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "DNS", "fe80::4 fe80::5 192.168.1.10 192.168.1.20"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDNS", "no"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDomains", "yes"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "SendRelease", "no"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "ClientIdentifier", "mac"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDNS", "no"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDomains", "yes"));
        assert_true(key_file_config_exists(key_file, "DHCPv6", "SendRelease", "no"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.101"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.2"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* STATICv4 + AUTOv6 + STATIC-DNS */
void test_static_ipv4_auto_ipv6_static_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 use-dns no send-release no addr 192.168.1.101 gw 192.168.1.2 dns 192.168.1.10,192.168.1.20") >= 0);
        assert_true(system("nmctl set-ipv6 dev test99 accept-ra yes use-dns no dns fe80::4,fe80::5") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "DNS", "fe80::4 fe80::5 192.168.1.10 192.168.1.20"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDNS", "no"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "SendRelease", "no"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDNS", "no"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.101"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.2"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* STATICv4 + STATICv6 + STATIC-DNS */
void test_static_ipv4_static_ipv6_static_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv4 dev test99 use-dns no send-release no addr 192.168.1.101 gw 192.168.1.2 dns 192.168.1.10,192.168.1.20") >= 0);
        assert_true(system("nmctl set-ipv6 dev test99 use-dns no accept-ra no addr fe80::10 gw fe80::1 dns fe80::4,fe80::5") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "no"));
        assert_true(key_file_config_exists(key_file, "Network", "DNS", "fe80::4 fe80::5 192.168.1.10 192.168.1.20"));

        assert_true(key_file_config_exists(key_file, "DHCPv4", "UseDNS", "no"));
        assert_true(key_file_config_exists(key_file, "DHCPv4", "SendRelease", "no"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDNS", "no"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.101"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.2"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "fe80::10"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "fe80::1"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* DHCPv6 + DHCP-DNS */
void test_none_ipv4_dhcp_ipv6_dhcp_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv6 dev test99 dhcp yes send-release no use-domains yes") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDomains", "yes"));
        assert_true(key_file_config_exists(key_file, "DHCPv6", "SendRelease", "no"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* AUTOv6 + DHCP-DNS */
void test_none_ipv4_auto_ipv6_dhcp_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv6 dev test99 dhcp yes accept-ra yes") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));

        unlink("/etc/systemd/network/10-test99.network");
}

/* STATICv6 + STATIC-DNS */
void test_none_ipv4_static_ipv6_static_dns(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv6 dev test99 use-dns no accept-ra no addr fe80::10 gw fe80::1 dns fe80::4,fe80::5") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);
        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "no"));
        assert_true(key_file_config_exists(key_file, "Network", "DNS", "fe80::4 fe80::5"));

        assert_true(key_file_config_exists(key_file, "DHCPv6", "UseDNS", "no"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "fe80::10"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "fe80::1"));

        unlink("/etc/systemd/network/10-test99.network");
}

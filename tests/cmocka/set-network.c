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

        assert_true(system("nmctl set-ipv4 dev test99 dhcp yes a 192.168.1.14/24 gw 192.168.1.1") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "ipv4"));

        assert_true(key_file_config_exists(key_file, "Address", "Address", "192.168.1.14/24"));
        assert_true(key_file_config_exists(key_file, "Route", "Gateway", "192.168.1.1"));
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
}

void test_set_ipv6_dhcp_no_accept_ra_yes(void **state) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert_true(system("nmctl set-ipv6 dev test99 dhcp no accept-ra yes") >= 0);

        r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
        assert_true(r >= 0);

        display_key_file(key_file);

        assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));
        assert_true(key_file_config_exists(key_file, "Network", "DHCP", "no"));
        assert_true(key_file_config_exists(key_file, "Network", "LinkLocalAddressing", "ipv6"));
        assert_true(key_file_config_exists(key_file, "Network", "IPv6AcceptRA", "yes"));
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
}

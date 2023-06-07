/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "config-parser.h"
#include "networkd-api.h"
#include "string-util.h"

int network_parse_string(const char *key, char **state) {
        _auto_cleanup_ char *s = NULL;
        int r;

        assert(state);

        r = parse_state_file("/run/systemd/netif/state", key, &s, NULL);
        if (r < 0)
                return r;

        if (isempty_str(s))
                return -ENODATA;

        *state = steal_ptr(s);
        return 0;
}

int network_parse_operational_state(char **ret) {
        return network_parse_string("OPER_STATE", ret);
}

int network_parse_carrier_state(char **ret) {
        return network_parse_string("CARRIER_STATE", ret);
}

int network_parse_address_state(char **ret) {
        return network_parse_string("ADDRESS_STATE", ret);
}

int network_parse_ipv4_address_state(char **ret) {
        return network_parse_string("IPV4_ADDRESS_STATE", ret);
}

int network_parse_ipv6_address_state(char **ret) {
        return network_parse_string("IPV6_ADDRESS_STATE", ret);
}

static int network_parse_strv(const char *key, char ***ret) {
        _auto_cleanup_ char *s = NULL;
        int r;

        assert(ret);

        r = parse_state_file("/run/systemd/netif/state", key, &s, NULL);
        if (r < 0)
                return r;

        if (isempty_str(s)) {
                *ret = NULL;
                return 0;
        }

        *ret = strsplit(s, " ", -1);
        return r;
}

int network_parse_dns(char ***ret) {
        return network_parse_strv("DNS", ret);
}

int network_parse_ntp(char ***ret) {
        return network_parse_strv("NTP", ret);
}

int network_parse_search_domains(char ***ret) {
        return network_parse_strv("DOMAINS", ret);
}

int network_parse_route_domains(char ***ret) {
        return network_parse_strv("ROUTE_DOMAINS", ret);
}

static int network_parse_link_strv(int ifindex, const char *key, char ***ret) {
        _auto_cleanup_ char *s = NULL, *path = NULL;
        int r;

        assert(ifindex);
        assert(ret);

        asprintf(&path, "/run/systemd/netif/links/%i", ifindex);
        r = parse_state_file(path, key, &s, NULL);
        if (r < 0)
                return r;

        if (isempty_str(s)) {
                *ret = NULL;
                return 0;
        }

        *ret = strsplit(s, " ", -1);
        return r;
}

static int network_parse_link_string(int ifindex, const char *key, char **ret) {
        _auto_cleanup_ char *s = NULL, *path = NULL;
        int r;

        assert(ifindex);
        assert(ret);

        asprintf(&path, "/run/systemd/netif/links/%i", ifindex);
        r = parse_state_file(path, key, &s, NULL);
        if (r < 0)
                return r;

        if (isempty_str(s)) {
                *ret = NULL;
                return 0;
        }

        *ret = steal_ptr(s);
        return r;
}

static int network_parse_link_lease_strv(int ifindex, const char *key, char ***ret) {
        _auto_cleanup_ char *s = NULL, *path = NULL;
        int r;

        assert(ifindex);
        assert(ret);

        asprintf(&path, "/run/systemd/netif/leases/%i", ifindex);
        r = parse_state_file(path, key, &s, NULL);
        if (r < 0)
                return r;

        if (isempty_str(s)) {
                *ret = NULL;
                return 0;
        }

        *ret = strsplit(s, " ", -1);
        return r;
}


static int network_parse_link_lease_string(int ifindex, const char *key, char **ret) {
        _auto_cleanup_ char *s = NULL, *path = NULL;
        int r;

        assert(ifindex);
        assert(ret);

        asprintf(&path, "/run/systemd/netif/leases/%i", ifindex);
        r = parse_state_file(path, key, &s, NULL);
        if (r < 0)
                return r;

        if (isempty_str(s)) {
                *ret = NULL;
                return 0;
        }

        *ret = steal_ptr(s);
        return r;
}

int network_parse_link_setup_state(int ifindex, char **state) {
        return network_parse_link_string(ifindex, "ADMIN_STATE", state);
}

int network_parse_link_network_file(int ifindex, char **filename) {
        return network_parse_link_string(ifindex, "NETWORK_FILE", filename);
}

int network_parse_link_operational_state(int ifindex, char **state) {
        return network_parse_link_string(ifindex, "OPER_STATE", state);
}

int network_parse_link_address_state(int ifindex, char **state) {
        return network_parse_link_string(ifindex, "ADDRESS_STATE", state);
}

int network_parse_link_ipv4_state(int ifindex, char **state) {
        return network_parse_link_string(ifindex, "IPV4_ADDRESS_STATE", state);
}

int network_parse_link_ipv6_state(int ifindex, char **state) {
        return network_parse_link_string(ifindex, "IPV6_ADDRESS_STATE", state);
}

int network_parse_link_online_state(int ifindex, char **state) {
        return network_parse_link_string(ifindex, "ONLINE_STATE", state);
}

int network_parse_link_required_for_online(int ifindex, char **state) {
        return network_parse_link_string(ifindex, "REQUIRED_FOR_ONLINE", state);
}

int network_parse_link_device_activation_policy(int ifindex, char **state) {
        return network_parse_link_string(ifindex, "ACTIVATION_POLICY", state);
}

int network_parse_link_llmnr(int ifindex, char **llmnr) {
        return network_parse_link_string(ifindex, "LLMNR", llmnr);
}

int network_parse_link_mdns(int ifindex, char **mdns) {
        return network_parse_link_string(ifindex, "MDNS", mdns);
}

int network_parse_link_dnssec(int ifindex, char **dnssec) {
        return network_parse_link_string(ifindex, "DNSSEC", dnssec);
}

int network_parse_link_dnssec_negative_trust_anchors(int ifindex, char **nta) {
        return network_parse_link_string(ifindex, "DNSSEC_NTA", nta);
}

int network_parse_link_timezone(int ifindex, char **ret) {
        return network_parse_link_string(ifindex, "TIMEZONE", ret);
}

int network_parse_link_dns(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "DNS", ret);
}

int network_parse_link_ntp(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "NTP", ret);
}

int network_parse_link_search_domains(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "DOMAINS", ret);
}

int network_parse_link_route_domains(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "ROUTE_DOMAINS", ret);
}

int network_parse_link_addresses(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "ADDRESSES", ret);
}

int network_parse_link_dhcp6_client_iaid(int ifindex, char **ret) {
        return network_parse_link_string(ifindex, "DHCP6_CLIENT_IAID", ret);
}

int network_parse_link_dhcp6_client_duid(int ifindex, char **ret) {
        return network_parse_link_string(ifindex, "DHCP6_CLIENT_DUID", ret);
}

int network_parse_link_dhcp4_address(int ifindex, char **ret) {
        return network_parse_link_lease_string(ifindex, "ADDRESS", ret);
}

int network_parse_link_dhcp4_server_address(int ifindex, char **ret) {
        return network_parse_link_lease_string(ifindex, "SERVER_ADDRESS", ret);
}

int network_parse_link_dhcp4_router(int ifindex, char **ret) {
        return network_parse_link_lease_string(ifindex, "ROUTER", ret);
}

int network_parse_link_dhcp4_client_id(int ifindex, char **ret) {
        return network_parse_link_lease_string(ifindex, "CLIENTID", ret);
}

int network_parse_link_dhcp4_address_lifetime(int ifindex, char **ret) {
        return network_parse_link_lease_string(ifindex, "LIFETIME", ret);
}

int network_parse_link_dhcp4_address_lifetime_t1(int ifindex, char **ret) {
        return network_parse_link_lease_string(ifindex, "T1", ret);
}

int network_parse_link_dhcp4_address_lifetime_t2(int ifindex, char **ret) {
        return network_parse_link_lease_string(ifindex, "T2", ret);
}

int network_parse_link_dhcp4_dns(int ifindex, char ***ret) {
        return network_parse_link_lease_strv(ifindex, "DNS", ret);
}

int network_parse_link_dhcp4_search_domains(int ifindex, char ***ret) {
        return network_parse_link_lease_strv(ifindex, "DOMAINS", ret);
}

int network_parse_link_dhcp4_ntp(int ifindex, char ***ret) {
        return network_parse_link_lease_strv(ifindex, "NTP", ret);
}

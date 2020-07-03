/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <errno.h>
#include <glib.h>
#include <string.h>

#include "alloc-util.h"
#include "config-parser.h"
#include "networkd-api.h"
#include "string-util.h"

int network_parse_operational_state(char **state) {
        _auto_cleanup_ char *s = NULL;
        int r;

        assert(state);

        r = parse_state_file("/run/systemd/netif/state", "OPER_STATE", &s);
        if (r < 0)
                return r;

        if (isempty_string(s))
                return -ENODATA;

        *state = steal_pointer(s);

        return 0;
}

static int network_parse_strv(const char *key, char ***ret) {
        _auto_cleanup_ char *s = NULL;
        int r;

        assert(ret);

        r = parse_state_file("/run/systemd/netif/state", key, &s);
        if (r < 0)
                return r;

        if (isempty_string(s)) {
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
        r = parse_state_file(path, key, &s);
        if (r < 0)
                return r;

        if (isempty_string(s)) {
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
        r = parse_state_file(path, key, &s);
        if (r < 0)
                return r;

        if (isempty_string(s)) {
                *ret = NULL;
                return 0;
        }

        *ret = steal_pointer(s);

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

int network_parse_link_dhcp4_addresses(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "DHCP4_ADDRESS", ret);
}

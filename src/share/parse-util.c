/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <linux/if.h>

#include "alloc-util.h"
#include "macros.h"
#include "parse-util.h"
#include "string-util.h"

int parse_int(const char *c, int *val) {
        char *p;
        long r;

        assert(c);

        r = strtol(c, &p, 0);
        if (!p || p == c || *p)
                return -1;

        if ((r == LONG_MAX || r == LONG_MIN) && errno == ERANGE)
                return -ERANGE;

        if (r < INT_MIN || r > INT_MAX)
                return -ERANGE;

        *val = r;
        return 0;
}

int parse_uint64(const char *c, uint64_t *val) {
        char *p;
        uint64_t r;

        assert(c);

        r = strtol(c, &p, 10);
        if (!p || p == c || *p)
                return -1;

        if (r == UINT64_MAX && errno == ERANGE)
                return -ERANGE;

        *val = r;
        return 0;
}

int parse_uint32(const char *c, unsigned *val) {
        char *p;
        long r;

        assert(c);

        r = strtol(c, &p, 0);
        if (!p || p == c || *p)
                return -1;

        if ((r == LONG_MAX || r == LONG_MIN) && errno == ERANGE)
                return -ERANGE;

        if (r < INT_MIN || r > INT_MAX)
                return -ERANGE;

        *val = r;
        return 0;
}

int parse_uint16(const char *c, uint16_t *val) {
        char *p;
        long r;

        assert(c);

        r = strtol(c, &p, 0);
        if (!p || p == c || *p)
                return -1;

        if ((r == LONG_MAX || r == LONG_MIN) && errno == ERANGE)
                return -ERANGE;

        if (r > 0xffff)
                return -ERANGE;

        *val = r;
        return 0;
}

bool is_port_or_range(const char *c) {
        uint16_t k;
        int r;

        assert(c);

        r = parse_uint16(c, &k);
        if (r < 0) {
                _auto_cleanup_strv_ char **s = NULL;
                char **j;

                s = strsplit(c, "-", -1);
                if (!s)
                        return false;

                strv_foreach(j, s) {
                        r = parse_uint16(*j, &k);
                        if (r < 0)
                                return false;
                }
        }

        return true;
}

bool is_uint32_or_max(const char *c) {
        unsigned v;
        int r;

        assert(c);

        if (str_eq(c, "max"))
            return true;

        r = parse_uint32(c, &v);
        if (r < 0)
                return false;

        return true;
}

int parse_link_queue(const char *c, unsigned *ret) {
        unsigned v;
        int r;

        assert(c);

        r = parse_uint32(c, &v);
        if (r < 0 || v > 4096) {
                return false;
        }
        *ret = v;

        return true;
}

int parse_link_gso(const char *c, int *ret) {
        unsigned v;
        int r;

        assert(c);

        r = parse_uint32(c, &v);
        if (r < 0 || v > 65535)
                return -EINVAL;

        *ret = v;
        return 0;
}

int parse_bool(const char *v) {
        if (!v)
                return -EINVAL;

        if (str_eq(v, "1") || str_eq_fold(v, "yes") || str_eq_fold(v, "y") ||
            str_eq_fold(v, "true") || str_eq_fold(v, "t") || str_eq_fold(v, "on") ||
            str_eq_fold(v, "enable"))
                return 1;
        else if (str_eq(v, "0") || str_eq_fold(v, "no") || str_eq_fold(v, "n") ||
                 str_eq_fold(v, "false") || str_eq_fold(v, "f") || str_eq_fold(v, "off") ||
                 str_eq_fold(v, "disable"))
                return 0;

        return -EINVAL;
}

const char *parse_bool_or_ip_family(const char *v) {
        if (!v)
                return NULL;

        if (str_eq(v, "1") || str_eq_fold(v, "yes") || str_eq_fold(v, "y") ||
            str_eq_fold(v, "true") || str_eq_fold(v, "t") || str_eq_fold(v, "on"))
                return "yes";
        else if (str_eq(v, "0") || str_eq_fold(v, "no") || str_eq_fold(v, "n") ||
                 str_eq_fold(v, "false") || str_eq_fold(v, "f") || str_eq_fold(v, "off"))
                return "no";
        else if (str_eq(v, "ipv4") || str_eq_fold(v, "ipv6"))
               return v;

        return NULL;
}

int parse_link_alias(const char *c) {
        assert(c);

        if (!str_eq(c, "ifalias"))
                return -EINVAL;

        return 0;
}

int parse_link_macpolicy(const char *c) {
        assert(c);

        if ((!str_eq(c, "persistent")) && (!str_eq(c, "random")) && (!str_eq(c, "none")))
                return -EINVAL;

        return 0;
}

bool valid_address_label(char *c) {
        assert(c);

        if (strlen(c) > IFNAMSIZ)
                return false;

        for(char *p = c; *p; p++)
                if (!g_ascii_isprint(*p))
                        return false;

        return true;
}

int parse_link_namepolicy(const char *c) {
        assert(c);

        if ((!str_eq(c, "kernel")) && (!str_eq(c, "database")) &&
            (!str_eq(c, "onboard")) && (!str_eq(c, "slot")) &&
            (!str_eq(c, "path")) && (!str_eq(c, "mac")) &&
            (!str_eq(c, "keep")))
                return -EINVAL;

        return 0;
}

int parse_link_name(const char *c) {
        assert(c);

        if (string_has_prefix(c, "eth") || string_has_prefix(c, "ens") || string_has_prefix(c, "lo"))
                return -EINVAL;

        return 0;
}

int parse_link_altnamepolicy(const char *c) {
        assert(c);

        if ((!str_eq(c, "database")) && (!str_eq(c, "onboard")) &&
            (!str_eq(c, "slot")) && (!str_eq(c, "path")) && (!str_eq(c, "mac")))
                return -EINVAL;

        return 0;
}

int parse_link_bytes(const char *c) {
        unsigned v;
        int r;

        assert(c);

        if (string_has_suffix(c, "K") || string_has_suffix(c, "M") || string_has_suffix(c, "G"))
                return true;

        r = parse_uint32(c, &v);
        if (r < 0)
                return false;

        return true;
}

int parse_link_duplex(const char *c) {
        assert(c);

        if ((!str_eq(c, "full")) && (!str_eq(c, "half")))
                return -EINVAL;

        return 0;
}

int parse_link_wakeonlan(const char *c) {
        assert(c);

        if((!str_eq(c, "off")) && (!str_eq(c, "phy")) && (!str_eq(c, "unicast")) &&
           (!str_eq(c, "multicast")) && (!str_eq(c, "broadcast")) &&
           (!str_eq(c, "arp")) && (!str_eq(c, "magic")) && (!str_eq(c, "secureon")))
                return -EINVAL;

        return 0;
}

int parse_link_port(const char *c) {
        assert(c);

        if((!str_eq(c, "tp")) && (!str_eq(c, "aui")) && (!str_eq(c, "bnc")) &&
           (!str_eq(c, "mii")) && (!str_eq(c, "fibre")))
                return -EINVAL;

        return 0;
}

int parse_link_advertise(const char *c) {
        assert(c);

        if((!str_eq(c, "10baset-half")) && (!str_eq(c, "10baset-full")) && (!str_eq(c, "100baset-half")) &&
           (!str_eq(c, "100baset-full")) && (!str_eq(c, "1000baset-half")) && (!str_eq(c, "1000baset-full")) &&
           (!str_eq(c, "10000baset-full")) && (!str_eq(c, "2500basex-full")) && (!str_eq(c, "1000basekx-full")) &&
           (!str_eq(c, "10000basekx4-full")) && (!str_eq(c, "10000basekr-full")) && (!str_eq(c, "10000baser-fec")) &&
           (!str_eq(c, "20000basemld2-full")) && (!str_eq(c, "20000basekr2-full")))
                return -EINVAL;

        return 0;
}

int parse_sriov_vlan_protocol(const char *c) {
        assert(c);

        if((!str_eq(c, "802.1Q")) && (!str_eq(c, "802.1ad")))
                return -EINVAL;

        return 0;
}

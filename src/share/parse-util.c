/* Copyright 2024 VMware, Inc.
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

        if (streq(c, "max"))
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

        if (streq(v, "1") || streq_fold(v, "yes") || streq_fold(v, "y") ||
            streq_fold(v, "true") || streq_fold(v, "t") || streq_fold(v, "on") ||
            streq_fold(v, "enable"))
                return 1;
        else if (streq(v, "0") || streq_fold(v, "no") || streq_fold(v, "n") ||
                 streq_fold(v, "false") || streq_fold(v, "f") || streq_fold(v, "off") ||
                 streq_fold(v, "disable"))
                return 0;

        return -EINVAL;
}

const char *parse_bool_or_ip_family(const char *v) {
        if (!v)
                return NULL;

        if (streq(v, "1") || streq_fold(v, "yes") || streq_fold(v, "y") ||
            streq_fold(v, "true") || streq_fold(v, "t") || streq_fold(v, "on"))
                return "yes";
        else if (streq(v, "0") || streq_fold(v, "no") || streq_fold(v, "n") ||
                 streq_fold(v, "false") || streq_fold(v, "f") || streq_fold(v, "off"))
                return "no";
        else if (streq(v, "ipv4") || streq_fold(v, "ipv6"))
               return v;

        return NULL;
}

int parse_link_alias(const char *c) {
        assert(c);

        if (!streq(c, "ifalias"))
                return -EINVAL;

        return 0;
}

int parse_link_macpolicy(const char *c) {
        assert(c);

        if ((!streq(c, "persistent")) && (!streq(c, "random")) && (!streq(c, "none")))
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

        if ((!streq(c, "kernel")) && (!streq(c, "database")) &&
            (!streq(c, "onboard")) && (!streq(c, "slot")) &&
            (!streq(c, "path")) && (!streq(c, "mac")) &&
            (!streq(c, "keep")))
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

        if ((!streq(c, "database")) && (!streq(c, "onboard")) &&
            (!streq(c, "slot")) && (!streq(c, "path")) && (!streq(c, "mac")))
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

        if ((!streq(c, "full")) && (!streq(c, "half")))
                return -EINVAL;

        return 0;
}

int parse_link_wakeonlan(const char *c) {
        assert(c);

        if((!streq(c, "off")) && (!streq(c, "phy")) && (!streq(c, "unicast")) &&
           (!streq(c, "multicast")) && (!streq(c, "broadcast")) &&
           (!streq(c, "arp")) && (!streq(c, "magic")) && (!streq(c, "secureon")))
                return -EINVAL;

        return 0;
}

int parse_link_port(const char *c) {
        assert(c);

        if((!streq(c, "tp")) && (!streq(c, "aui")) && (!streq(c, "bnc")) &&
           (!streq(c, "mii")) && (!streq(c, "fibre")))
                return -EINVAL;

        return 0;
}

int parse_link_advertise(const char *c) {
        assert(c);

        if((!streq(c, "10baset-half")) && (!streq(c, "10baset-full")) && (!streq(c, "100baset-half")) &&
           (!streq(c, "100baset-full")) && (!streq(c, "1000baset-half")) && (!streq(c, "1000baset-full")) &&
           (!streq(c, "10000baset-full")) && (!streq(c, "2500basex-full")) && (!streq(c, "1000basekx-full")) &&
           (!streq(c, "10000basekx4-full")) && (!streq(c, "10000basekr-full")) && (!streq(c, "10000baser-fec")) &&
           (!streq(c, "20000basemld2-full")) && (!streq(c, "20000basekr2-full")))
                return -EINVAL;

        return 0;
}

int parse_sriov_vlan_protocol(const char *c) {
        assert(c);

        if((!streq(c, "802.1Q")) && (!streq(c, "802.1ad")))
                return -EINVAL;

        return 0;
}

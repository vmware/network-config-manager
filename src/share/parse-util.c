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

int parse_integer(const char *c, int *val) {
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

        if (string_equal(c, "max"))
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

int parse_boolean(const char *v) {
        if (!v)
                return -EINVAL;

        if (string_equal(v, "1") || string_equal_fold(v, "yes") || string_equal_fold(v, "y") ||
            string_equal_fold(v, "true") || string_equal_fold(v, "t") || string_equal_fold(v, "on") ||
            string_equal_fold(v, "enable"))
                return 1;
        else if (string_equal(v, "0") || string_equal_fold(v, "no") || string_equal_fold(v, "n") ||
                 string_equal_fold(v, "false") || string_equal_fold(v, "f") || string_equal_fold(v, "off") ||
                 string_equal_fold(v, "disable"))
                return 0;

        return -EINVAL;
}

const char *parse_boolean_or_ip_family(const char *v) {
        if (!v)
                return NULL;

        if (string_equal(v, "1") || string_equal_fold(v, "yes") || string_equal_fold(v, "y") ||
            string_equal_fold(v, "true") || string_equal_fold(v, "t") || string_equal_fold(v, "on"))
                return "yes";
        else if (string_equal(v, "0") || string_equal_fold(v, "no") || string_equal_fold(v, "n") ||
                 string_equal_fold(v, "false") || string_equal_fold(v, "f") || string_equal_fold(v, "off"))
                return "no";
        else if (string_equal(v, "ipv4") || string_equal_fold(v, "ipv6"))
               return v;

        return NULL;
}

int parse_link_alias(const char *c) {
        assert(c);

        if (!string_equal(c, "ifalias"))
                return -EINVAL;

        return 0;
}

int parse_link_macpolicy(const char *c) {
        assert(c);

        if ((!string_equal(c, "persistent")) && (!string_equal(c, "random")) && (!string_equal(c, "none")))
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

        if ((!string_equal(c, "kernel")) && (!string_equal(c, "database")) &&
            (!string_equal(c, "onboard")) && (!string_equal(c, "slot")) &&
            (!string_equal(c, "path")) && (!string_equal(c, "mac")) &&
            (!string_equal(c, "keep")))
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

        if ((!string_equal(c, "database")) && (!string_equal(c, "onboard")) &&
            (!string_equal(c, "slot")) && (!string_equal(c, "path")) && (!string_equal(c, "mac")))
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

        if ((!string_equal(c, "full")) && (!string_equal(c, "half")))
                return -EINVAL;

        return 0;
}

int parse_link_wakeonlan(const char *c) {
        assert(c);

        if((!string_equal(c, "off")) && (!string_equal(c, "phy")) && (!string_equal(c, "unicast")) &&
           (!string_equal(c, "multicast")) && (!string_equal(c, "broadcast")) &&
           (!string_equal(c, "arp")) && (!string_equal(c, "magic")) && (!string_equal(c, "secureon")))
                return -EINVAL;

        return 0;
}

int parse_link_port(const char *c) {
        assert(c);

        if((!string_equal(c, "tp")) && (!string_equal(c, "aui")) && (!string_equal(c, "bnc")) &&
           (!string_equal(c, "mii")) && (!string_equal(c, "fibre")))
                return -EINVAL;

        return 0;
}

int parse_link_advertise(const char *c) {
        assert(c);

        if((!string_equal(c, "10baset-half")) && (!string_equal(c, "10baset-full")) && (!string_equal(c, "100baset-half")) &&
           (!string_equal(c, "100baset-full")) && (!string_equal(c, "1000baset-half")) && (!string_equal(c, "1000baset-full")) &&
           (!string_equal(c, "10000baset-full")) && (!string_equal(c, "2500basex-full")) && (!string_equal(c, "1000basekx-full")) &&
           (!string_equal(c, "10000basekx4-full")) && (!string_equal(c, "10000basekr-full")) && (!string_equal(c, "10000baser-fec")) &&
           (!string_equal(c, "20000basemld2-full")) && (!string_equal(c, "20000basekr2-full")))
                return -EINVAL;

        return 0;
}

int parse_sriov_vlanprotocol(const char *c) {
        assert(c);

        if((!string_equal(c, "802.1Q")) && (!string_equal(c, "802.1ad")))
                return -EINVAL;

        return 0;
}

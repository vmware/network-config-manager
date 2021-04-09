/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2021 VMware, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

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

int parse_boolean(const char *v) {
        if (!v)
                return -EINVAL;

        if (string_equal(v, "1") || string_equal_fold(v, "yes") || string_equal_fold(v, "y") ||
            string_equal_fold(v, "true") || string_equal_fold(v, "t") || string_equal_fold(v, "on"))
                return 1;
        else if (string_equal(v, "0") || string_equal_fold(v, "no") || string_equal_fold(v, "n") ||
                 string_equal_fold(v, "false") || string_equal_fold(v, "f") || string_equal_fold(v, "off"))
                return 0;

        return -EINVAL;
}

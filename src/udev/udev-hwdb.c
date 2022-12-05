/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <systemd/sd-hwdb.h>

#include "alloc-util.h"
#include "macros.h"
#include "string-util.h"
#include "udev-hwdb.h"

int hwdb_get_vendor(const uint8_t *ether_address, char **ret) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        _auto_cleanup_ char *s = NULL;
        const char *description;
        char modalias[24] = {};
        int r;

        assert(ether_address);

        r = sd_hwdb_new(&hwdb);
        if (r < 0)
                return r;

        sprintf(modalias, "OUI:%2.2X%2.2X%2.2X", ether_address[0], ether_address[1], ether_address[2]);
        r = sd_hwdb_get(hwdb, modalias, "ID_OUI_FROM_DATABASE", &description);
        if (r < 0)
                return r;

         s = strdup(description);
         if (!s)
                return -ENOMEM;

        *ret = steal_pointer(s);
        return 0;
}

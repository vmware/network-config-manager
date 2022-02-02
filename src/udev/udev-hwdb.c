/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "macros.h"
#include "string-util.h"
#include "udev-hwdb.h"

int hwdb_get_vendor_model(const char *modalias, char **vendor, char **model) {
        _cleanup_(udev_hwdb_free) struct udev_hwdb *hwdb = NULL;
        _cleanup_(udev_free) struct udev *udev = NULL;
        _auto_cleanup_ char *s = NULL, *t = NULL;
        struct udev_list_entry *head, *entry;

        assert(modalias);

        udev = udev_new();
        if (!udev)
                return -ENOMEM;

        hwdb = udev_hwdb_new(udev);
        if (!hwdb)
                return -ENOMEM;

        head = udev_hwdb_get_properties_list_entry(hwdb, modalias, 0);
        udev_list_entry_foreach(entry, head) {
                const char *name = udev_list_entry_get_name(entry);

                if (!name)
                        continue;

                if (!*vendor && string_equal(name, "ID_VENDOR_FROM_DATABASE")) {
                        s = g_strdup(udev_list_entry_get_value(entry));
                        if (!s)
                                return -ENOMEM;

                        *vendor = steal_pointer(s);
                } else if (!*model && string_equal(name, "ID_MODEL_FROM_DATABASE")) {
                        t = g_strdup(udev_list_entry_get_value(entry));
                        if (!t)
                                return -ENOMEM;

                        *model = steal_pointer(t);
                }
        }

        return 0;
}

int hwdb_get_manufacturer(const uint8_t *ether_address, char **manufacturer) {
        _cleanup_(udev_hwdb_free) struct udev_hwdb *hwdb = NULL;
        _cleanup_(udev_free) struct udev *udev = NULL;
        _auto_cleanup_ char *s = NULL;
        struct udev_list_entry *head, *entry;
        char modalias[24] = {};

        assert(ether_address);

        sprintf(modalias, "OUI:%2.2X%2.2X%2.2X", ether_address[0], ether_address[1], ether_address[2]);

        udev = udev_new();
        if (!udev)
                return -ENOMEM;

        hwdb = udev_hwdb_new(udev);
        if (!hwdb)
                return -ENOMEM;

        head = udev_hwdb_get_properties_list_entry(hwdb, modalias, 0);
        udev_list_entry_foreach(entry, head) {
                const char *name = udev_list_entry_get_name(entry);

                if (name && string_equal(name, "ID_OUI_FROM_DATABASE")) {
                        s = g_strdup(udev_list_entry_get_value(entry));
                        if (!s)
                                return -ENOMEM;
                        break;
                }
        }

        *manufacturer = steal_pointer(s);
        return 0;
}

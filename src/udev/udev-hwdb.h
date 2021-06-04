/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <libudev.h>

DEFINE_CLEANUP(struct udev_device*, udev_device_unref);
DEFINE_CLEANUP(struct udev *, udev_unref);

static inline void udev_hwdb_free(struct udev_hwdb **db) {
        if (db && *db)
                *db = udev_hwdb_unref(*db);
}

static inline void udev_free(struct udev **udev) {
        if (udev && *udev)
                *udev = udev_unref(*udev);
}

int hwdb_get_vendor_model(const char *modalias, char **vendor, char **model);
int hwdb_get_manufacturer(const uint8_t *bdaddr, char **company);

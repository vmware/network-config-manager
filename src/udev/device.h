/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <systemd/sd-device.h>

int device_new_from_ifname(sd_device **ret, char *ifname);

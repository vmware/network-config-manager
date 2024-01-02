/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <systemd/sd-journal.h>

int add_matches_for_unit(sd_journal *j, const char *unit);
int add_match_boot_id(sd_journal *j, sd_id128_t id);
int add_match_current_boot(sd_journal *j);

int display_network_logs(int ifindex, char *ifname);

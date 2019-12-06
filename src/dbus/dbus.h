/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2019 VMware, Inc.
 */

#include <stdint.h>
#include <systemd/sd-bus.h>

#include "alloc-util.h"
#include "dns.h"

#pragma once

static inline void sd_bus_freep(sd_bus **bus) {
        if (bus && *bus) {
                sd_bus_close(*bus);
                *bus = sd_bus_unref(*bus);
        }
}

int dbus_get_string_systemd_manager(const char *p, char **ret);
int dbus_get_property_from_hostnamed(const char *p, char **ret);

int dbus_set_hostname(const char *hostname);

int dbus_stop_unit(const char *unit);
int dbus_restart_unit(const char *unit);

int dbus_get_dns_servers_from_resolved(const char *dns, DNSServers **ret);
int dbus_add_dns_server(int ifindex, DNSServers *serv);
int dbus_add_dns_domains(int ifindex, char **domains);
int dbus_revert_resolve_link(int ifindex);
int dbus_get_dns_domains_from_resolved(DNSDomains **domains);

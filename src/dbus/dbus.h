/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <systemd/sd-bus.h>

#include "alloc-util.h"
#include "dns.h"

#pragma once

void sd_bus_free(sd_bus *bus);
DEFINE_CLEANUP(sd_bus *, sd_bus_free);

int dbus_get_string_systemd_manager(const char *p, char **ret);
int dbus_get_property_from_hostnamed(const char *p, char **ret);

int dbus_set_hostname(const char *hostname);

int dbus_stop_unit(const char *unit);
int dbus_restart_unit(const char *unit);

int dbus_get_dns_servers_from_resolved(const char *dns, DNSServers **ret);
int dbus_get_current_dns_servers_from_resolved(DNSServers **ret);

int dbus_add_dns_server(int ifindex, DNSServers *serv);
int dbus_add_dns_domains(int ifindex, char **domains);
int dbus_revert_resolve_link(int ifindex);
int dbus_get_dns_domains_from_resolved(DNSDomains **domains);
int dbus_network_reload(void);
int dbus_reconfigure_link(int ifindex);

int dbus_get_system_property_from_networkd(const char *p, char **ret);

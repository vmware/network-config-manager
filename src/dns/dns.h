/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2019 VMware, Inc
 */

#pragma once

#include <glib.h>

#include "network-util.h"

typedef struct DNSServer {
        int family;
        int ifindex;

        IPAddress address;
} DNSServer;

typedef struct DNSServers {
        GSequence *dns_servers;
} DNSServers;

typedef struct DNSDomain {
        int ifindex;

        char *domain;
} DNSDomain;

typedef struct DNSDomains {
        GSequence *dns_domains;
} DNSDomains;

int dns_servers_new(DNSServers **ret);
int dns_server_new(DNSServer **ret);
int dns_server_add(DNSServers **h, DNSServer *a);

int dns_domain_news(DNSDomains **ret);
int dns_domain_new(DNSDomain **ret);
int dns_domain_add(DNSDomains **h, DNSDomain *a);

int dns_read_resolv_conf(char ***dns, char ***domains);
int add_dns_server_and_domain_to_resolv_conf(DNSServers *dns, char **domains);

void dns_servers_free(DNSServers **d);
void dns_domain_freep(void *d);
void dns_domains_free(DNSDomains **d);

/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "dbus.h"
#include "dracut-parser.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "network-manager.h"
#include "network.h"
#include "networkd-api.h"
#include "parse-util.h"
#include "network-sriov.h"
#include "string-util.h"
#include "network-routing-policy-rule.h"

#define BRIDGE_PRIORITY_MAX 63

static const char *const dhcp_client_mode_table[_DHCP_CLIENT_MAX] = {
        [DHCP_CLIENT_NO]   = "no",
        [DHCP_CLIENT_YES]  = "yes",
        [DHCP_CLIENT_IPV4] = "ipv4",
        [DHCP_CLIENT_IPV6] = "ipv6",
};

const char *dhcp_client_modes_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(dhcp_client_mode_table))
                return NULL;

        return dhcp_client_mode_table[id];
}

int dhcp_client_name_to_mode(char *name) {
        assert(name);

        for (size_t i = DHCP_CLIENT_NO; i < (size_t) ELEMENTSOF(dhcp_client_mode_table); i++)
                if (str_eq_fold(name, dhcp_client_mode_table[i]))
                        return i;

        return _DHCP_CLIENT_INVALID;
}

static const char *const dhcp_client_kind_table[_DHCP_CLIENT_MAX] = {
        [DHCP_CLIENT_IPV4]   = "ipv4",
        [DHCP_CLIENT_IPV6]   = "ipv6",
};

const char *dhcp_client_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(dhcp_client_kind_table))
                return NULL;

        return dhcp_client_kind_table[id];
}

int dhcp_name_to_client(char *name) {
        assert(name);

        for (size_t i = DHCP_CLIENT_IPV4; i < (size_t) ELEMENTSOF(dhcp_client_kind_table); i++)
                if (str_eq_fold(name, dhcp_client_kind_table[i]))
                        return i;

        if (str_eq(name, "4"))
                return DHCP_CLIENT_IPV4;
        else if (str_eq(name, "6"))
                return DHCP_CLIENT_IPV6;

        return _DHCP_CLIENT_INVALID;
}

static const char *const dhcp_client_identifier[_DHCP_CLIENT_IDENTIFIER_MAX] = {
        [DHCP_CLIENT_IDENTIFIER_MAC]       = "mac",
        [DHCP_CLIENT_IDENTIFIER_DUID]      = "duid",
        [DHCP_CLIENT_IDENTIFIER_DUID_ONLY] = "duid-ony",
};

const char *dhcp_client_identifier_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(dhcp_client_identifier))
                return NULL;

        return dhcp_client_identifier[id];
}

int dhcp_client_identifier_to_mode(char *name) {
        assert(name);

        for (size_t i = DHCP_CLIENT_IDENTIFIER_MAC; i < (size_t) ELEMENTSOF(dhcp_client_identifier); i++)
                if (str_eq_fold(name, dhcp_client_identifier[i]))
                        return i;

        return _DHCP_CLIENT_IDENTIFIER_INVALID;
}

static const char *const dhcp_client_duid_type [_DHCP_CLIENT_DUID_TYPE_MAX] =  {
        [DHCP_CLIENT_DUID_TYPE_LINK_LAYER_TIME] = "link-layer-time",
        [DHCP_CLIENT_DUID_TYPE_VENDOR]          = "vendor",
        [DHCP_CLIENT_DUID_TYPE_LINK_LAYER]      = "link-layer",
        [DHCP_CLIENT_DUID_TYPE_UUID]            = "uuid",
};

const char *dhcp_client_duid_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(dhcp_client_duid_type))
                return NULL;

        return dhcp_client_duid_type[id];
}

int dhcp_client_duid_name_to_type(char *name) {
        assert(name);

        for (size_t i = DHCP_CLIENT_DUID_TYPE_LINK_LAYER_TIME; i < (size_t) ELEMENTSOF(dhcp_client_duid_type); i++)
                if (str_eq_fold(name, dhcp_client_duid_type[i]))
                        return i;

        return _DHCP_CLIENT_DUID_TYPE_INVALID;
}

static const char *const link_local_address_type[_LINK_LOCAL_ADDRESS_MAX] =  {
        [LINK_LOCAL_ADDRESS_YES]           = "yes",
        [LINK_LOCAL_ADDRESS_NO]            = "no",
        [LINK_LOCAL_ADDRESS_IPV4]          = "ipv4",
        [LINK_LOCAL_ADDRESS_IPV6]          = "ipv6",
        [LINK_LOCAL_ADDRESS_FALLBACK]      = "fallback",
        [LINK_LOCAL_ADDRESS_IPV4_FALLBACK] = "ipv4-fallback",
};

const char *link_local_address_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(link_local_address_type))
                return NULL;

        return link_local_address_type[id];
}

int link_local_address_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = LINK_LOCAL_ADDRESS_YES; i < (size_t) ELEMENTSOF(link_local_address_type); i++)
                if (str_eq_fold(name, link_local_address_type[i]))
                        return i;

        return _LINK_LOCAL_ADDRESS_INVALID;
}

static const char* const ipv6_link_local_address_gen_type[_IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_MAX] = {
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_EUI64]          = "eui64",
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_NONE]           = "none",
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_STABLE_PRIVACY] = "stable-privacy",
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_RANDOM]         = "random",
};

const char *ipv6_link_local_address_gen_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(ipv6_link_local_address_gen_type))
                return NULL;

        return ipv6_link_local_address_gen_type[id];
}

int ipv6_link_local_address_gen_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_EUI64; i < (size_t) ELEMENTSOF(ipv6_link_local_address_gen_type); i++)
                if (str_eq_fold(name, ipv6_link_local_address_gen_type[i]))
                        return i;

        return _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_INVALID;
}

static const char* const address_protocol_table[_ADDRESS_PROTOCOL_MAX] = {
        [ADDRESS_PROTOCOL_UNSPEC] = "unspec",
        [ADDRESS_PROTOCOL_LO]     = "kernel-loopback",
        [ADDRESS_PROTOCOL_RA]     = "kernel-router-announcement",
        [ADDRESS_PROTOCOL_LL]     = "kernel-link-local",
};

const char *address_protocol_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(address_protocol_table))
                return NULL;

        return address_protocol_table[id];
}

int address_protocol_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = ADDRESS_PROTOCOL_UNSPEC; i < (size_t) ELEMENTSOF(address_protocol_table); i++)
                if (str_eq_fold(name, address_protocol_table[i]))
                        return i;

        return _ADDRESS_PROTOCOL_INVALID;
}

static const char* const link_event_table[_LINK_EVENT_MAX] = {
        [LINK_EVENT_NONE]             = "none",
        [LINK_EVENT_REBOOT]           = "reboot",
        [LINK_EVENT_FEATURES]         = "feature-change",
        [LINK_EVENT_BONDING_FAILOVER] = "bonding-failover",
        [LINK_EVENT_NOTIFY_PEERS]     = "notify-peers",
        [LINK_EVENT_IGMP_RESEND]      = "resend-igmp",
        [LINK_EVENT_BONDING_OPTIONS]  = "bonding-option",
};

const char *link_event_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(link_event_table))
                return NULL;

        return link_event_table[id];
}

int link_event_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = LINK_EVENT_NONE; i < (size_t) ELEMENTSOF(link_event_table); i++)
                if (str_eq_fold(name, link_event_table[i]))
                        return i;

        return _LINK_EVENT_INVALID;
}

static const char* const ipv6_privacy_extensions_type[_IPV6_PRIVACY_EXTENSIONS_MAX] = {
        [IPV6_PRIVACY_EXTENSIONS_NO] = "no",
        [IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC] = "prefer-public",
        [IPV6_PRIVACY_EXTENSIONS_YES] = "yes",
};

const char *ipv6_privacy_extensions_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(ipv6_privacy_extensions_type))
                return NULL;

        return ipv6_privacy_extensions_type[id];
}

int ipv6_privacy_extensions_to_type(const char *name) {
        assert(name);

        for (size_t i = IPV6_PRIVACY_EXTENSIONS_NO; i < (size_t) ELEMENTSOF(ipv6_link_local_address_gen_type); i++)
                if (str_eq_fold(name, ipv6_privacy_extensions_type[i]))
                        return i;

        return _IPV6_PRIVACY_EXTENSIONS_INVALID;
}

static const char *const ipv6_ra_preference_type[_IPV6_RA_PREFERENCE_MAX] =  {
        [IPV6_RA_PREFERENCE_LOW]    = "low",
        [IPV6_RA_PREFERENCE_MEDIUM] = "medium",
        [IPV6_RA_PREFERENCE_HIGH]   = "high",
};

const char *ipv6_ra_preference_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(ipv6_ra_preference_type))
                return NULL;

        return ipv6_ra_preference_type[id];
}

int ipv6_ra_preference_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = IPV6_RA_PREFERENCE_LOW; i < (size_t) ELEMENTSOF(ipv6_ra_preference_type); i++)
                if (str_eq_fold(name, ipv6_ra_preference_type[i]))
                        return i;

        return _IPV6_RA_PREFERENCE_INVALID;
}

static const char *const ip_duplicate_address_detection_type[_IP_DUPLICATE_ADDRESS_DETECTION_MAX] =  {
        [IP_DUPLICATE_ADDRESS_DETECTION_NONE] = "none",
        [IP_DUPLICATE_ADDRESS_DETECTION_IPV4] = "ipv4",
        [IP_DUPLICATE_ADDRESS_DETECTION_IPV6] = "ipv6",
        [IP_DUPLICATE_ADDRESS_DETECTION_BOTH] = "both",
};

const char *ip_duplicate_address_detection_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(ip_duplicate_address_detection_type))
                return NULL;

        return ip_duplicate_address_detection_type[id];
}

int ip_duplicate_address_detection_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = IP_DUPLICATE_ADDRESS_DETECTION_NONE; i < (size_t) ELEMENTSOF(ip_duplicate_address_detection_type); i++)
                if (str_eq_fold(name, ip_duplicate_address_detection_type[i]))
                        return i;

        return _IP_DUPLICATE_ADDRESS_DETECTION_INVALID;
}

static const char* const keep_configuration_table[_KEEP_CONFIGURATION_MAX] = {
        [KEEP_CONFIGURATION_NO]           = "no",
        [KEEP_CONFIGURATION_DHCP_ON_STOP] = "dhcp-on-stop",
        [KEEP_CONFIGURATION_DHCP]         = "dhcp",
        [KEEP_CONFIGURATION_STATIC]       = "static",
        [KEEP_CONFIGURATION_YES]          = "yes",
};

const char *keep_configuration_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(keep_configuration_table))
                return NULL;

        return keep_configuration_table[id];
}

int keep_configuration_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = KEEP_CONFIGURATION_NO; i < (size_t) ELEMENTSOF(keep_configuration_table); i++)
                if (str_eq_fold(name, keep_configuration_table[i]))
                        return i;

        return _KEEP_CONFIGURATION_INVALID;
}

static const char *const route_scope_type[_ROUTE_SCOPE_MAX] =  {
        [ROUTE_SCOPE_UNIVERSE] = "global",
        [ROUTE_SCOPE_SITE]     = "site",
        [ROUTE_SCOPE_LINK]     = "link",
        [ROUTE_SCOPE_HOST]     = "host",
        [ROUTE_SCOPE_NOWHERE]  = "nowhere",
};

const char *route_scope_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(route_scope_type))
                return NULL;

        return route_scope_type[id];
}

int route_scope_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = ROUTE_SCOPE_UNIVERSE; i < (size_t) ELEMENTSOF(route_scope_type); i++)
                if (route_scope_type[i] && str_eq_fold(name, route_scope_type[i]))
                        return i;

        return _ROUTE_SCOPE_INVALID;
}

static const char * const route_type[_ROUTE_TYPE_MAX] = {
        [ROUTE_TYPE_UNICAST]     = "unicast",
        [ROUTE_TYPE_LOCAL]       = "local",
        [ROUTE_TYPE_BROADCAST]   = "broadcast",
        [ROUTE_TYPE_ANYCAST]     = "anycast",
        [ROUTE_TYPE_MULTICAST]   = "multicast",
        [ROUTE_TYPE_BLACKHOLE]   = "blackhole",
        [ROUTE_TYPE_UNREACHABLE] = "unreachable",
        [ROUTE_TYPE_PROHIBIT]    = "prohibit",
        [ROUTE_TYPE_THROW]       = "throw",
        [ROUTE_TYPE_NAT]         = "nat",
        [ROUTE_TYPE_XRESOLVE]    = "xresolve",
};

const char *route_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(route_type))
                return NULL;

        return route_type[id];
}

int route_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = ROUTE_TYPE_UNICAST; i < (size_t) ELEMENTSOF(route_type); i++)
                if (route_type[i] && str_eq_fold(name, route_type[i]))
                        return i;

        return _ROUTE_TYPE_INVALID;
}

static const char * const ipv6_route_preference_type[_IPV6_ROUTE_PREFERENCE_MAX] = {
        [IPV6_ROUTE_PREFERENCE_LOW]     = "low",
        [IPV6_ROUTE_PREFERENCE_MEDIUM]  = "medium",
        [IPV6_ROUTE_PREFERENCE_HIGH]    = "high",
};

const char *ipv6_route_preference_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(ipv6_route_preference_type))
                return NULL;

        return ipv6_route_preference_type[id];
}

int ipv6_route_preference_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = IPV6_ROUTE_PREFERENCE_LOW; i < (size_t) ELEMENTSOF(ipv6_route_preference_type); i++)
                if (str_eq_fold(name, ipv6_route_preference_type[i]))
                        return i;

        return _IPV6_ROUTE_PREFERENCE_INVALID;
}

static const char * const route_protocol_type[_ROUTE_PROTOCOL_MAX] = {
       [ROUTE_PROTOCOL_KERNEL]  = "kernel",
       [ROUTE_PROTOCOL_BOOT]    = "boot",
       [ROUTE_PROTOCOL_STATIC]  = "static",
       [ROUTE_PRTOCOL_DHCP]     = "dhcp",
};

const char *route_protocol_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(route_protocol_type))
                return NULL;

        return route_protocol_type[id];
}

int route_protocol_to_mode(const char *name) {
        assert(name);

        for (size_t i = IPV6_ROUTE_PREFERENCE_LOW; i < (size_t) ELEMENTSOF(route_protocol_type); i++)
                if (str_eq_fold(name, route_protocol_type[i]))
                        return i;

        return _ROUTE_PROTOCOL_INVALID;
}

static const char * const ipoib_mode_table[_IP_OIB_MODE_MODE_MAX] = {
        [IP_OIB_MODE_DATAGRAM]       = "datagram",
        [IP_OIB_MODE_MODE_CONNECTED] = "connected",
};

const char *ipoib_mode_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(ipoib_mode_table))
                return NULL;

        return ipoib_mode_table[id];
}

int ipoib_name_to_mode(const char *name) {
        assert(name);

        for (size_t i = IP_OIB_MODE_DATAGRAM; i < (size_t) ELEMENTSOF(ipoib_mode_table); i++)
                if (str_eq_fold(name, ipoib_mode_table[i]))
                        return i;

        return _IP_OIB_MODE_MODE_INVALID;
}

static const char* const dhcp6_client_start_mode_table[_DHCP6_CLIENT_START_MODE_MAX] = {
        [DHCP6_CLIENT_START_MODE_NO]                  = "no",
        [DHCP6_CLIENT_START_MODE_INFORMATION_REQUEST] = "information-request",
        [DHCP6_CLIENT_START_MODE_SOLICIT]             = "solicit",
};

const char *dhcp6_client_start_mode_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(dhcp6_client_start_mode_table))
                return NULL;

        return dhcp6_client_start_mode_table[id];
}

int dhcp6_client_start_name_to_mode(const char *name) {
        assert(name);

        for (size_t i = DHCP6_CLIENT_START_MODE_NO; i < (size_t) ELEMENTSOF(dhcp6_client_start_mode_table); i++)
                if (str_eq_fold(name, dhcp6_client_start_mode_table[i]))
                        return i;

        return _DHCP6_CLIENT_START_MODE_INVALID;
}

static const char *const auth_key_management_type[_AUTH_KEY_MANAGEMENT_MAX] =  {
        [AUTH_KEY_MANAGEMENT_NONE]    = "password",
        [AUTH_KEY_MANAGEMENT_WPA_PSK] = "psk",
        [AUTH_KEY_MANAGEMENT_WPA_EAP] = "eap",
        [AUTH_KEY_MANAGEMENT_8021X]   = "8021x",
};

const char *auth_key_management_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(auth_key_management_type))
                return NULL;

        return auth_key_management_type[id];
}

int auth_key_management_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = AUTH_KEY_MANAGEMENT_NONE; i < (size_t) ELEMENTSOF(auth_key_management_type); i++)
                if (str_eq_fold(name, auth_key_management_type[i]))
                        return i;

        return _AUTH_KEY_MANAGEMENT_INVALID;
}

static const char* const auth_eap_method_type[_AUTH_EAP_METHOD_MAX] =  {
        [AUTH_EAP_METHOD_NONE] = "none",
        [AUTH_EAP_METHOD_TLS]  = "tls",
        [AUTH_EAP_METHOD_PEAP] = "peap",
        [AUTH_EAP_METHOD_TTLS] = "ttls",
};

const char *auth_eap_method_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(auth_eap_method_type))
                return NULL;

        return auth_eap_method_type[id];
}

int auth_eap_method_to_mode(const char *name) {
        assert(name);

        for (size_t i = AUTH_EAP_METHOD_NONE; i < (size_t) ELEMENTSOF(auth_eap_method_type); i++)
                if (str_eq_fold(name, auth_eap_method_type[i]))
                        return i;

        return _AUTH_EAP_METHOD_INVALID;
}

int create_network_conf_file(const char *ifname, char **ret) {
        _auto_cleanup_ char *file = NULL, *network = NULL;
        int r;

        assert(ifname);

        r = determine_conf_file_name(ifname, &file);
        if (r < 0)
                return r;

        r = create_conf_file("/etc/systemd/network", file, "network", &network);
        if (r < 0)
                return r;

        r = set_config_file_str(network, "Match", "Name", ifname);
        if (r < 0)
                return r;

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                 return r;

        if (ret)
                *ret = steal_ptr(network);


        return dbus_network_reload();
}

int determine_network_conf_file(const char *ifname, char **ret) {
        _auto_cleanup_ char *file = NULL, *network = NULL;
        int r;

        r = determine_conf_file_name(ifname, &file);
        if (r < 0)
                return r;

        r = determine_conf_file("/etc/systemd/network", file, "network", &network);
        if (r < 0)
                return r;

        *ret = steal_ptr(network);
        return 0;
}

int create_or_parse_network_file(const IfNameIndex *ifidx, char **ret) {
        _auto_cleanup_ char *setup = NULL, *network = NULL;
        int r;

        assert(ifidx);

        (void) dbus_network_reload();

        r = network_parse_link_setup_state(ifidx->ifindex, &setup);
        if (r < 0) {
                r = create_network_conf_file(ifidx->ifname, &network);
                if (r < 0)
                        return r;
        } else {
                r = network_parse_link_network_file(ifidx->ifindex, &network);
                if (r < 0) {
                        r = create_network_conf_file(ifidx->ifname, &network);
                        if (r < 0)
                                return r;
                }
        }

        if (!g_file_test(network, G_FILE_TEST_EXISTS)) {
                r = create_network_conf_file(ifidx->ifname, &network);
                if (r < 0)
                        return r;
        }

        *ret = steal_ptr(network);
        return 0;
}

int parse_network_file(const int ifindex, const char *ifname, char **ret) {
        _auto_cleanup_ char *network = NULL;
        int r;

        if (ifindex > 0) {
                r = network_parse_link_network_file(ifindex, &network);
                if (r < 0) {
                        r = determine_network_conf_file(ifname, &network);
                        if (r < 0)
                                return r;

                        if (!g_file_test(network, G_FILE_TEST_EXISTS)) {
                                r = create_network_conf_file(ifname, &network);
                                if (r < 0)
                                        return r;
                        }
                }
        } else {
                r = determine_network_conf_file(ifname, &network);
                if (r < 0)
                        return r;

                if (!g_file_test(network, G_FILE_TEST_EXISTS)) {
                                r = create_network_conf_file(ifname, &network);
                                if (r < 0)
                                        return r;
                }

        }

        *ret = steal_ptr(network);
        return 0;
}

int dhcp4_server_new(DHCP4Server **ret) {
        _cleanup_(dhcp4_server_freep) DHCP4Server *s = NULL;

        s = new0(DHCP4Server, 1);
        if (!s)
                return -ENOMEM;

        *s = (DHCP4Server) {
               .emit_dns = -1,
               .static_leases = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free),
           };

        if (!s->static_leases)
                return -ENOMEM;

        *ret = steal_ptr(s);
        return 0;
}

void dhcp4_server_free(DHCP4Server *s) {
        if (!s)
                return;

        free(s->default_lease_time);
        free(s->max_lease_time);
        free(s);
}

static gboolean routing_policy_rule_equal(gconstpointer v1, gconstpointer v2) {
        RoutingPolicyRule *a = (RoutingPolicyRule *) v1;
        RoutingPolicyRule *b = (RoutingPolicyRule *) v2;

        if (!memcmp(&a->to, &b->to, sizeof(a->to)) &&
            !memcmp(&a->from, &b->from, sizeof(a->from)) &&
            !memcmp(&a->iif, &b->iif, sizeof(a->iif)) &&
            !memcmp(&a->oif, &b->oif, sizeof(a->oif)) &&
            a->table == b->table &&
            a->priority == b->priority &&
            a->table == b->table &&
            a->fwmark == b->fwmark &&
            a->type == b->type &&
            a->tos == b->tos &&
            a->invert_rule == b->invert_rule )
                return true;

        return false;
}


static gboolean route_equal(gconstpointer v1, gconstpointer v2) {
        Route *a = (Route *) v1;
        Route *b = (Route *) v2;

        if (!memcmp(&a->gw, &b->gw, sizeof(a->gw)) &&
            !memcmp(&a->dst, &b->dst, sizeof(a->dst)) &&
            !memcmp(&a->src, &b->src, sizeof(a->src)) &&
            !memcmp(&a->prefsrc, &b->prefsrc, sizeof(a->prefsrc)) &&
            a->family == b->family &&
            a->priority == b->priority &&
            a->table == b->table &&
            a->mtu == b->mtu &&
            a->metric == b->metric &&
            a->flags == b->flags)
                return true;

        return false;
}

static gboolean address_equal(gconstpointer v1, gconstpointer v2) {
        IPAddress *a = (IPAddress *) v1;
        IPAddress *b = (IPAddress *) v2;
        int r;

        switch (a->family) {
                case AF_INET:
                        r = memcmp(&a->in, &b->in, sizeof(a->in));
                        if (!r)
                                true;
                        break;
                case AF_INET6:
                        r = memcmp(&a->in6, &b->in6, sizeof(a->in6));
                        if (!r)
                                true;
                        break;
                default:
                        break;
        }

        if (a->family == b->family)
                return true;

        return false;
}


static int wifi_access_point_free (void *key, void *value, void *user_data) {
        WiFiAccessPoint *ap = value;

        if (!ap)
                return 0;

        free(ap->ssid);
        free(ap->auth->identity);
        free(ap->auth->anonymous_identity);
        free(ap->auth->password);
        free(ap->auth->ca_certificate);
        free(ap->auth->client_certificate);
        free(ap->auth->client_key);
        free(ap->auth->client_key_password);

        free(ap->auth);
        free(ap);

        return 0;
}

int network_new(Network **ret) {
        _auto_cleanup_ Network *n = NULL;
        int r;

        n = new(Network, 1);
        if (!n)
                return log_oom();

        *n = (Network) {
                .unmanaged = -1,
                .arp = -1,
                .multicast = -1,
                .all_multicast = -1,
                .promiscuous = -1,
                .req_for_online = -1,
                .optional = -1,
                .dhcp_type = _DHCP_CLIENT_INVALID,
                .dhcp4 = -1,
                .dhcp6 = -1,
                .dhcp4_use_mtu = -1,
                .dhcp4_use_dns = -1,
                .dhcp4_use_domains = -1,
                .dhcp4_use_routes = -1,
                .dhcp4_use_gw = -1,
                .dhcp4_use_hostname = -1,
                .dhcp4_send_hostname = -1,
                .dhcp4_send_release = -1,
                .dhcp4_use_ntp = -1,
                .dhcp6_use_dns = -1,
                .dhcp6_use_ntp = -1,
                .dhcp6_use_domains = -1,
                .dhcp6_use_hostname = -1,
                .dhcp6_send_release = -1,
                .dhcp6_rapid_commit = -1,
                .dhcp6_use_address = -1,
                .dhcp6_client_start_mode = _DHCP6_CLIENT_START_MODE_INVALID,
                .ipv6_ra_use_dns = -1,
                .ipv6_ra_use_domains = -1,
                .ipv6_ra_use_mtu = -1,
                .ipv6_ra_use_gw = -1,
                .ipv6_ra_use_route_prefix = -1,
                .ipv6_ra_use_auto_prefix = -1,
                .ipv6_ra_use_onlink_prefix = -1,
                .gateway_onlink = -1,
                .configure_without_carrier = -1,
                .lldp = -1,
                .emit_lldp = -1,
                .ipv6_accept_ra = -1,
                .enable_dhcp4_server = -1,
                .keep_configuration = _KEEP_CONFIGURATION_INVALID,
                .dhcp_client_identifier_type = _DHCP_CLIENT_IDENTIFIER_INVALID,
                .link_local = _LINK_LOCAL_ADDRESS_INVALID,
                .ipv6_address_generation = _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_INVALID,
                .ipv6_privacy = _IPV6_PRIVACY_EXTENSIONS_INVALID,
                .parser_type = _PARSER_TYPE_INVALID,
                .priority = BRIDGE_PRIORITY_MAX + 1,
                .ipoib_mode = _IP_OIB_MODE_MODE_INVALID,
        };

        r = set_new(&n->addresses, g_str_hash, address_equal);
        if (r < 0)
                return r;

        n->routes = g_hash_table_new_full(g_str_hash, route_equal, NULL, g_free);
        if (!n->routes)
                return log_oom();

        n->routing_policy_rules = g_hash_table_new_full(g_str_hash, routing_policy_rule_equal, NULL, g_free);
        if (!n->routing_policy_rules)
                return log_oom();

        n->sriovs = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
        if (!n->sriovs)
                return log_oom();

        r = set_new(&n->nameservers, g_str_hash, g_str_equal);
        if (r < 0)
                return r;

        r = set_new(&n->domains, g_str_hash, g_str_equal);
        if (r < 0)
                return r;

        *ret = steal_ptr(n);
        return 0;
}

void network_free(Network *n) {
        if (!n)
                return;

        set_freep(&n->addresses);
        set_freep(&n->nameservers);
        set_freep(&n->domains);

        g_hash_table_destroy(n->routes);
        g_hash_table_destroy(n->routing_policy_rules);
        g_hash_table_destroy(n->sriovs);

        if (n->access_points) {
                g_hash_table_foreach_steal(n->access_points, wifi_access_point_free, NULL);
                g_hash_table_destroy(n->access_points);
        }

        free(n->ifname);
        free(n->mac);
        free(n->match_mac);
        free(n->hostname);
        free(n->gateway);
        free(n->dhcp4_hostname);
        free(n->req_family_for_online);
        free(n->activation_policy);
        free(n->link);

        if (n->dhcp4_server)
                g_hash_table_destroy(n->dhcp4_server->static_leases);

        free(n->dhcp4_server);

        strv_free(n->ntps);
        strv_free(n->driver);
        free(n);
}

void g_network_free (gpointer data) {
        Network *n;

        n = data;
        network_freep(&n);
}

int parse_address_from_str_and_add(const char *s, Set *a) {
        _auto_cleanup_ IPAddress *address = NULL;
        int r;

        assert(s);
        assert(a);

        r = parse_ip_from_str(s, &address);
        if (r < 0)
                return r;


        set_add(a, address);
        steal_ptr(address);

        return 0;
}

static void append_wpa_auth_conf(const WIFIAuthentication *auth, GString *s) {
        assert(s);
        assert(auth);

        switch (auth->key_management) {
        case AUTH_KEY_MANAGEMENT_NONE:
                break;
        case AUTH_KEY_MANAGEMENT_WPA_PSK:
                g_string_append(s, "        key_mgmt=WPA-PSK\n");
                break;
        case AUTH_KEY_MANAGEMENT_WPA_EAP:
                g_string_append(s, "        key_mgmt=WPA-EAP\n");
                break;
        case AUTH_KEY_MANAGEMENT_8021X:
                g_string_append(s, "        key_mgmt=IEEE8021X\n");
                break;
        default:
                break;
        }

        switch (auth->eap_method) {
        case AUTH_EAP_METHOD_NONE:
                break;
        case AUTH_EAP_METHOD_TLS:
                g_string_append(s, "        eap=TLS\n");
                break;
        case AUTH_EAP_METHOD_PEAP:
                g_string_append(s, "        eap=PEAP\n");
                break;
        case AUTH_EAP_METHOD_TTLS:
                g_string_append(s, "        eap=TTLS\n");
                break;
        default:
                break;
        }

        if (auth->identity)
                g_string_append_printf(s, "        identity=\"%s\"\n", auth->identity);

        if (auth->anonymous_identity)
                g_string_append_printf(s, "        anonymous_identity=\"%s\"\n", auth->anonymous_identity);

        if (auth->password) {
                if (auth->key_management == AUTH_KEY_MANAGEMENT_WPA_PSK)
                        g_string_append_printf(s, "        psk=\"%s\"\n", auth->password);
                else
                        g_string_append_printf(s, "        password=\"%s\"\n", auth->password);
        }

        if (auth->ca_certificate)
                g_string_append_printf(s, "        ca_cert=\"%s\"\n", auth->ca_certificate);

        if (auth->client_certificate)
                g_string_append_printf(s, "        client_cert=\"%s\"\n", auth->client_certificate);

        if (auth->client_key)
                g_string_append_printf(s, "        private_key=\"%s\"\n", auth->client_key);

        if (auth->client_key_password)
                g_string_append_printf(s, "        private_key_passwd=\"%s\"\n", auth->client_key_password);
}

static void append_access_points(gpointer key, gpointer value, gpointer userdata) {
        GString *config = userdata;
        WiFiAccessPoint *ap = value;

        g_string_append(config, "network={\n");
        g_string_append_printf(config, "        ssid=\"%s\"\n", ap->ssid);

        append_wpa_auth_conf(ap->auth, config);

        g_string_append(config, "}\n\n");
}

int generate_wifi_config(Network *n, GString **ret) {
        _cleanup_(g_string_unrefp) GString *config = NULL;

        assert(n);

        config = g_string_new(NULL);
        if (!config)
                return log_oom();

        g_string_append(config, "# WPA Supplicant Configuration\n"
                                "# this goes in /etc/network-config-manager/wpa_supplicant.conf on Photon OS\n"
                                "# chown root, chmod 600 \n\n");
        g_string_append(config, "# allow frontend (e.g., wpa_cli) to be used by all users in 'wheel' group\n"
                                "ctrl_interface=DIR=/run/wpa_supplicant GROUP=wheel\n"
                                "update_config=1\n\n");

        g_hash_table_foreach(n->access_points, append_access_points, config);

        *ret = steal_ptr(config);
        return 0;
}

static void append_sriovs(gpointer key, gpointer value, gpointer userdata) {
        KeyFile *key_file = userdata;
        SRIOV *s = value;

        (void )sriov_add_new_section(key_file, s);
}

static void append_dhcp4_server_static_leases(gpointer key, gpointer value, gpointer userdata) {
        _cleanup_(section_freep) Section *section = NULL;
        _auto_cleanup_ char *address = NULL;
        DHCP4ServerLease *l = value;
        KeyFile *key_file = userdata;
        int r;

        r = section_new("DHCPServerStaticLease", &section);
        if (r < 0)
                return;

        r = ip_to_str(l->addr.family, &l->addr, &address);
        if (r < 0)
                return;

        (void ) add_key_to_section(section, "MACAddress", l->mac);
        (void ) add_key_to_section(section, "Address", address);

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return;

        steal_ptr(section);
}

static void append_routing_policy_rules(gpointer key, gpointer value, gpointer userdata) {
        _auto_cleanup_ char *to = NULL, *from = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        RoutingPolicyRule *rule = value;
        KeyFile *key_file = userdata;
        int r;

        if (ip_is_null(&rule->to) && ip_is_null(&rule->from))
                return;

        r = section_new("RoutingPolicyRule", &section);
        if (r < 0)
                return;

        if (!ip_is_null(&rule->from)) {
                (void) ip_to_str_prefix(rule->from.family, &rule->from, &from);
                (void ) add_key_to_section(section, "From", from);
        }

        if (!ip_is_null(&rule->to)) {
                (void) ip_to_str_prefix(rule->to.family, &rule->to, &to);
                (void ) add_key_to_section(section, "To", to);
        }

        if (rule->priority != G_MAXUINT)
                (void) add_key_to_section_uint(section, "Priority", rule->priority);

        if (rule->table > 0 && rule->table != RT_TABLE_MAIN)
                (void) add_key_to_section_uint(section, "Table", rule->table);

        if (rule->tos != G_MAXUINT8)
                (void) add_key_to_section_uint(section, "TypeOfService", rule->tos);

        if (rule->fwmark != G_MAXUINT)
                (void) add_key_to_section_uint(section, "FirewallMark", rule->fwmark);

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return;

        steal_ptr(section);
}

static void append_routes(gpointer key, gpointer value, gpointer userdata) {
        _auto_cleanup_ char *gateway = NULL, *destination = NULL, *prefsrc = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        KeyFile *key_file = userdata;
        Route *route = value;
        int r;

        if (ip_is_null(&route->dst) && ip_is_null(&route->gw))
                return;

        r = section_new("Route", &section);
        if (r < 0)
                return;

        if (!ip_is_null(&route->dst)) {
                (void) ip_to_str_prefix(route->dst.family, &route->dst, &destination);
                (void ) add_key_to_section(section, "Destination", destination);
        } else if (route->to_default) {
                switch(route->family) {
                        case AF_INET:
                                (void ) add_key_to_section(section, "Destination", "0.0.0.0/0");
                                break;
                        case AF_INET6:
                                (void ) add_key_to_section(section, "Destination", "::/0");
                                break;
                }
        }

        if (!ip_is_null(&route->gw)) {
                (void) ip_to_str_prefix(route->gw.family, &route->gw, &gateway);
                (void) add_key_to_section(section, "Gateway", gateway);
        }

        if (!ip_is_null(&route->prefsrc)) {
                (void) ip_to_str_prefix(route->prefsrc.family, &route->prefsrc, &prefsrc);
                (void) add_key_to_section(section, "PreferredSource", prefsrc);
        }

        if (route->onlink >= 0)
                (void) add_key_to_section(section, "Onlink", bool_to_str(route->onlink));

        if (route->table > 0 && route->table != RT_TABLE_MAIN)
                (void) add_key_to_section_uint(section, "Table", route->table);

       if (route->scope > 0)
                add_key_to_section(section, "Scope", route_scope_type_to_name(route->scope));

       if (route->type != _ROUTE_TYPE_INVALID && route->type != ROUTE_TYPE_UNICAST)
               (void) add_key_to_section(section, "Type", route_type_to_name(route->type));

       if (route->metric > 0)
               (void) add_key_to_section_uint(section, "RouteMetric", route->metric);

       if (route->initcwnd > 0)
               (void) add_key_to_section_uint(section, "InitialCongestionWindow", route->initcwnd);

       if (route->initrwnd > 0)
               (void) add_key_to_section_uint(section, "InitialAdvertisedReceiveWindow", route->initrwnd);

       if (route->quick_ack >= 0)
               (void) add_key_to_section(section, "QuickAck", bool_to_str(route->quick_ack));

       if (route->tfo >= 0)
               (void) add_key_to_section(section, "FastOpenNoCookie", bool_to_str(route->tfo));

       if (route->ttl_propogate >= 0)
               (void) add_key_to_section(section, "TTLPropagate", bool_to_str(route->ttl_propogate));

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return;

        steal_ptr(section);
}

static void append_nameservers(gpointer key, gpointer value, gpointer userdata) {
        _auto_cleanup_ char *pretty = NULL;
        IPAddress *a = (IPAddress *) key;
        GString *config = userdata;
        int r;

        r = ip_to_str(a->family,a, &pretty);
        if (r < 0)
                return;

        g_string_append_printf(config, "%s ", pretty);
}

static void append_domains(gpointer key, gpointer value, gpointer userdata) {
        GString *config = userdata;

        g_string_append_printf(config, "%s ", (char *) key);
}

static void append_addresses(gpointer key, gpointer value, gpointer userdata) {
        _cleanup_(section_freep) Section *section = NULL;
        _auto_cleanup_ char *addr = NULL;
        KeyFile *key_file = userdata;
        IPAddress *a = key;
        int r;

        r = section_new("Address", &section);
        if (r < 0)
                return;

        r = ip_to_str_prefix(a->family, a, &addr);
        if (r < 0)
                return;

        (void) add_key_to_section(section, "Address", addr);

        if (a->label)
                (void) add_key_to_section(section, "Label", a->label);

        if (a->lifetime)
                (void) add_key_to_section(section, "PreferredLifetime", a->lifetime);

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return;

        steal_ptr(addr);
        steal_ptr(section);
}

int generate_network_config(Network *n) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(n);

        if (n->parser_type == PARSER_TYPE_YAML && !n->modified)
                return 0;

        r = create_network_conf_file(n->ifname, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = set_config(key_file, "Match", "Name", n->ifname);
        if (r < 0)
                return r;

        if (n->match_mac) {
                r = set_config(key_file, "Match", "MACAddress", n->match_mac);
                if (r < 0)
                        return r;
        }

        if (n->driver) {
                _cleanup_(g_string_unrefp) GString *c = NULL;
                char **d;

                c = g_string_new(NULL);
                if (!c)
                        return log_oom();

                strv_foreach(d, n->driver) {
                        g_string_append_printf(c, "%s ", *d);
                }

                r = set_config(key_file, "Match", "Driver", c->str);
                if (r < 0)
                        return r;
        }

        if (n->unmanaged >= 0 || n->arp >= 0 || n->multicast >= 0 || n->all_multicast >= 0 || n->promiscuous >= 0 ||
            n->req_for_online >= 0 || n->mtu > 0 || n->mac || n->req_family_for_online || n->activation_policy || n->mac) {

                if (n->unmanaged >= 0) {
                        r = set_config(key_file, "Link", "Unmanaged", bool_to_str(!n->unmanaged));
                        if (r < 0)
                                return r;
                }

                if (n->mac) {
                        r = set_config(key_file, "Link", "MACAddress", n->mac);
                        if (r < 0)
                                return r;
                }

                if (n->arp >= 0) {
                        r = set_config(key_file, "Link", "ARP", bool_to_str(n->arp));
                        if (r < 0)
                                return r;
                }

                if (n->multicast >= 0) {
                        r = set_config(key_file, "Link", "Multicast", bool_to_str(n->multicast));
                        if (r < 0)
                                return r;
                }

                if (n->all_multicast >= 0) {
                        r = set_config(key_file, "Link", "AllMulticast", bool_to_str(n->all_multicast));
                        if (r < 0)
                                return r;
                }

                if (n->promiscuous >= 0) {
                        r = set_config(key_file, "Link", "Promiscuous", bool_to_str(n->promiscuous));
                        if (r < 0)
                                return r;
                }

                if (n->req_for_online >= 0) {
                        r = set_config(key_file, "Link", "RequiredForOnline", bool_to_str(n->req_for_online));
                        if (r < 0)
                                return r;
                }

                if (n->optional >= 0) {
                        r = set_config(key_file, "Link", "RequiredForOnline", bool_to_str(!n->optional));
                        if (r < 0)
                                return r;
                }

                if (n->mtu > 0) {
                        r = key_file_set_uint(key_file, "Link", "MTUBytes", n->mtu);
                        if (r < 0)
                                return r;
                }

                if (n->mac) {
                        r = set_config(key_file, "Link", "MACAddress", n->mac);
                        if (r < 0)
                                return r;
                }

                if (n->req_family_for_online) {
                        r = set_config(key_file, "Link", "RequiredFamilyForOnline", n->req_family_for_online);
                        if (r < 0)
                                return r;
                }

                if (n->activation_policy) {
                        r = set_config(key_file, "Link", "ActivationPolicy", n->activation_policy);
                        if (r < 0)
                                return r;
                }
        }

        if (n->dhcp_type != _DHCP_CLIENT_INVALID) {
                if (n->parser_type == PARSER_TYPE_YAML)
                        r = set_config(key_file, "Network", "DHCP", dhcp_client_modes_to_name(n->dhcp_type));
                else
                        r = set_config(key_file, "Network", "DHCP", dracut_to_networkd_dhcp_mode_to_name(n->dhcp_type));
        }

        if (n->keep_configuration != _KEEP_CONFIGURATION_INVALID) {
                r = set_config(key_file, "Network", "KeepConfiguration", keep_configuration_type_to_name(n->keep_configuration));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4 >= 0 || n->dhcp6 >= 0) {
               if (n->dhcp4 > 0  && n->dhcp6 > 0)
                       r = set_config(key_file, "Network", "DHCP", "yes");
               else if (n->dhcp4 > 0)
                       r = set_config(key_file, "Network", "DHCP", "ipv4");
               else if (n->dhcp6 > 0)
                       r = set_config(key_file, "Network", "DHCP", "ipv6");
        }

        if (n->lldp >= 0) {
                r = set_config(key_file, "Network", "LLDP", bool_to_str(n->lldp));
                if (r < 0)
                        return r;
        }

        if (n->link_local != _LINK_LOCAL_ADDRESS_INVALID) {
                r = set_config(key_file, "Network", "LinkLocalAddressing", link_local_address_type_to_name(n->link_local));
                if (r < 0)
                        return r;
        }

        if (n->ipv6_address_generation != _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_INVALID) {
                r = set_config(key_file, "Network", "IPv6LinkLocalAddressGenerationMode", ipv6_link_local_address_gen_type_to_name(n->ipv6_address_generation));
                if (r < 0)
                        return r;
        }

        if (n->ipv6_privacy != _IPV6_PRIVACY_EXTENSIONS_INVALID) {
                r = set_config(key_file, "Network", "IPv6PrivacyExtensions", ipv6_privacy_extensions_type_to_name(n->ipv6_privacy));
                if (r < 0)
                        return r;
        }

        if (n->ipv6_accept_ra >= 0) {
                r = set_config(key_file, "Network", "IPv6AcceptRA", bool_to_str(n->ipv6_accept_ra));
                if (r < 0)
                        return r;
        }

        if (n->enable_dhcp4_server >= 0) {
                r = set_config(key_file, "Network", "DHCPServer", bool_to_str(n->enable_dhcp4_server));
                if (r < 0)
                        return r;
        }

        if (n->ipv6_mtu > 0) {
                r = set_config_uint(key_file, "Network", "IPv6MTUBytes", n->ipv6_mtu);
                if (r < 0)
                        return r;
        }

        if (n->configure_without_carrier >= 0) {
                r = set_config(key_file, "Network", "ConfigureWithoutCarrier", bool_to_str(n->configure_without_carrier));
                if (r < 0)
                        return r;
        }

        if (n->nameservers && set_size(n->nameservers) > 0) {
                _cleanup_(g_string_unrefp) GString *c = NULL;

                c = g_string_new(NULL);
                if (!c)
                        return log_oom();

                set_foreach(n->nameservers, append_nameservers, c);
                r = set_config(key_file, "Network", "DNS", c->str);
                if (r < 0)
                        return r;
        }

        if (n->domains && set_size(n->domains) > 0) {
                _cleanup_(g_string_unrefp) GString *c = NULL;

                c = g_string_new(NULL);
                if (!c)
                        return log_oom();

                set_foreach(n->domains, append_domains, c);
                r = set_config(key_file, "Network", "Domains", c->str);
                if (r < 0)
                        return r;
        }

        if (n->ntps) {
                _cleanup_(g_string_unrefp) GString *c = NULL;
                char **d;

                c = g_string_new(NULL);
                if (!c)
                        return log_oom();

                strv_foreach(d, n->ntps) {
                        g_string_append_printf(c, "%s ", *d);
                }

                r = set_config(key_file, "Network", "NTP", c->str);
                if (r < 0)
                        return r;
        }

        /* [DHCPv4] */
        if (n->dhcp_client_identifier_type != _DHCP_CLIENT_IDENTIFIER_INVALID) {
                r = set_config(key_file, "DHCPv4", "ClientIdentifier", dhcp_client_identifier_to_name(n->dhcp_client_identifier_type));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_use_dns >= 0) {
                r = set_config(key_file, "DHCPv4", "UseDNS", bool_to_str(n->dhcp4_use_dns));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_use_domains >= 0) {
                r = set_config(key_file, "DHCPv4", "UseDomains", bool_to_str(n->dhcp4_use_domains));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_use_ntp >= 0) {
                r = set_config(key_file, "DHCPv4", "UseNTP", bool_to_str(n->dhcp4_use_ntp));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_use_mtu >= 0) {
                r = set_config(key_file, "DHCPv4", "UseMTU", bool_to_str(n->dhcp4_use_mtu));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_use_routes >= 0) {
                r = set_config(key_file, "DHCPv4", "UseRoutes", bool_to_str(n->dhcp4_use_routes));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_use_gw >= 0) {
                r = set_config(key_file, "DHCPv4", "UseGateway", bool_to_str(n->dhcp4_use_gw));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_use_hostname >= 0) {
                r = set_config(key_file, "DHCPv4", "UseHostname", bool_to_str(n->dhcp4_use_hostname));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_send_hostname >= 0) {
                r = set_config(key_file, "DHCPv4", "SendHostname", bool_to_str(n->dhcp4_send_hostname));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_send_release >= 0) {
                r = set_config(key_file, "DHCPv4", "SendRelease", bool_to_str(n->dhcp4_send_release));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_hostname) {
                r = set_config(key_file, "DHCPv4", "Hostname", n->dhcp4_hostname);
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_route_metric > 0) {
                r = set_config_uint(key_file, "DHCPv4", "RouteMetric", n->dhcp4_route_metric);
                if (r < 0)
                        return r;
        }

        /* [DHCPv6] */
        if (n->dhcp6_use_dns >= 0) {
                r = set_config(key_file, "DHCPv6", "UseDNS", bool_to_str(n->dhcp6_use_dns));
                if (r < 0)
                        return r;
        }

        if (n->dhcp6_use_domains >= 0) {
                r = set_config(key_file, "DHCPv6", "UseDomains", bool_to_str(n->dhcp6_use_domains));
                if (r < 0)
                        return r;
        }

        if (n->dhcp6_use_ntp >= 0) {
                r = set_config(key_file, "DHCPv6", "UseNTP", bool_to_str(n->dhcp6_use_ntp));
                if (r < 0)
                        return r;
        }

        if (n->dhcp6_use_hostname >= 0) {
                r = set_config(key_file, "DHCPv6", "UseHostname", bool_to_str(n->dhcp6_use_hostname));
                if (r < 0)
                        return r;
        }

        if (n->dhcp6_rapid_commit >= 0) {
                r = set_config(key_file, "DHCPv6", "RapidCommit", bool_to_str(n->dhcp6_rapid_commit));
                if (r < 0)
                        return r;
        }

        if (n->dhcp6_use_address >= 0) {
                r = set_config(key_file, "DHCPv6", "UseAddress", bool_to_str(n->dhcp6_use_address));
                if (r < 0)
                        return r;
        }

        if (n->dhcp6_send_release >= 0) {
                r = set_config(key_file, "DHCPv6", "SendRelease", bool_to_str(n->dhcp6_send_release));
                if (r < 0)
                        return r;
        }

        if (n->dhcp6_client_start_mode >= 0) {
                r = set_config(key_file, "DHCPv6", "WithoutRA", dhcp6_client_start_mode_to_name(n->dhcp6_client_start_mode));
                if (r < 0)
                        return r;
        }

        /* [IPv6AcceptRA] */
        if (n->ipv6_ra_token) {
                r = set_config(key_file, "IPv6AcceptRA", "Token", n->ipv6_ra_token);
                if (r < 0)
                        return r;
        }

        if (n->ipv6_ra_use_dns >= 0) {
                r = set_config(key_file, "IPv6AcceptRA", "UseDNS", bool_to_str(n->ipv6_ra_use_dns));
                if (r < 0)
                        return r;
        }

        if (n->ipv6_ra_use_domains >= 0) {
                r = set_config(key_file, "IPv6AcceptRA", "UseDomains", bool_to_str(n->ipv6_ra_use_domains));
                if (r < 0)
                        return r;
        }

        if (n->ipv6_ra_use_mtu >= 0) {
                r = set_config(key_file, "IPv6AcceptRA", "UseMTU", bool_to_str(n->ipv6_ra_use_mtu));
                if (r < 0)
                        return r;
        }

        if (n->ipv6_ra_use_gw >= 0) {
                r = set_config(key_file, "IPv6AcceptRA", "UseGateway", bool_to_str(n->ipv6_ra_use_gw));
                if (r < 0)
                        return r;
        }

        if (n->ipv6_ra_use_route_prefix >= 0) {
                r = set_config(key_file, "IPv6AcceptRA", "UseRoutePrefix", bool_to_str(n->ipv6_ra_use_route_prefix));
                if (r < 0)
                        return r;
        }

        if (n->ipv6_ra_use_auto_prefix >= 0) {
                r = set_config(key_file, "IPv6AcceptRA", "UseAutonomousPrefix", bool_to_str(n->ipv6_ra_use_auto_prefix));
                if (r < 0)
                        return r;
        }

        if (n->ipv6_ra_use_onlink_prefix >= 0) {
                r = set_config(key_file, "IPv6AcceptRA", "UseOnLinkPrefix", bool_to_str(n->ipv6_ra_use_onlink_prefix));
                if (r < 0)
                        return r;
        }

        if (n->addresses && set_size(n->addresses) > 0)
                set_foreach(n->addresses, append_addresses, key_file);

        if (n->routes && g_hash_table_size(n->routes) > 0)
                g_hash_table_foreach(n->routes, append_routes, key_file);

        if (n->routing_policy_rules && g_hash_table_size(n->routing_policy_rules) > 0)
                g_hash_table_foreach(n->routing_policy_rules, append_routing_policy_rules, key_file);

        if (n->sriovs && g_hash_table_size(n->sriovs) > 0)
                g_hash_table_foreach(n->sriovs, append_sriovs, key_file);

        if (n->neighbor_suppression > 0) {
                r = set_config(key_file, "Bridge", "NeighborSuppression", bool_to_str(n->neighbor_suppression));
                if (r < 0)
                        return r;
        }

        if (n->dhcp4_server) {
                r = set_config_uint(key_file, "DHCPServer", "PoolOffset", n->dhcp4_server->pool_offset);
                if (r < 0)
                        return r;

                r = set_config_uint(key_file, "DHCPServer", "PoolSize", n->dhcp4_server->pool_size);
                if (r < 0)
                        return r;

                if (n->dhcp4_server->default_lease_time) {
                        r = set_config(key_file, "DHCPServer", "DefaultLeaseTimeSec", n->dhcp4_server->default_lease_time);
                        if (r < 0)
                                return r;
                }

                if (n->dhcp4_server->max_lease_time) {
                        r = set_config(key_file, "DHCPServer", "MaxLeaseTimeSec", n->dhcp4_server->max_lease_time);
                        if (r < 0)
                                return r;
                }

                if (n->dhcp4_server->emit_dns >= 0) {
                        r = set_config(key_file, "DHCPServer", "EmitDNS", bool_to_str(n->dhcp4_server->emit_dns));
                        if (r < 0)
                                return r;
                }

                if (!ip_is_null(&n->dhcp4_server->dns)) {
                        _auto_cleanup_ char *dns = NULL;

                        r = ip_to_str(n->dhcp4_server->dns.family, &n->dhcp4_server->dns, &dns);
                        if (r < 0)
                                return r;
                        r = set_config(key_file, "DHCPServer", "DNS", dns);
                        if (r < 0)
                                return r;
                }

                if (g_hash_table_size(n->dhcp4_server->static_leases) > 0)
                        g_hash_table_foreach(n->dhcp4_server->static_leases, append_dhcp4_server_static_leases, key_file);
        }

        if (n->cost > 0) {
                r = set_config_uint(key_file, "Bridge", "Cost", n->cost);
                if (r < 0)
                        return r;
        }

        if (n->priority <= BRIDGE_PRIORITY_MAX) {
                r = set_config_uint(key_file, "Bridge", "Priority", n->priority);
                if (r < 0)
                        return r;
        }

        if (n->ipoib_mode != _IP_OIB_MODE_MODE_INVALID) {
                r = set_config(key_file, "IPoIB", "Mode", ipoib_mode_to_name(n->ipoib_mode));
                if (r < 0)
                        return r;
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        (void) dbus_network_reload();
        return 0;
}

int generate_master_device_network(Network *n) {
        _cleanup_(config_manager_freep) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        if (!n->netdev)
                return 0;

        r = netdev_ctl_name_to_configs_new(&m);
        if (r < 0)
                return r;

        /* MACVLAN */
        switch (n->netdev->kind) {
                case NETDEV_KIND_MACVLAN: {
                        MACVLan *macvlan = n->netdev->macvlan;

                        r = parse_ifname_or_index(macvlan->master, &p);
                        if (r < 0)
                                log_debug("Failed to find device: %s", macvlan->master);

                        r = parse_network_file(p ? p->ifindex : -1, macvlan->master, &network);
                        if (r < 0)
                                return r;

                        if (config_exists(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname))
                                break;

                        r = add_key_to_section_str(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname);
                        if (r < 0)
                                return r;
                }
                        break;
                case NETDEV_KIND_VLAN: {
                        VLan *vlan = n->netdev->vlan;

                        r = parse_ifname_or_index(vlan->master, &p);
                        if (r < 0)
                                log_debug("Failed to find device: %s", vlan->master);

                        r = parse_network_file(p ? p->ifindex : -1, vlan->master, &network);
                        if (r < 0)
                                return r;

                        if (config_exists(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname))
                                break;

                        r = add_key_to_section_str(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname);
                        if (r < 0)
                                return r;
                }
                        break;
                case NETDEV_KIND_BOND: {
                        Bond *b = n->netdev->bond;
                        char **d;

                        strv_foreach(d, b->interfaces) {
                                r = parse_ifname_or_index(*d, &p);
                                if (r < 0)
                                        log_debug("Failed to find device: %s", *d);

                                r = parse_network_file(p ? p->ifindex : -1, *d, &network);
                                if (r < 0)
                                        return r;

                                if (config_exists(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname))
                                        break;

                                r = add_key_to_section_str(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname);
                                if (r < 0)
                                        return r;
                        }
                }
                        break;
                case NETDEV_KIND_BRIDGE: {
                        Bridge *b = n->netdev->bridge;
                        char **d;

                        strv_foreach(d, b->interfaces) {
                                r = parse_ifname_or_index(*d, &p);
                                if (r < 0)
                                        log_debug("Failed to find device: %s", *d);

                                r = parse_network_file(p ? p->ifindex : -1, *d, &network);
                                if (r < 0)
                                        return r;

                                if (config_exists(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname))
                                        break;

                                r = add_key_to_section_str(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname);
                                if (r < 0)
                                        return r;
                        }
                }
                        break;
                case NETDEV_KIND_VRF: {
                        VRF *vrf = n->netdev->vrf;
                        char **d;

                        strv_foreach(d, vrf->interfaces) {
                                r = parse_ifname_or_index(*d, &p);
                                if (r < 0)
                                        log_debug("Failed to find device: %s", *d);

                                r = parse_network_file(p ? p->ifindex : -1, *d, &network);
                                if (r < 0)
                                        return r;

                                if (config_exists(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname))
                                        break;

                                r = add_key_to_section_str(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname);
                                if (r < 0)
                                        return r;
                        }
                }
                        break;
                case NETDEV_KIND_VXLAN: {
                        VxLan *vx = n->netdev->vxlan;

                        r = parse_ifname_or_index(vx->master, &p);
                        if (r < 0)
                                log_debug("Failed to find device: %s", vx->master);

                        r = parse_network_file(p ? p->ifindex : -1, vx->master, &network);
                        if (r < 0)
                                return r;

                        if (config_exists(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname))
                                break;

                        r = add_key_to_section_str(network, "Network", ctl_to_config(m, netdev_kind_to_name(n->netdev->kind)), n->netdev->ifname);
                        if (r < 0)
                                return r;
                }

                default:
                        break;
        }

        return 0;
}

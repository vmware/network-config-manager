/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "netdev.h"
#include "network-address.h"
#include "network-route.h"

typedef enum DHCPClient {
        DHCP_CLIENT_NO,
        DHCP_CLIENT_YES,
        DHCP_CLIENT_IPV4,
        DHCP_CLIENT_IPV6,
        _DHCP_CLIENT_MAX,
        _DHCP_CLIENT_INVALID = -1
} DHCPClient;

typedef enum {
        DHCP_CLIENT_IDENTIFIER_MAC,
        DHCP_CLIENT_IDENTIFIER_DUID,
        DHCP_CLIENT_IDENTIFIER_DUID_ONLY,
        _DHCP_CLIENT_IDENTIFIER_MAX,
        _DHCP_CLIENT_IDENTIFIER_INVALID = -1,
} DHCPClientIdentifier;

typedef enum DHCPClientDUIDType {
       DHCP_CLIENT_DUID_TYPE_LINK_LAYER_TIME,
       DHCP_CLIENT_DUID_TYPE_VENDOR,
       DHCP_CLIENT_DUID_TYPE_LINK_LAYER,
       DHCP_CLIENT_DUID_TYPE_UUID,
       _DHCP_CLIENT_DUID_TYPE_MAX,
       _DHCP_CLIENT_DUID_TYPE_INVALID = -1,
} DHCPClientDUIDType;

typedef enum LinkLocalAddress {
        LINK_LOCAL_ADDRESS_YES,
        LINK_LOCAL_ADDRESS_NO,
        LINK_LOCAL_ADDRESS_IPV4,
        LINK_LOCAL_ADDRESS_IPV6,
        LINK_LOCAL_ADDRESS_FALLBACK,
        LINK_LOCAL_ADDRESS_IPV4_FALLBACK,
       _LINK_LOCAL_ADDRESS_MAX,
       _LINK_LOCAL_ADDRESS_INVALID = -1,
} LinkLocalAddress;

typedef enum IPDuplicateAddressDetection {
        IP_DUPLICATE_ADDRESS_DETECTION_NONE,
        IP_DUPLICATE_ADDRESS_DETECTION_IPV4,
        IP_DUPLICATE_ADDRESS_DETECTION_IPV6,
        IP_DUPLICATE_ADDRESS_DETECTION_BOTH,
       _IP_DUPLICATE_ADDRESS_DETECTION_MAX,
       _IP_DUPLICATE_ADDRESS_DETECTION_INVALID = -1,
} IPDuplicateAddressDetection;

typedef enum IPv6RAPreference {
        IPV6_RA_PREFERENCE_LOW,
        IPV6_RA_PREFERENCE_MEDIUM,
        IPV6_RA_PREFERENCE_HIGH,
       _IPV6_RA_PREFERENCE_MAX,
       _IPV6_RA_PREFERENCE_INVALID = -1,
} IPv6RAPreference;

typedef enum RouteScope {
        ROUTE_SCOPE_UNIVERSE,
        ROUTE_SCOPE_SITE,
        ROUTE_SCOPE_LINK,
        ROUTE_SCOPE_HOST,
        ROUTE_SCOPE_NOWHERE,
       _ROUTE_SCOPE_MAX,
       _ROUTE_SCOPE_INVALID = -1,
} RouteScope;

typedef enum IPv6RoutePreference {
        IPV6_ROUTE_PREFERENCE_LOW,
        IPV6_ROUTE_PREFERENCE_MEDIUM,
        IPV6_ROUTE_PREFERENCE_HIGH,
        _IPV6_ROUTE_PREFERENCE_MAX,
        _IPV6_ROUTE_PREFERENCE_INVALID = -1,
} IPv6RoutePreference;

typedef enum RouteProtcol {
       ROUTE_PROTOCOL_KERNEL,
       ROUTE_PROTOCOL_BOOT,
       ROUTE_PROTOCOL_STATIC,
       ROUTE_PRTOCOL_DHCP,
       _ROUTE_PROTOCOL_MAX,
       _ROUTE_PROTOCOL_INVALID = -1,
} RouteProtocol;

typedef enum RouteType {
       ROUTE_TYPE_UNICAST,
       ROUTE_TYPE_LOCAL,
       ROUTE_TYPE_BROADCAST,
       ROUTE_TYPE_ANYCAST,
       ROUTE_TYPE_MULTICAST,
       ROUTE_TYPE_BLACKHOLE,
       ROUTE_TYPE_UNREACHABLE,
       ROUTE_TYPE_PROHIBIT,
       ROUTE_TYPE_THROW,
       ROUTE_TYPE_NAT,
       ROUTE_TYPE_XRESOLVE,
       _ROUTE_TYPE_MAX,
       _ROUTE_TYPE_INVALID = -1
} RouteType;

/* iproute */
typedef enum RouteTable {
       ROUTE_TABLE_UNSPEC,
       ROUTE_TABLE_DEFAULT  = 253,
       ROUTE_TABLE_MAIN     = 254,
       ROUTE_TABLE_LOCAL    = 255,
       _ROUTE_TABLE_MAX,
       _ROUTE_TABLE_INVALID = -1
} RouteTable;

typedef enum AuthKeyManagement {
        AUTH_KEY_MANAGEMENT_NONE,
        AUTH_KEY_MANAGEMENT_WPA_PSK,
        AUTH_KEY_MANAGEMENT_WPA_EAP,
        AUTH_KEY_MANAGEMENT_8021X,
        _AUTH_KEY_MANAGEMENT_MAX,
        _AUTH_KEY_MANAGEMENT_INVALID = -1,
} AuthKeyManagement;

typedef enum AuthEAPMethod {
        AUTH_EAP_METHOD_NONE,
        AUTH_EAP_METHOD_TLS,
        AUTH_EAP_METHOD_PEAP,
        AUTH_EAP_METHOD_TTLS,
        _AUTH_EAP_METHOD_MAX,
        _AUTH_EAP_METHOD_INVALID = -1,
} AuthEAPMethod;

typedef enum ParserType {
        PARSER_TYPE_YAML,
        PARSER_TYPE_DRACUT,
        _PARSER_TYPE_MAX,
        _PARSER_TYPE_INVALID = -1,
} ParserType;

typedef struct WIFIAuthentication {
        AuthKeyManagement key_management;
        AuthEAPMethod eap_method;

        char *identity;
        char *anonymous_identity;
        char *password;
        char *ca_certificate;
        char *client_certificate;
        char *client_key;
        char *client_key_password;
} WIFIAuthentication;

typedef struct WiFiAccessPoint {
        char *ssid;

        WIFIAuthentication *auth;
} WiFiAccessPoint;

typedef struct Network {
        char *ifname;
        char *mac;
        char *match_mac;
        char *hostname;
        char *req_family_for_online;

        ParserType parser_type;
        DHCPClient dhcp_type;
        DHCPClientIdentifier dhcp_client_identifier_type;
        LinkLocalAddress link_local;

        int unmanaged;
        int arp;
        int multicast;
        int all_multicast;
        int promiscuous;
        int req_for_online;
        uint32_t mtu;

        int dhcp4_use_mtu;
        int dhcp4_use_dns;
        int dhcp4_use_domains;
        int dhcp4_use_ntp;
        int dhcp6_use_dns;
        int dhcp6_use_ntp;
        int lldp;
        int ipv6_accept_ra;

        IPAddress *gateway;
        int gateway_onlink;

        Set *addresses;
        Set *nameservers;
        Set *ntps;

        NetDev *netdev;

        GHashTable *access_points;
        GHashTable *routes;
} Network;

int network_new(Network **ret);
void network_unrefp(Network **n);
void g_network_free(gpointer data);

int parse_address_from_string_and_add(const char *s, Set *a);

int create_network_conf_file(const char *ifname, char **ret);
int create_or_parse_network_file(const IfNameIndex *ifnameidx, char **ret);

const char *dhcp_client_modes_to_name(int id);
int dhcp_client_name_to_mode(char *name);

const char *dhcp_client_to_name(int id);
int dhcp_name_to_client(char *name);

const char *dhcp_client_identifier_to_name(int id);
int dhcp_client_identifier_to_mode(char *name);

const char *dhcp_client_duid_type_to_name(int id);
int dhcp_client_duid_type_to_mode(char *name);

const char *ipv6_ra_preference_type_to_name(int id);
int ipv6_ra_preference_type_to_mode(const char *name);

const char *auth_key_management_type_to_name(int id);
int auth_key_management_type_to_mode(const char *name);

const char *auth_eap_method_to_name(int id);
int auth_eap_method_to_mode(const char *name);

const char *link_local_address_type_to_name(int id);
int link_local_address_type_to_mode(const char *name);

const char *ip_duplicate_address_detection_type_to_name(int id);
int ip_duplicate_address_detection_type_to_mode(const char *name);

const char *route_scope_type_to_name(int id);
int route_scope_type_to_mode(const char *name);

const char *route_type_to_name(int id);
int route_type_to_mode(const char *name);

const char *ipv6_route_preference_to_name(int id);
int ipv6_route_preference_type_to_mode(const char *name);

const char *route_protocol_to_name(int id);
int route_protocol_to_mode(const char *name);

const char *route_table_to_name(int id);
int route_table_to_mode(const char *name);

int generate_network_config(Network *n, GString **ret);
int generate_wifi_config(Network *n, GString **ret);

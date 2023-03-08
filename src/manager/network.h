/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <linux/fib_rules.h>

#include "netdev.h"
#include "network-address.h"
#include "network-route.h"

typedef enum DHCPClient {
        DHCP_CLIENT_NO,
        DHCP_CLIENT_YES,
        DHCP_CLIENT_IPV4,
        DHCP_CLIENT_IPV6,
        _DHCP_CLIENT_MAX,
        _DHCP_CLIENT_INVALID = -EINVAL
} DHCPClient;

typedef enum {
        DHCP_CLIENT_IDENTIFIER_MAC,
        DHCP_CLIENT_IDENTIFIER_DUID,
        DHCP_CLIENT_IDENTIFIER_DUID_ONLY,
        _DHCP_CLIENT_IDENTIFIER_MAX,
        _DHCP_CLIENT_IDENTIFIER_INVALID = -EINVAL,
} DHCPClientIdentifier;

typedef enum DHCPClientDUIDType {
       DHCP_CLIENT_DUID_TYPE_LINK_LAYER_TIME,
       DHCP_CLIENT_DUID_TYPE_VENDOR,
       DHCP_CLIENT_DUID_TYPE_LINK_LAYER,
       DHCP_CLIENT_DUID_TYPE_UUID,
       _DHCP_CLIENT_DUID_TYPE_MAX,
       _DHCP_CLIENT_DUID_TYPE_INVALID = -EINVAL,
} DHCPClientDUIDType;

typedef enum LinkLocalAddress {
        LINK_LOCAL_ADDRESS_YES,
        LINK_LOCAL_ADDRESS_NO,
        LINK_LOCAL_ADDRESS_IPV4,
        LINK_LOCAL_ADDRESS_IPV6,
        LINK_LOCAL_ADDRESS_FALLBACK,
        LINK_LOCAL_ADDRESS_IPV4_FALLBACK,
       _LINK_LOCAL_ADDRESS_MAX,
       _LINK_LOCAL_ADDRESS_INVALID = -EINVAL,
} LinkLocalAddress;

typedef enum IPv6LinkLocalAddressGenMode {
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_EUI64,
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_NONE,
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_STABLE_PRIVACY,
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_RANDOM,
       _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_MAX,
       _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_INVALID = -EINVAL,
} IPv6LinkLocalAddressGenMode;

typedef enum IPv6PrivacyExtensions {
        IPV6_PRIVACY_EXTENSIONS_NO,
        IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC,
        IPV6_PRIVACY_EXTENSIONS_YES,
        _IPV6_PRIVACY_EXTENSIONS_MAX,
        _IPV6_PRIVACY_EXTENSIONS_INVALID = -EINVAL,
} IPv6PrivacyExtensions;

typedef enum IPDuplicateAddressDetection {
        IP_DUPLICATE_ADDRESS_DETECTION_NONE,
        IP_DUPLICATE_ADDRESS_DETECTION_IPV4,
        IP_DUPLICATE_ADDRESS_DETECTION_IPV6,
        IP_DUPLICATE_ADDRESS_DETECTION_BOTH,
       _IP_DUPLICATE_ADDRESS_DETECTION_MAX,
       _IP_DUPLICATE_ADDRESS_DETECTION_INVALID = -EINVAL,
} IPDuplicateAddressDetection;

typedef enum IPv6RAPreference {
        IPV6_RA_PREFERENCE_LOW,
        IPV6_RA_PREFERENCE_MEDIUM,
        IPV6_RA_PREFERENCE_HIGH,
       _IPV6_RA_PREFERENCE_MAX,
       _IPV6_RA_PREFERENCE_INVALID = -EINVAL,
} IPv6RAPreference;

typedef enum RouteScope {
        ROUTE_SCOPE_UNIVERSE,
        ROUTE_SCOPE_SITE,
        ROUTE_SCOPE_LINK,
        ROUTE_SCOPE_HOST,
        ROUTE_SCOPE_NOWHERE,
       _ROUTE_SCOPE_MAX,
       _ROUTE_SCOPE_INVALID = -EINVAL,
} RouteScope;

typedef enum IPv6RoutePreference {
        IPV6_ROUTE_PREFERENCE_LOW,
        IPV6_ROUTE_PREFERENCE_MEDIUM,
        IPV6_ROUTE_PREFERENCE_HIGH,
        _IPV6_ROUTE_PREFERENCE_MAX,
        _IPV6_ROUTE_PREFERENCE_INVALID = -EINVAL,
} IPv6RoutePreference;

typedef enum RouteProtcol {
       ROUTE_PROTOCOL_KERNEL,
       ROUTE_PROTOCOL_BOOT,
       ROUTE_PROTOCOL_STATIC,
       ROUTE_PRTOCOL_DHCP,
       _ROUTE_PROTOCOL_MAX,
       _ROUTE_PROTOCOL_INVALID = -EINVAL,
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
       _ROUTE_TYPE_INVALID = -EINVAL
} RouteType;

/* iproute */
typedef enum RouteTable {
       ROUTE_TABLE_UNSPEC,
       ROUTE_TABLE_DEFAULT  = 253,
       ROUTE_TABLE_MAIN     = 254,
       ROUTE_TABLE_LOCAL    = 255,
       _ROUTE_TABLE_MAX,
       _ROUTE_TABLE_INVALID = -EINVAL
} RouteTable;

typedef enum AuthKeyManagement {
        AUTH_KEY_MANAGEMENT_NONE,
        AUTH_KEY_MANAGEMENT_WPA_PSK,
        AUTH_KEY_MANAGEMENT_WPA_EAP,
        AUTH_KEY_MANAGEMENT_8021X,
        _AUTH_KEY_MANAGEMENT_MAX,
        _AUTH_KEY_MANAGEMENT_INVALID = -EINVAL,
} AuthKeyManagement;

typedef enum AuthEAPMethod {
        AUTH_EAP_METHOD_NONE,
        AUTH_EAP_METHOD_TLS,
        AUTH_EAP_METHOD_PEAP,
        AUTH_EAP_METHOD_TTLS,
        _AUTH_EAP_METHOD_MAX,
        _AUTH_EAP_METHOD_INVALID = -EINVAL,
} AuthEAPMethod;

typedef enum ParserType {
        PARSER_TYPE_YAML,
        PARSER_TYPE_DRACUT,
        _PARSER_TYPE_MAX,
        _PARSER_TYPE_INVALID = -EINVAL,
} ParserType;

typedef struct RoutingPolicyRule {
        IPAddress to;
        IPAddress from;

        IfNameIndex oif;
        IfNameIndex iif;

        bool invert;

        char *ipproto;
        char *sport;
        char *dport;

        uint8_t tos;
        uint8_t type;

        uint32_t table;
        uint32_t priority;

        struct fib_rule_uid_range uid_range;
} RoutingPolicyRule;

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
        char *driver;
        char *hostname;
        char *req_family_for_online;
        char *activation_policy;

        ParserType parser_type;
        DHCPClient dhcp_type;

        int dhcp4;
        int dhcp6;

        DHCPClientIdentifier dhcp_client_identifier_type;
        LinkLocalAddress link_local;
        IPv6LinkLocalAddressGenMode ipv6_address_generation;
        IPv6PrivacyExtensions ipv6_privacy;

        int unmanaged;
        int arp;
        int multicast;
        int all_multicast;
        int promiscuous;
        int req_for_online;
        uint32_t mtu;
        uint32_t ipv6_mtu;

        /* dhcp4 section  */
        uint32_t dhcp4_route_metric;
        int dhcp4_use_mtu;
        int dhcp4_use_dns;
        int dhcp4_use_domains;
        int dhcp4_use_ntp;
        int dhcp4_use_routes;
        int dhcp4_use_hostname;
        int dhcp4_send_hostname;
        char *dhcp4_hostname;

        /* dhcp6 section  */
        int dhcp6_use_dns;
        int dhcp6_use_ntp;
        int dhcp6_use_domains;
        int dhcp6_use_address;
        int dhcp6_use_hostname;

        /* Network section */
        int lldp;
        int emit_lldp;
        int ipv6_accept_ra;

        IPAddress *gateway;
        int gateway_onlink;

        Set *addresses;
        Set *nameservers;
        Set *domains;
        Set *ntps;

        void *link;
        NetDev *netdev;

        bool modified;

        GHashTable *access_points;
        GHashTable *routes;
} Network;

int network_new(Network **ret);
void network_free(Network *n);
DEFINE_CLEANUP(Network*, network_free);
void g_network_free(gpointer data);

typedef struct Networks {
    GHashTable *networks;
} Networks;

int networks_new(Networks **ret);
void networks_free(Networks *n);
DEFINE_CLEANUP(Networks*, networks_free);

int routing_policy_rule_new(RoutingPolicyRule **ret);
void routing_policy_rule_free(RoutingPolicyRule *rule);
DEFINE_CLEANUP(RoutingPolicyRule*, routing_policy_rule_free);

int parse_address_from_string_and_add(const char *s, Set *a);

int create_network_conf_file(const char *ifname, char **ret);
int create_or_parse_network_file(const IfNameIndex *ifidx, char **ret);

const char *dhcp_client_modes_to_name(int id);
int dhcp_client_name_to_mode(char *name);

const char *dhcp_client_to_name(int id);
int dhcp_name_to_client(char *name);

const char *dhcp_client_identifier_to_name(int id);
int dhcp_client_identifier_to_mode(char *name);

const char *dhcp_client_duid_type_to_name(int id);
int dhcp_client_duid_name_to_type(char *name);

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

const char *ipv6_link_local_address_gen_type_to_name(int id);
int ipv6_link_local_address_gen_type_to_mode(const char *name);

const char *ipv6_privacy_extensions_type_to_name(int id);
int ipv6_privacy_extensions_to_type(const char *name);

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

int generate_network_config(Network *n);
int generate_wifi_config(Network *n, GString **ret);

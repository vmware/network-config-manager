/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <network-config-manager.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "arphrd-to-name.h"
#include "ctl.h"
#include "ctl-display.h"
#include "dbus.h"
#include "dns.h"
#include "log.h"
#include "macros.h"
#include "netdev-link.h"
#include "network-address.h"
#include "network-link.h"
#include "network-manager.h"
#include "network-route.h"
#include "network-sriov.h"
#include "network-util.h"
#include "networkd-api.h"
#include "nftables.h"
#include "parse-util.h"
#include "udev-hwdb.h"
#include "network-json.h"
#include "config-parser.h"

_public_ int ncm_link_set_mtu(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t mtu;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        r = parse_mtu(argv[2], &mtu);
        if (r < 0) {
                log_warning("Failed to parse link mtu '%s': %s", argv[2], g_strerror(-r));
                return r;
        }

        r = manager_set_link_mtu(p, mtu);
        if (r < 0) {
                log_warning("Failed to update MTU for '%s': %s", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_get_mtu(const char *ifname, uint32_t *ret) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t mtu;
        int r;

        assert(ifname);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return -errno;

        r = link_get_mtu(p->ifname, &mtu);
        if (r < 0)
                return r;

        *ret = mtu;
        return 0;
}

_public_ int ncm_link_set_mac(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        if (!parse_ether_address(argv[2])) {
               log_warning("Failed to parse MAC address: %s", argv[2]);
               return -EINVAL;
        }

        r = manager_set_link_mac_addr(p, argv[2]);
        if (r < 0) {
                log_warning("Failed to update MAC Address for '%s': %s", p->ifname, g_strerror(-r) );
                return r;
        }

        return 0;
}

_public_ int ncm_link_get_mac(const char *ifname, char **ret) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        char *mac;
        int r;

        assert(ifname);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return -errno;

        r = link_read_sysfs_attribute(p->ifname, "address", &mac);
        if (r < 0)
                return r;

        *ret = mac;
        return 0;
}

_public_ int ncm_link_set_mode(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool k;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        r = parse_boolean(argv[2]);
        if (r < 0) {
                log_warning("Failed to parse link mode '%s' '%s': %s", p->ifname, argv[2], g_strerror(-r));
                return r;
        }

        k = r;
        r = manager_set_link_flag(p, !k, "Unmanaged");
        if (r < 0) {
                printf("Failed to set link mode '%s': %s\n", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_option(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool k;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "arp")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse link arp '%s' '%s': %s", p->ifname, argv[i], g_strerror(-r));
                                return r;
                        }

                        k = r;
                        r = manager_set_link_flag(p, k, "ARP");
                        if (r < 0) {
                                printf("Failed to set link arp '%s': %s\n", p->ifname, g_strerror(-r));
                                return r;
                        }

                        continue;
                }
                if (string_equal(argv[i], "mc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse link multicast '%s' '%s': %s", p->ifname, argv[i], g_strerror(-r));
                                return r;
                        }

                        k = r;
                        r = manager_set_link_flag(p, k, "Multicast");
                        if (r < 0) {
                                printf("Failed to set link multicast '%s': %s\n", p->ifname, g_strerror(-r));
                                return r;
                        }

                        continue;
                }
                if (string_equal(argv[i], "amc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse link allmulticast '%s' '%s': %s", p->ifname, argv[i], g_strerror(-r));
                                return r;
                        }

                        k = r;
                        r = manager_set_link_flag(p, k, "AllMulticast");
                        if (r < 0) {
                                printf("Failed to set link allmulticast '%s': %s\n", p->ifname, g_strerror(-r));
                                return r;
                        }

                        continue;
                }
                if (string_equal(argv[i], "pcs")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse link promiscuous '%s' '%s': %s", p->ifname, argv[i], g_strerror(-r));
                                return r;
                        }

                        k = r;
                        r = manager_set_link_flag(p, k, "Promiscuous");
                        if (r < 0) {
                                printf("Failed to set link promiscuous '%s': %s\n", p->ifname, g_strerror(-r));
                                return r;
                        }

                        continue;
                }
                if (string_equal(argv[i], "rfo")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse link RequiredForOnline '%s' '%s': %s", p->ifname, argv[i], g_strerror(-r));
                                return r;
                        }

                        k = r;
                        r = manager_set_link_flag(p, k, "RequiredForOnline");
                        if (r < 0) {
                                printf("Failed to set link RequiredForOnline '%s': %s\n", p->ifname, g_strerror(-r));
                                return r;
                        }

                        continue;
                }
        }

        return 0;
}

_public_ int ncm_link_set_group(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t group;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        r = parse_group(argv[2], &group);
        if (r < 0) {
                log_warning("Failed to parse link group '%s': %s", argv[2], g_strerror(-r));
                return r;
        }

        r = manager_set_link_group(p, group);
        if (r < 0) {
                log_warning("Failed to update Group for '%s': %s", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_rf_online(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        r = parse_link_rf_online(argv[2]);
        if (r < 0) {
               log_warning("Failed to parse RequiredFamilyForOnline '%s': %s", argv[2], g_strerror(EINVAL));
               return r;
        }

        r = manager_set_link_rf_online(p, argv[2]);
        if (r < 0) {
                log_warning("Failed to update RequiredFamilyForOnline for '%s': %s", p->ifname, g_strerror(-r) );
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_act_policy(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        r = parse_link_act_policy(argv[2]);
        if (r < 0) {
               log_warning("Failed to parse ActivationPolicy '%s': %s", argv[2], g_strerror(EINVAL));
               return r;
        }

        r = manager_set_link_act_policy(p, argv[2]);
        if (r < 0) {
                log_warning("Failed to update ActivationPolicy for '%s': %s", p->ifname, g_strerror(-r) );
                return r;
        }

        return 0;
}


_public_ int ncm_link_set_network_ipv6_mtu(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t mtu;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        r = parse_mtu(argv[2], &mtu);
        if (r < 0)
                return r;

        if (mtu < 1280) {
                log_warning("MTU must be greater than or equal to 1280 bytes. Failed to update MTU for '%s': %s", p->ifname, g_strerror(EINVAL));
                return r;
        }

        r = manager_link_set_network_ipv6_mtu(p, mtu);
        if (r < 0) {
                log_warning("Failed to update MTU for '%s': %s", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_dhcp_mode(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int mode, r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        mode = dhcp_client_name_to_mode(argv[2]);
        if (mode < 0) {
                log_warning("Failed to find DHCP mode : %s", argv[2]);
                return r;
        }

        r = manager_set_link_dhcp_client(p, mode);
        if (r < 0) {
                log_warning("Failed to set link mode '%s': %s\n", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_get_dhcp_mode(const char *ifname, int *ret) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int mode, r;

        assert(ifname);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return -errno;

        r = manager_get_link_dhcp_client(p, &mode);
        if (r < 0)
                return r;

        *ret = mode;
        return 0;
}

_public_ int ncm_link_set_dhcp4_client_identifier(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        DHCPClientIdentifier d;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        d = dhcp_client_identifier_to_mode(argv[2]);
        if (d == _DHCP_CLIENT_IDENTIFIER_INVALID) {
                log_warning("Failed to parse DHCP4 client identifier: %s", argv[2]);
                return -EINVAL;
        }

        r = manager_set_link_dhcp4_client_identifier(p, d);
        if (r < 0) {
                log_warning("Failed to set link DHCP4 client identifier '%s': %s\n", p->ifname, g_strerror(r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_get_dhcp4_client_identifier(const char *ifname, char **ret) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        DHCPClientIdentifier d;
        int r;

        assert(ifname);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return -errno;

        r = manager_get_link_dhcp4_client_identifier(p, &d);
        if (r < 0)
                return r;

        *ret = strdup(dhcp_client_identifier_to_name(d));
        if (!*ret)
                return -ENOMEM;

        return 0;
}

_public_ int ncm_link_set_dhcp_client_iaid(int argc, char *argv[]) {
        DHCPClient kind = _DHCP_CLIENT_INVALID;
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t v;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "family") || string_equal_fold(argv[i], "f")) {
                        parse_next_arg(argv, argc, i);

                        r  = dhcp_name_to_client(argv[i]);
                        if (r < 0) {

                                log_warning("Failed to determine DHCP client type '%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }
                        kind = r;

                        continue;
                }

                if (string_equal_fold(argv[i], "iaid")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v);
                        if (r < 0) {
                                log_warning("Failed to parse IAID '%s' for link '%s': %s", argv[2], argv[1], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(EINVAL));
                return -EINVAL;
        }

        if (kind == _DHCP_CLIENT_INVALID) {
                log_warning("Missing DHCP client family: %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_link_dhcp_client_iaid(p, kind, v);
        if (r < 0) {
                log_warning("Failed to set link DHCP4 client IAID for'%s': %s\n", p->ifname, g_strerror(r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_get_dhcp_client_iaid(char *ifname, uint32_t *ret) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t v;
        int r;

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return -errno;

        r = manager_get_link_dhcp_client_iaid(p, DHCP_CLIENT_IPV4, &v);
        if (r < 0)
                return r;

        *ret = v;
        return 0;
}

_public_ int ncm_link_set_dhcp_client_duid(int argc, char *argv[]) {
        DHCPClient kind = _DHCP_CLIENT_INVALID;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *raw_data = NULL;
        DHCPClientDUIDType d;
        bool system = false;
        int r;

        /* Try to resolve the link name. If not assume this is for the system, i.e. /etc/systemd/networkd.conf */
        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                if (string_equal_fold(argv[1], "system") || string_equal_fold(argv[1], "s"))
                        system = true;
                else {
                        log_warning("Failed to resolve link '%s': %s", argv[1], g_strerror(EINVAL));
                        return -EINVAL;
                }
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "family") || string_equal_fold(argv[i], "f")) {
                        parse_next_arg(argv, argc, i);

                        r  = dhcp_name_to_client(argv[i]);
                        if (r < 0) {

                                log_warning("Failed to determine DHCP client type '%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }
                        kind = r;

                        continue;
                }

                if (string_equal_fold(argv[i], "duid")) {
                        parse_next_arg(argv, argc, i);

                        d = dhcp_client_duid_name_to_type(argv[i]);
                        if (d == _DHCP_CLIENT_DUID_TYPE_INVALID) {
                                log_warning("Failed to parse DHCPv4 DUID type '%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        continue;
                }

                if (string_equal_fold(argv[i], "data") || string_equal_fold(argv[i], "rawdata")) {
                        parse_next_arg(argv, argc, i);

                        raw_data = strdup(argv[i]);
                        if (!raw_data)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_link_dhcp_client_duid(p, d, raw_data, system, kind);
        if (r < 0) {
                log_warning("Failed to set link DHCP client DUID for '%s': %s\n", p->ifname, g_strerror(r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_network_section_bool(int argc, char *argv[]) {
        _cleanup_(config_manager_unrefp) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool v;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_network_section_bool_configs_new(&m);
        if (r < 0) {
                log_warning("Failed to set network section '%s'", g_strerror(-r));
                return r;
        }

        r = parse_boolean(argv[2]);
        if (r < 0) {
                log_warning("Failed to parse %s=%s for link '%s': %s", argv[0], argv[2], argv[1], g_strerror(-r));
                return r;
        }

        v = r;
        return manager_set_network_section_bool(p, ctl_to_config(m, argv[0]), v);
}

_public_ int ncm_link_set_dhcp4_section(int argc, char *argv[]) {
        _cleanup_(config_manager_unrefp) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool v;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_network_dhcp4_section_configs_new(&m);
        if (r < 0) {
                log_warning("Failed to set dhcp4 section for link '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        for (int i = 2; i < argc; i++) {
                if (ctl_to_config(m, argv[i])) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse %s=%s for link '%s': %s", argv[i-1], argv[i], argv[1], g_strerror(-r));
                                return r;
                        }
                        v = r;

                        r = manager_set_dhcp_section(DHCP_CLIENT_IPV4, p, ctl_to_config(m, argv[i-1]), v);
                        if (r < 0) {
                                log_warning("Failed to dhcp4 section %s=%s for link '%s': %s", argv[i-1], argv[i], argv[1], g_strerror(-r));
                                return r;
                        }
                } else {
                        log_warning("Failed to parse %s=%s for link '%s': %s", argv[i-1], argv[i], argv[1], g_strerror(-r));
                        return r;
                }
        }

        return 0;
}

_public_ int ncm_link_set_dhcp6_section(int argc, char *argv[]) {
        _cleanup_(config_manager_unrefp) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool v;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_network_dhcp6_section_configs_new(&m);
        if (r < 0) {
                log_warning("Failed to set dhcp4 section for link '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        for (int i = 2; i < argc; i++) {
                if (ctl_to_config(m, argv[i])) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse %s=%s for link '%s': %s", argv[i-1], argv[i], argv[1], g_strerror(-r));
                                return r;
                        }
                        v = r;

                        r = manager_set_dhcp_section(DHCP_CLIENT_IPV6, p, ctl_to_config(m, argv[i-1]), v);
                        if (r < 0) {
                                log_warning("Failed to dhcp4 section %s=%s for link '%s': %s", argv[i-1], argv[i], argv[1], g_strerror(-r));
                                return r;
                        }
                } else {
                        log_warning("Failed to parse %s=%s for link '%s': %s", argv[i-1], argv[i], argv[1], g_strerror(-r));
                        return r;
                }
        }


        return 0;
}

_public_ int ncm_link_update_state(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        LinkState state;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        state = link_name_to_state(argv[2]);
        if (state < 0) {
                log_warning("Failed to find link state '%s': %s", argv[2], g_strerror(EINVAL));
                return r;
        }

        r = manager_set_link_state(p, state);
        if (r < 0) {
                log_warning("Failed to set link state '%s': %s\n", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_add_address(int argc, char *argv[]) {
        IPDuplicateAddressDetection dad = _IP_DUPLICATE_ADDRESS_DETECTION_INVALID;
        _auto_cleanup_ char *scope = NULL, *pref_lft = NULL, *label = NULL;
        _auto_cleanup_ IPAddress *address = NULL, *peer = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r, prefix_route = -1;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "address")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &address);
                        if (r < 0) {
                                log_warning("Failed to parse address '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "peer")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &peer);
                        if (r < 0) {
                                log_warning("Failed to parse peer address '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "label")) {
                        parse_next_arg(argv, argc, i);

                        label = strdup(argv[i]);
                        if (!label)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "pref-lifetime")) {
                        uint32_t lft;

                        parse_next_arg(argv, argc, i);

                        if (!string_equal(argv[i], "forever") && !string_equal(argv[i], "infinity")) {
                                r = parse_uint32(argv[i], &lft);
                                if (r < 0) {
                                        log_warning("Failed to parse pref-lifetime '%s': %s", argv[i], g_strerror(-r));
                                        return r;
                                }
                        }

                        pref_lft = strdup(argv[i]);
                        if (!pref_lft)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "scope")) {
                        parse_next_arg(argv, argc, i);

                        if (!string_equal(argv[i], "global") && !string_equal(argv[i], "link") && !string_equal(argv[i], "host")) {
                                uint32_t k;

                                r = parse_uint32(argv[i], &k);
                                if (r < 0) {
                                        log_warning("Failed to parse scope '%s': %s", argv[i], g_strerror(-r));
                                        return r;
                                }

                                if (k > 255) {
                                        log_warning("Scope '%s' is out of range [0-255]: %s", argv[i], g_strerror(EINVAL));
                                        return r;
                                }
                        }

                        scope = strdup(argv[i]);
                        if (!scope)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "dad")) {
                        parse_next_arg(argv, argc, i);

                        r = ip_duplicate_address_detection_type_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse dad '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        dad = r;
                        continue;
                }

                if (string_equal(argv[i], "prefix-route")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse prefix-route '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        prefix_route = r;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = manager_configure_link_address(p, address, peer, scope, pref_lft, dad, prefix_route, label);
        if (r < 0) {
                log_warning("Failed to configure link address: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_delete_address(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *address = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *a = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "address")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &address);
                        if (r < 0) {
                                log_warning("Failed to parse address '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        a = strdup(argv[i]);
                        if (!a)
                                return log_oom();
                        break;
                }
        }

        r = manager_delete_link_address(p, a);
        if (r < 0) {
                log_warning("Failed to remove link address '%s': %s\n", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_get_addresses(const char *ifname, char ***ret) {
        _cleanup_(addresses_unrefp) Addresses *addr = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        assert(ifname);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return -errno;

        r = manager_get_one_link_address(p->ifindex, &addr);
        if (r < 0)
                return r;

        if (!set_size(addr->addresses))
                return -ENODATA;

        g_hash_table_iter_init(&iter, addr->addresses->hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                Address *a = (Address *) g_bytes_get_data(key, &size);
                _auto_cleanup_ char *c = NULL;

                r = ip_to_string_prefix(a->family, &a->address, &c);
                if (r < 0)
                        return r;

                if (!s) {
                        s = strv_new(c);
                        if (!s)
                                return log_oom();
                } else {
                        r = strv_add(&s, c);
                        if (r < 0)
                                return log_oom();
                }

                steal_pointer(c);
        }

        *ret = steal_pointer(s);
        return 0;
}

_public_ int ncm_display_one_link_addresses(int argc, char *argv[]) {
        _cleanup_(addresses_unrefp) Addresses *addr = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        bool ipv4 = false, ipv6 = false;
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        if (argc >= 2) {
                for (int i = 2; i < argc; i++) {
                        if (string_equal(argv[i], "family") || string_equal(argv[i], "f")) {
                                parse_next_arg(argv, argc, i);

                                if (string_equal(argv[i], "ipv4") || string_equal(argv[i], "4"))
                                        ipv4 = true;
                                else if (string_equal(argv[i], "ipv6") || string_equal(argv[i], "6"))
                                        ipv6 = true;
                        }
                }
        }

        r = manager_get_one_link_address(p->ifindex, &addr);
        if (r < 0)
                return r;

        if (!set_size(addr->addresses))
                return -ENODATA;

        printf("Addresses: ");
        g_hash_table_iter_init(&iter, addr->addresses->hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                Address *a = (Address *) g_bytes_get_data(key, &size);
                _auto_cleanup_ char *c = NULL;

                r = ip_to_string_prefix(a->family, &a->address, &c);
                if (r < 0)
                        return r;

                if ((a->family == AF_INET && ipv4 ) || (a->family == AF_INET6 && ipv6))
                        printf("%s ", c);

                if (!ipv4 && !ipv6)
                        printf("%s ", c);
        }

        printf("\n");

        return 0;
}

_public_ int ncm_link_add_default_gateway(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ IPAddress *gw = NULL;
        _auto_cleanup_ Route *rt = NULL;
        int r, onlink = -1;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "gateway") || string_equal(argv[i], "gw")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &gw);
                        if (r < 0) {
                                log_warning("Failed to parse gateway address '%s': %s", argv[2], g_strerror(-r));
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "onlink")) {
                        parse_next_arg(argv, argc, i);

                        onlink = parse_boolean(argv[i]);
                        if (onlink < 0) {
                                log_warning("Failed to parse onlink '%s': %s\n", argv[1], g_strerror(EINVAL));
                                return -EINVAL;
                        }
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = route_new(&rt);
        if (r < 0)
                return log_oom();

        *rt = (Route) {
                  .onlink = onlink,
                  .ifindex = p->ifindex,
                  .family = gw->family,
                  .gw = *gw,
        };

        r = manager_configure_default_gateway(p, rt);
        if (r < 0) {
                log_warning("Failed to configure link default gateway on link '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_add_route(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *gw = NULL, *dst = NULL, *source = NULL, *pref_source = NULL;
        IPv6RoutePreference rt_pref = _IPV6_ROUTE_PREFERENCE_INVALID;
        RouteProtocol protocol = _ROUTE_PROTOCOL_INVALID;
        RouteScope scope = _ROUTE_SCOPE_INVALID;
        RouteTable table = _ROUTE_TABLE_INVALID;
        RouteType type = _ROUTE_TYPE_INVALID;
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t metric = 0, mtu = 0;
        int onlink = -1, r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "gateway") || string_equal(argv[i], "gw")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &gw);
                        if (r < 0) {
                                log_warning("Failed to parse route gateway address '%s': %s", argv[2], g_strerror(-r));
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "destination") || string_equal(argv[i], "dest")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &dst);
                        if (r < 0) {
                                log_warning("Failed to parse route destination address '%s': %s", argv[2], g_strerror(-r));
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "source") || string_equal(argv[i], "src")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &source);
                        if (r < 0) {
                                log_warning("Failed to parse route source address '%s': %s", argv[2], g_strerror(-r));
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "pref-source") || string_equal(argv[i], "pfsrc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &pref_source);
                        if (r < 0) {
                                log_warning("Failed to parse route preferred source address '%s': %s", argv[2], g_strerror(-r));
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "metric") || string_equal(argv[i], "mt")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &metric);
                        if (r < 0) {
                                log_warning("Failed to parse route metric '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "ipv6-preference") || string_equal(argv[i], "ipv6-pref")) {
                        parse_next_arg(argv, argc, i);

                        r = ipv6_route_preference_type_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse route IPv6 preference '%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        rt_pref = r;
                        continue;
                }

                if (string_equal(argv[i], "protocol") || string_equal(argv[i], "proto")) {
                        parse_next_arg(argv, argc, i);

                        protocol = route_protocol_to_mode(argv[i]);
                        if (r < 0) {
                                r = parse_integer(argv[i], &protocol);
                                if (r < 0) {
                                        log_warning("Failed to parse route protocol '%s': %s", argv[i], g_strerror(-r));
                                        return r;
                                }

                                if (protocol == 0 || protocol > 255) {
                                        log_warning("Route protocol is out of rance [1-255] '%s': %s", argv[i], g_strerror(EINVAL));
                                        return -EINVAL;
                                }
                        }
                        continue;
                }

                if (string_equal(argv[i], "type")) {
                        parse_next_arg(argv, argc, i);

                        r = route_type_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse route type '%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        type = r;
                        continue;
                }

                if (string_equal(argv[i], "scope")) {
                        parse_next_arg(argv, argc, i);

                        r = route_scope_type_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse route scope '%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        scope = r;
                        continue;
                }

                if (string_equal(argv[i], "table")) {
                        parse_next_arg(argv, argc, i);

                        table = route_table_to_mode(argv[i]);
                        if (table < 0) {
                                r = parse_integer(argv[i], &table);
                                if (r < 0) {
                                        log_warning("Failed to parse route table '%s': %s", argv[i], g_strerror(-r));
                                        return r;
                                }
                        }

                        continue;
                }

                if (string_equal(argv[i], "mtu")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_mtu(argv[i], &mtu);
                        if (r < 0) {
                                log_warning("Failed to parse route mtu '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "onlink")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse route onlink '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        onlink = r;

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = manager_configure_route(p, gw, dst, source , pref_source, rt_pref, protocol, scope, type, table, mtu, metric, onlink);
        if (r < 0) {
                log_warning("Failed to configure route on link '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_get_routes(char *ifname, char ***ret) {
        _cleanup_(routes_unrefp) Routes *route = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        assert(ifname);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return -errno;

        r = manager_get_one_link_route(p->ifindex, &route);
        if (r < 0)
                return r;

        if (set_size(route->routes) <= 0)
                return -ENODATA;

        while (g_hash_table_iter_next (&iter, &key, &value)) {
                Route *a = (Route *) g_bytes_get_data(key, &size);
                _auto_cleanup_ char *c = NULL;

                ip_to_string(a->family, &a->address, &c);
                if (r < 0)
                        return r;

                if (!s) {
                        s = strv_new(c);
                        if (!s)
                                return log_oom();
                } else {
                        r = strv_add(&s, c);
                        if (r < 0)
                                return log_oom();
                }

                steal_pointer(c);
        }

        *ret = steal_pointer(s);
        return 0;
}

_public_ int ncm_link_delete_gateway_or_route(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        if (string_equal(argv[0], "delete-gateway"))
                r = manager_remove_gateway_or_route(p, true);
        else
                r = manager_remove_gateway_or_route(p, false);

        if (r < 0) {
                log_warning("Failed to delete %s on '%s': %s\n", argv[0], p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_add_additional_gw(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *a = NULL, *gw = NULL, *destination = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ Route *rt = NULL;
        uint32_t table;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "address") || string_equal(argv[i], "addr")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &a);
                        if (r < 0) {
                                log_warning("Failed to parse address '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "destination") || string_equal(argv[i], "dest")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &destination);
                        if (r < 0) {
                                log_warning("Failed to parse destination '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "gw")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &gw);
                        if (r < 0) {
                                log_warning("Failed to parse gateway '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "table")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &table);
                        if (r < 0) {
                                log_warning("Failed to parse table '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }


        r = route_new(&rt);
        if (r < 0)
                return log_oom();

        *rt = (Route) {
                .family = a->family,
                .ifindex = p->ifindex,
                .table = table,
                .dst_prefixlen = destination->prefix_len,
                .destination = *destination,
                .address = *a,
                .gw = *gw,
        };

        r = manager_configure_additional_gw(p, rt);
        if (r < 0) {
                log_warning("Failed to add route to link '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_add_routing_policy_rules(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL, *oif = NULL, *iif = NULL;
        _auto_cleanup_ IPAddress *to = NULL, *from = NULL;
        _auto_cleanup_ char *tos = NULL;
        uint32_t table = 0, priority = 0;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "iif")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &iif);
                        if (r < 0) {
                                log_warning("Failed to find link '%s': %s", argv[i], g_strerror(-r));
                                return -errno;
                        }

                        continue;
                }

                if (string_equal(argv[i], "oif")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &oif);
                        if (r < 0) {
                                log_warning("Failed to find link '%s': %s", argv[i], g_strerror(-r));
                                return -errno;
                        }

                        continue;
                }

                if (string_equal(argv[i], "from")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &from);
                        if (r < 0) {
                                log_warning("Failed to parse from address '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "to")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &to);
                        if (r < 0) {
                                log_warning("Failed to parse ntp address '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "table")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &table);
                        if (r < 0) {
                                log_warning("Failed to parse table '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "prio")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &priority);
                        if (r < 0) {
                                log_warning("Failed to parse priority '%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        continue;
                }

                if (string_equal(argv[i], "tos")) {
                        uint32_t k;

                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &k);
                        if (r < 0) {
                                log_warning("Failed to parse tos '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        if (k == 0 || k > 255) {
                                log_warning("TOS is out of range '%s': %s", g_strerror(EINVAL), argv[i]);
                                return -EINVAL;
                        }

                        tos = strdup(argv[i]);
                        if (!tos)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = manager_configure_routing_policy_rules(p, iif, oif, to, from, table, priority, tos);
        if (r < 0) {
                log_warning("Failed to configure routing policy rules on link '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_remove_routing_policy_rules(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_remove_routing_policy_rules(p);
        if (r < 0) {
                log_warning("Failed to remove routing policy rules on link '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_add_dhcpv4_server(int argc, char *argv[]) {
        uint32_t pool_offset = 0, pool_size = 0, max_lease_time = 0, default_lease_time = 0;
        int emit_dns = -1, emit_ntp = -1, emit_router = -1;
        _auto_cleanup_ IPAddress *dns = NULL, *ntp = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "dns")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &dns);
                        if (r < 0) {
                                log_warning("Failed to parse dns address '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "ntp")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &ntp);
                        if (r < 0) {
                                log_warning("Failed to parse ntp address '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "pool-offset")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &pool_offset);
                        if (r < 0) {
                                log_warning("Failed to parse pool offset '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "pool-size")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &pool_size);
                        if (r < 0) {
                                log_warning("Failed to parse pool size '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "default-lease-time")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &default_lease_time);
                        if (r < 0) {
                                log_warning("Failed to parse default lease time '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "max-lease-time")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &max_lease_time);
                        if (r < 0) {
                                log_warning("Failed to parse maximum lease time '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "emit-dns")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse emit dns '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        emit_dns = r;
                        continue;
                }

                if (string_equal(argv[i], "emit-ntp")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse emit ntp '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        emit_ntp = r;
                        continue;
                }

                if (string_equal(argv[i], "emit-router")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse emit router '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        emit_router = r;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = manager_configure_dhcpv4_server(p, dns, ntp, pool_offset, pool_size, default_lease_time, max_lease_time,
                                            emit_dns, emit_ntp, emit_router);
        if (r < 0) {
                log_warning("Failed to configure DHCPv4 server on link '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_remove_dhcpv4_server(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_remove_dhcpv4_server(p);
        if (r < 0) {
                log_warning("Failed to remove DHCPv4 server on link '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_add_ipv6_router_advertisement(int argc, char *argv[]) {
        uint32_t pref_lifetime = 0, valid_lifetime = 0, route_lifetime = 0, dns_lifetime = 0;
        _auto_cleanup_ IPAddress *prefix = NULL, *dns = NULL, *route_prefix = NULL;
        int emit_dns = -1, emit_domain = -1, assign = -1, managed = -1, other = -1;
        IPv6RAPreference preference = _IPV6_RA_PREFERENCE_INVALID;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *domain = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "prefix")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &prefix);
                        if (r < 0) {
                                log_warning("Failed to parse prefix address '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "route-prefix")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &route_prefix);
                        if (r < 0) {
                                log_warning("Failed to parse route prefix address '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "dns")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &dns);
                        if (r < 0) {
                                log_warning("Failed to parse dns address '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "domain")) {
                        parse_next_arg(argv, argc, i);

                        if (!valid_hostname(argv[i])) {
                                log_warning("Failed to parse domain '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        domain = strdup(argv[i]);
                        if (!domain)
                                log_oom();

                        continue;
                }

                if (string_equal(argv[i], "pref-lifetime")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &pref_lifetime);
                        if (r < 0) {
                                log_warning("Failed to parse pref-lifetime '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "valid-lifetime")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &valid_lifetime);
                        if (r < 0) {
                                log_warning("Failed to parse valid-lifetime '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "route-lifetime")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &route_lifetime);
                        if (r < 0) {
                                log_warning("Failed to parse default route-lifetime '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "dns-lifetime")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &dns_lifetime);
                        if (r < 0) {
                                log_warning("Failed to parse default dns-lifetime '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (string_equal(argv[i], "assign")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse assign '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        assign = r;
                        continue;
                }

                if (string_equal(argv[i], "managed")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse managed '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        managed = r;
                        continue;
                }

                if (string_equal(argv[i], "other")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse other '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        other = r;
                        continue;
                }

                if (string_equal(argv[i], "emit-dns")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse emit-dns '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        emit_dns = r;
                        continue;
                }

                if (string_equal(argv[i], "emit-domain")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse emit-domain '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        emit_domain = r;
                        continue;
                }

                if (string_equal(argv[i], "router-pref")) {
                        parse_next_arg(argv, argc, i);

                        r = ipv6_ra_preference_type_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse router preference '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        preference = r;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = manager_configure_ipv6_router_advertisement(p, prefix, route_prefix, dns, domain, pref_lifetime, valid_lifetime,
                                                        dns_lifetime, route_lifetime, preference, managed, other, emit_dns, emit_domain, assign);
        if (r < 0) {
                log_warning("Failed to configure IPv6 RA on link '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_remove_ipv6_router_advertisement(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_remove_ipv6_router_advertisement(p);
        if (r < 0) {
                log_warning("Failed to remove IPv6 router advertisement on link '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_show_dns_server(int argc, char *argv[]) {
        _cleanup_(dns_servers_freep) DNSServers *fallback = NULL, *dns = NULL, *current = NULL;
        char buf[IF_NAMESIZE + 1] = {};
        GSequenceIter *i;
        DNSServer *d;
        int r;

        if (json_enabled())
                return json_show_dns_server();

        r = dbus_acquire_dns_servers_from_resolved("DNS", &dns);
        if (r >= 0 && dns && !g_sequence_is_empty(dns->dns_servers)) {
                display(beautify_enabled() ? true : false, ansi_color_bold_cyan(), "             DNS: ");

                for (i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *pretty = NULL;

                        d = g_sequence_get(i);
                        if (!d->ifindex)
                                continue;

                        r = ip_to_string(d->address.family, &d->address, &pretty);
                        if (r >= 0)
                                printf("%s ", string_strip(pretty));
                }
                printf("\n");
        }

        r = dbus_get_current_dns_servers_from_resolved(&current);
        if (r >= 0 && current && !g_sequence_is_empty(current->dns_servers)) {
                _auto_cleanup_ char *pretty = NULL;

                i = g_sequence_get_begin_iter(current->dns_servers);
                d = g_sequence_get(i);
                r = ip_to_string(d->address.family, &d->address, &pretty);
                if (r >= 0) {
                        display(beautify_enabled(), ansi_color_bold_cyan(), "CurrentDNSServer:");
                        printf(" %s\n", pretty);
                }
        }

        r = dbus_acquire_dns_servers_from_resolved("FallbackDNS", &fallback);
        if (r >= 0 && !g_sequence_is_empty(fallback->dns_servers)) {

                display(beautify_enabled(), ansi_color_bold_cyan(), "     FallbackDNS: ");
                for (i = g_sequence_get_begin_iter(fallback->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *pretty = NULL;

                        d = g_sequence_get(i);

                        r = ip_to_string(d->address.family, &d->address, &pretty);
                        if (r >= 0)
                                printf("%s ", pretty);

                }
                printf("\n\n");
        }

        if (dns && !g_sequence_is_empty(dns->dns_servers)) {
                if (beautify_enabled())
                        printf("%5s %-20s %-14s\n", "INDEX", "LINK", "DNS");

                for (i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *pretty = NULL;

                        d = g_sequence_get(i);

                        if (!d->ifindex)
                                continue;

                        if_indextoname(d->ifindex, buf);
                        r = ip_to_string(d->address.family, &d->address, &pretty);
                        if (r >= 0)
                                printf("%5d %-16s %s\n", d->ifindex, buf, pretty);
                }
        }

        return 0;
}

_public_ int ncm_get_dns_server(char ***ret) {
        _cleanup_(dns_servers_freep) DNSServers *dns = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        int r;

        assert(ret);

        r = dbus_acquire_dns_servers_from_resolved("DNS", &dns);
        if (r < 0)
                return r;

        for (GSequenceIter *i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                _auto_cleanup_ char *k = NULL;
                DNSServer *d;

                d = g_sequence_get(i);
                if (!d->ifindex)
                        continue;

                r = ip_to_string(d->address.family, &d->address, &k);
                if (r >= 0) {
                        if (!s) {
                                s = strv_new(k);
                                if (!s)
                                        return -ENOMEM;
                        } else {
                                r = strv_add(&s, k);
                                if (r < 0)
                                        return r;
                        }
                }

                steal_pointer(k);
        }

        *ret = steal_pointer(s);
        return 0;
}

_public_ int ncm_add_dns_server(int argc, char *argv[]) {
        _cleanup_(dns_servers_freep) DNSServers *dns = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool system = false, global = false;
        int r;

        if (string_equal(argv[1], "system"))
                system = true;
        else if (string_equal(argv[1], "global"))
                global = true;
        else {
                r = parse_ifname_or_index(argv[1], &p);
                if (r < 0) {
                        log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                        return -EINVAL;
                }
        }

        for (int i = 2; i < argc; i++) {
                _auto_cleanup_ IPAddress *a = NULL;
                _auto_cleanup_ DNSServer *s = NULL;

                r = parse_ip(argv[i], &a);
                if (r < 0) {
                        log_warning("Failed to parse DNS server address: %s", argv[i]);
                        return r;
                }

                r = dns_server_new(&s);
                if (r < 0)
                        return log_oom();

                *s = (DNSServer) {
                        .ifindex = p ? p->ifindex : 0,
                        .address = *a,
                };

                r = dns_server_add(&dns, s);
                if (r < 0) {
                        log_warning("Failed to add DNS server address: %s", argv[i]);
                        return r;
                }

                steal_pointer(s);
        }

        r = manager_add_dns_server(p, dns, system, global);
        if (r < 0) {
                log_warning("Failed to add DNS server %s: %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_add_dns_domains(int argc, char *argv[]) {
       _auto_cleanup_strv_ char **domains = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool system = false, global = false;
        int r;

        if (string_equal(argv[1], "system"))
                system = true;
        else if (string_equal(argv[1], "global"))
                global = true;
        else {
                r = parse_ifname_or_index(argv[1], &p);
                if (r < 0) {
                        log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                        return -errno;
                }
        }

        r = argv_to_strv(argc - 2, argv + 2, &domains);
        if (r < 0) {
                log_warning("Failed to parse domains addresses: %s", g_strerror(-r));
                return r;
        }

        r = manager_add_dns_server_domain(p, domains, system, global);
        if (r < 0) {
                log_warning("Failed to add DNS domain to resolved '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_show_dns_server_domains(int argc, char *argv[]) {
        _cleanup_(dns_domains_freep) DNSDomains *domains = NULL;
        _auto_cleanup_ char *config_domain = NULL, *setup = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        char buffer[LINE_MAX] = {};
        GSequenceIter *i;
        DNSDomain *d;
        int r;

        if (json_enabled())
                return json_show_dns_server_domains();

        if (argc > 1 && string_equal(argv[1], "system")) {
                r = parse_ifname_or_index(argv[1], &p);
                if (r < 0) {
                        log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                        return -errno;
                }

                r = network_parse_link_setup_state(p->ifindex, &setup);
                if (r < 0) {
                        log_warning("Failed to get link setup '%s': %s\n", p->ifname, g_strerror(-r));
                        return r;
                }

                if (string_equal(setup, "unmanaged")) {
                       _auto_cleanup_strv_ char **a = NULL, **b = NULL;
                        char **j;

                        r = dns_read_resolv_conf(&a, &b);
                        if (r < 0) {
                                log_warning("Failed to read resolv.conf: %s", g_strerror(-r));
                                return r;

                        }

                        printf("Domains:");
                        strv_foreach(j, b) {
                                printf("%s ", *j);
                        }

                        printf("\n");
                        return 0;
                }
        }

        if (argc >= 2 && string_equal(argv[1], "system")) {
                r = manager_read_domains_from_system_config(&config_domain);
                if (r < 0) {
                        log_warning("Failed to read DNS domain from '/etc/systemd/resolved.conf': %s", g_strerror(-r));
                        return r;
                }

                printf("%s\n", config_domain);

                return 0;
        }

        r = dbus_acquire_dns_domains_from_resolved(&domains);
        if (r < 0){
                log_warning("Failed to fetch DNS domain from resolved: %s", g_strerror(-r));
                return r;
        }

        if (!domains || g_sequence_is_empty(domains->dns_domains)) {
                log_warning("No DNS Domain configured: %s", g_strerror(ENODATA));
                return -ENODATA;
        } else if (g_sequence_get_length(domains->dns_domains) == 1) {

                i = g_sequence_get_begin_iter(domains->dns_domains);
                d = g_sequence_get(i);

                display(beautify_enabled(), ansi_color_bold_cyan(), "DNS Domain: ");
                printf("%s\n", d->domain);
        } else {
                _cleanup_(set_unrefp) Set *all_domains = NULL;

                r = set_new(&all_domains, NULL, NULL);
                if (r < 0) {
                        log_debug("Failed to init set for domains: %s", g_strerror(-r));
                        return r;
                }

                display(beautify_enabled(), ansi_color_bold_cyan(), "DNS Domain: ");
                for (i = g_sequence_get_begin_iter(domains->dns_domains); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i))  {
                        char *s;

                        d = g_sequence_get(i);

                        if (*d->domain == '.')
                                continue;

                        if (set_contains(all_domains, d->domain))
                                continue;

                        s = g_strdup(d->domain);
                        if (!s)
                                log_oom();

                        if (!set_add(all_domains, s)) {
                                log_debug("Failed to add domain to set '%s': %s", d->domain, g_strerror(-r));
                                return -EINVAL;
                        }

                        printf("%s ", d->domain);
                }

                if (beautify_enabled() && g_sequence_get_length(domains->dns_domains) > 0)
                        printf("\n%5s %-20s %-18s\n", "INDEX", "LINK", "Domain");

                for (i = g_sequence_get_begin_iter(domains->dns_domains); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        d = g_sequence_get(i);

                        sprintf(buffer, "%" PRIu32, d->ifindex);

                        if (!d->ifindex)
                                continue;

                        r = parse_ifname_or_index(buffer, &p);
                        if (r < 0) {
                                log_warning("Failed to find link '%d': %s", d->ifindex, g_strerror(-r));
                                return -errno;
                        }
                        printf("%5d %-20s %-18s\n", d->ifindex, p->ifname, *d->domain == '.' ? "~." : d->domain);
                }
        }

        return 0;
}

_public_ int ncm_get_dns_domains(char ***ret) {
        _cleanup_(dns_domains_freep) DNSDomains *domains = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        int r;

        assert(ret);

        r = dbus_acquire_dns_domains_from_resolved(&domains);
        if (r < 0)
                return r;

        if (!domains || g_sequence_is_empty(domains->dns_domains))
                return -ENODATA;
        else
                for (GSequenceIter *i = g_sequence_get_begin_iter(domains->dns_domains); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *k = NULL;
                        DNSDomain *d;

                        d = g_sequence_get(i);

                        k = strdup(d->domain);
                        if (!k)
                                return -ENOMEM;

                        if (!s) {
                                s = strv_new(k);
                                if (!s)
                                        return -ENOMEM;
                        } else {
                                r = strv_add(&s, k);
                                if (r < 0)
                                        return r;
                        }

                        steal_pointer(k);
                }

        *ret = steal_pointer(s);
        return 0;
}

_public_ int ncm_revert_resolve_link(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_revert_dns_server_and_domain(p);
        if (r < 0) {
                log_warning("Failed to flush resolved settings for %s: %s", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_set_system_hostname(int argc, char *argv[]) {
        int r;

        if (isempty_string(argv[1])) {
                log_warning("Invalid hostname. Ignoring");
                return -EINVAL;
        }

        r = dbus_set_hostname(argv[1]);
        if (r < 0) {
                log_warning("Failed to set hostname '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_get_system_hostname(char **ret) {
        char *hostname;
        int r;

        assert(ret);

        r = dbus_get_property_from_hostnamed("StaticHostname", &hostname);
        if (r < 0)
                return r;

        *ret = hostname;
        return 0;
}

_public_ int ncm_link_add_ntp(int argc, char *argv[]) {
       _auto_cleanup_strv_ char **ntps = NULL;
       _auto_cleanup_ IfNameIndex *p = NULL;
       char **d;
       int r;

       r = parse_ifname_or_index(argv[1], &p);
       if (r < 0) {
               log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
               return -errno;
       }

       r = argv_to_strv(argc - 2, argv + 2, &ntps);
       if (r < 0) {
               log_warning("Failed to parse NTP addresses: %s", g_strerror(-r));
               return r;
       }

       strv_foreach(d, ntps) {
               _auto_cleanup_ IPAddress *a = NULL;

               r = parse_ip(*d, &a);
               if (r < 0) {
                       log_warning("Failed to parse NTP server address: %s", *d);
                       return r;
                }
       }

       if (string_equal(argv[0], "set-ntp"))
               r = manager_add_ntp_addresses(p, ntps, false);
       else
               r = manager_add_ntp_addresses(p, ntps, true);
       if (r < 0) {
               log_warning("Failed to add NTP addresses '%s': %s", argv[1], g_strerror(-r));
               return r;
       }

       return 0;
}

_public_ int ncm_link_delete_ntp(int argc, char *argv[]) {
       _auto_cleanup_ IfNameIndex *p = NULL;
       int r;

       r = parse_ifname_or_index(argv[1], &p);
       if (r < 0) {
               log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
               return -errno;
       }

       r = manager_remove_ntp_addresses(p);
       if (r < 0) {
               log_warning("Failed to delete NTP addresses '%s': %s", argv[1], g_strerror(-r));
               return r;
       }

       return 0;
}

_public_ int ncm_link_get_ntp(const char *ifname, char ***ret) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        char **ntp = NULL;
        int r;

        assert(ifname);
        assert(ret);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return -errno;

        r = network_parse_link_ntp(p->ifindex, &ntp);
        if (r < 0)
                return r;

        *ret = ntp;
        return 0;
}

_public_ int ncm_link_enable_ipv6(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        if (string_equal(argv[0], "enable-ipv6"))
                r = manager_enable_ipv6(p, true);
        else
                r = manager_enable_ipv6(p, false);

        if (r < 0) {
                log_warning("Failed to '%s' IPv6 for the link '%s': %s", argv[0], argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_network_reload(int argc, char *argv[]) {
        return manager_reload_network();
}

_public_ int ncm_link_reconfigure(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        return manager_reconfigure_link(p);
}

_public_ int ncm_create_bridge(int argc, char *argv[]) {
        _auto_cleanup_strv_ char **links = NULL;
        char **s;
        int r;

        r = argv_to_strv(argc - 2, argv + 2, &links);
        if (r < 0) {
                log_warning("Failed to parse links: %s", g_strerror(-r));
                return r;
        }

        strv_foreach(s, links) {
                _auto_cleanup_ IfNameIndex *p = NULL;

                r = parse_ifname_or_index(*s, &p);
                if (r < 0) {
                        log_warning("Failed to find link '%s': %s", *s, g_strerror(-r));
                        return r;
                }
        }

        r = manager_create_bridge(argv[1], links);
        if (r < 0) {
                log_warning("Failed to create bridge '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_bond(int argc, char *argv[]) {
        _auto_cleanup_strv_ char **links = NULL;
        bool have_mode = false;
        BondMode mode;
        char **s;
        int r;

        if (string_equal(argv[2], "mode")) {
                r = bond_name_to_mode(argv[3]);
                if (r < 0) {
                        log_warning("Failed to parse bond mode '%s' : %s", argv[3], g_strerror(EINVAL));
                        return r;
                }
                have_mode = true;
                mode = r;
        }

        r = argv_to_strv(argc - 4, argv + 4, &links);
        if (r < 0) {
                log_warning("Failed to parse links: %s", g_strerror(-r));
                return r;
        }

        strv_foreach(s, links) {
                _auto_cleanup_ IfNameIndex *p = NULL;

                r = parse_ifname_or_index(*s, &p);
                if (r < 0) {
                        log_warning("Failed to find link '%s': %s", *s, g_strerror(-r));
                        return r;
                }
        }

        if (!have_mode) {
                log_warning("Missing Bond mode: %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_create_bond(argv[1], mode, links);
        if (r < 0) {
                log_warning("Failed to create bond '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_macvlan(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool have_mode = false;
        MACVLanMode mode;
        int r;

        for (int i = 1; i < argc; i++) {
                if (string_equal(argv[i], "dev") || string_equal(argv[i], "device") || string_equal(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find link '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "mode")) {
                        parse_next_arg(argv, argc, i);

                        r = macvlan_name_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse MacVLan/MacVTap mode '%s' : %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }
                        have_mode = true;
                        mode = r;

                        continue;
                }

               if (i != 1) {
                       log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                       return -EINVAL;
               }
        }

        if (!have_mode) {
                log_warning("Missing MacVLan/MacVTap mode: %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        if (string_equal(argv[0], "create-macvlan"))
                r = manager_create_macvlan(argv[1], p->ifname, mode, true);
        else
                r = manager_create_macvlan(argv[1], p->ifname, mode, false);

        if (r < 0) {
                log_warning("Failed to %s '%s': %s", argv[0], argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_ipvlan(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool have_mode = false;
        IPVLanMode mode;
        int r;

        for (int i = 1; i < argc; i++) {
                if (string_equal(argv[i], "dev") || string_equal(argv[i], "device") || string_equal(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find dev '%s': %s", argv[i], g_strerror(-r));
                                return -errno;
                        }
                        continue;
                }

                if (string_equal(argv[i], "mode")) {
                        parse_next_arg(argv, argc, i);

                        r = ipvlan_name_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse IPVLan/IPVTap mode '%s' : %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }
                        have_mode = true;
                        mode = r;

                        continue;
                }

                if (i != 1) {
                        log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                        return -EINVAL;
                }
        }

        if (!have_mode) {
                log_warning("Missing IPVLan/IPVTap mode: %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        if (string_equal(argv[0], "create-ipvlan"))
                r = manager_create_ipvlan(argv[1], p->ifname, mode, true);
        else
                r = manager_create_ipvlan(argv[1], p->ifname, mode, false);

        if (r < 0) {
                log_warning("Failed to %s '%s': %s", argv[0], argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_vxlan(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *local = NULL, *remote = NULL, *group = NULL;
        bool independent = false, have_vni = false;
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint16_t port;
        uint32_t vni;
        int r;

        for (int i = 1; i < argc; i++) {
                if (string_equal(argv[i], "dev") || string_equal(argv[i], "device") || string_equal(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find link '%s': %s", argv[i], g_strerror(-r));
                                return -errno;
                        }
                        continue;
                }

                if (string_equal(argv[i], "vni")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &vni);
                        if (r < 0) {
                                log_warning("Failed to parse vni %s: %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        have_vni = true;
                        continue;
                }

                if (string_equal(argv[i], "local")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &local);
                        if (r < 0) {
                                log_warning("Failed to parse local address : %s", argv[i]);
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "remote")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &remote);
                        if (r < 0) {
                                log_warning("Failed to parse remote address : %s", argv[i]);
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "group")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &group);
                        if (r < 0) {
                                log_warning("Failed to parse greoup address : %s", argv[i]);
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "independent")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse independent %s : %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }
                        independent = r;
                        continue;
                }

                if (string_equal(argv[i], "port")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint16(argv[i], &port);
                        if (r < 0) {
                                log_warning("Failed to parse port %s: %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        continue;
                }

                if (i != 1) {
                        log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                        return -EINVAL;
                }
        }

        if (!have_vni) {
                log_warning("Missing VxLan vni: %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        if (!independent && !p) {
                log_warning("Missing device: %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_create_vxlan(argv[1], vni, local, remote, group, port, p->ifname, independent);
        if (r < 0) {
                log_warning("Failed to create vxlan '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_vlan(int argc, char *argv[]) {
        bool have_id = false, have_dev = false;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *proto = NULL;
        uint16_t id;
        int r = 0;

        for (int i = 1; i < argc; i++) {
                if (string_equal(argv[i], "dev") || string_equal(argv[i], "device") || string_equal(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find link '%s': %s", argv[i], g_strerror(-r));
                                return -errno;
                        }
                        have_dev = true;
                        continue;
                }

                if (string_equal(argv[i], "id")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint16(argv[i], &id);
                        if (r < 0) {
                                log_warning("Failed to parse VLan id '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }
                        have_id = true;
                        continue;
                }

                if (string_equal(argv[i], "proto") || string_equal(argv[i], "protocol")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "802.1q") || string_equal(argv[i], "802.1ad")) {
                                proto = strdup(argv[i]);
                                if (!proto)
                                        return log_oom();
                        } else {
                                log_warning("Failed to parse VLan proto '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        continue;
                }

                if (i != 1) {
                        log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                        return -EINVAL;
                }
        }

        if (!have_id) {
                log_warning("Missing VLan id: %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_dev) {
                log_warning("Missing device: %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_create_vlan(p, argv[1], id, proto);
        if (r < 0) {
                log_warning("Failed to create vlan '%s': %s", argv[2], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_remove_netdev(int argc, char *argv[]) {
        _cleanup_(config_manager_unrefp) ConfigManager *m = NULL;
        int r;

        r = netdev_ctl_name_to_configs_new(&m);
        if (r < 0) {
                log_warning("Failed to remove netdev '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        r = manager_remove_netdev(argv[1], ctl_to_config(m, argv[3]));
        if (r < 0) {
                log_warning("Failed to remove netdev '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_veth(int argc, char *argv[]) {
        _auto_cleanup_ char *peer = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (string_equal(argv[i], "peer")) {
                        parse_next_arg(argv, argc, i);

                        peer = strdup(argv[i]);
                        if (!peer)
                                return log_oom();
                }
        }

        r = manager_create_veth(argv[1], peer);
        if (r < 0) {
                log_warning("Failed to create veth '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_vrf(int argc, char *argv[]) {
        bool have_table = false;
        uint32_t table;
        int r;

        if (string_equal(argv[2], "table")) {
                r = parse_uint32(argv[3], &table);
                if (r < 0) {
                        log_warning("Failed to parse table id '%s' for '%s': %s", argv[3], argv[1], g_strerror(EINVAL));
                        return r;
                }
                have_table = true;
        }

        if (!have_table) {
                log_warning("Missing table id: %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_create_vrf(argv[1], table);
        if (r < 0) {
                log_warning("Failed to create vrf '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_tunnel(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *local = NULL, *remote = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool independent = false;
        NetDevKind kind;
        char *c;
        int r;

        c = strchr(argv[0], '-');
        kind = netdev_name_to_kind(++c);
        if (kind < 0) {
                log_warning("Failed to find tunnel kind '%s': %s", c, g_strerror(EINVAL));
                return -EINVAL;
        }

        for (int i = 1; i < argc; i++) {
                if (string_equal(argv[i], "dev") || string_equal(argv[i], "device") || string_equal(argv[i], "link")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find link '%s': %s", argv[i], g_strerror(-r));
                                return -errno;
                        }
                        continue;
                }

                if (string_equal(argv[i], "local")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &local);
                        if (r < 0) {
                                log_warning("Failed to parse local address : %s", argv[i]);
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "remote")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_string(argv[i], &remote);
                        if (r < 0) {
                                log_warning("Failed to parse remote address : %s", argv[i]);
                                return r;
                        }
                        continue;
                }

                if (string_equal(argv[i], "independent")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse independent %s : %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }
                        independent = r;
                        continue;
                }

                if (i != 1) {
                        log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                        return -EINVAL;
                }
        }

        r = manager_create_tunnel(argv[1], kind, local, remote, p->ifname, independent);
        if (r < 0) {
                log_warning("Failed to create vxlan '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_create_wireguard_tunnel(int argc, char *argv[]) {
        _auto_cleanup_ char *private_key = NULL, *public_key = NULL, *preshared_key = NULL, *endpoint = NULL, *allowed_ips = NULL;
        bool have_private_key = false, have_public_key = false;
        uint16_t listen_port;
        int r;

        for (int i = 1; i < argc; i++) {
                if (string_equal(argv[i], "private-key")) {
                        parse_next_arg(argv, argc, i);

                        private_key = strdup(argv[i]);
                        if (!private_key)
                                return log_oom();

                        have_private_key = true;
                        continue;
                }

                if (string_equal(argv[i], "public-key")) {
                        parse_next_arg(argv, argc, i);

                        public_key = strdup(argv[i]);
                        if (!public_key)
                                return log_oom();

                        have_public_key = true;
                        continue;
                }

                if (string_equal(argv[i], "preshared-key")) {
                        parse_next_arg(argv, argc, i);

                        preshared_key= strdup(argv[i]);
                        if (!preshared_key)
                                return log_oom();
                        continue;
                }

                if (string_equal(argv[i], "allowed-ips")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse allowed ips '%s': %s", argv[i], g_strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        _auto_cleanup_ IPAddress *address = NULL;

                                        r = parse_ip_from_string(*d, &address);
                                        if (r < 0) {
                                                log_warning("Failed to parse allowed ips '%s': %s", argv[i], g_strerror(EINVAL));
                                                return -EINVAL;
                                        }
                                }
                        } else {
                                _auto_cleanup_ IPAddress *address = NULL;

                                r = parse_ip_from_string(argv[i], &address);
                                if (r < 0) {
                                        log_warning("Failed to parse allowed ips '%s': %s", argv[i], g_strerror(EINVAL));
                                        return -EINVAL;
                                }
                        }

                        allowed_ips = strdup(argv[i]);
                        if (!allowed_ips)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "endpoint")) {
                        _auto_cleanup_ IPAddress *address = NULL;
                        uint16_t port;

                        parse_next_arg(argv, argc, i);

                        r = parse_ip_port(argv[i], &address, &port);
                        if (r < 0) {
                                log_warning("Failed to parse endpoint '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        endpoint = strdup(argv[i]);
                        if (!endpoint)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "listen-port")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint16(argv[i], &listen_port);
                        if (r < 0) {
                                log_warning("Failed to parse listen port '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                if (i != 1) {
                        log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                        return -EINVAL;
                }
        }

        if (!have_public_key || !have_private_key) {
                log_warning("Missing public-key or private-key : %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_create_wireguard_tunnel(argv[1], private_key, public_key, preshared_key, endpoint, allowed_ips, listen_port);
        if (r < 0) {
                log_warning("Failed to create wireguard tunnel '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_show_network_config(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *config = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_show_link_network_config(p, &config);
        if (r < 0) {
                log_warning("Failed to show network configuration of link '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        printf("%s\n", config);
        return 0;
}

_public_ int ncm_link_edit_network_config(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_edit_link_network_config(p);
        if (r < 0) {
                log_warning("Failed to edit network configuration of link '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link : %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "alias")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_alias(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse alias='%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        n->alias = strdup(argv[i]);
                        if (!n->alias)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "desc")) {
                        parse_next_arg(argv, argc, i);

                        if (!argv[i]) {
                                log_warning("Failed to parse desc='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->desc = strdup(argv[i]);
                        if (!n->desc)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "mtub")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_link_bytes(argv[i])) {
                                log_warning("Failed to parse mtub='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->mtub = strdup(argv[i]);
                        if (!n->mtub)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "bps")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_link_bytes(argv[i])) {
                                log_warning("Failed to parse bps='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->bps = strdup(argv[i]);
                        if (!n->bps)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "duplex")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_duplex(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse duplex='%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        n->duplex = strdup(argv[i]);
                        if (!n->duplex)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "wol")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                _auto_cleanup_ char *w = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse wakeonlan '%s': %s", argv[i], g_strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        r = parse_link_wakeonlan(*d);
                                        if (r < 0) {
                                                log_warning("Failed to parse wakeonlan '%s': %s", *d, g_strerror(EINVAL));
                                                return r;
                                        }
                                }

                                w = strv_join(" ", s);
                                if (!w) {
                                        log_warning("Failed to parse wakeonlan '%s': %s", *d, g_strerror(EINVAL));
                                        return -EINVAL;
                                }
                                n->wol = strdup(w);
                        } else {
                                r = parse_link_wakeonlan(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse wakeonlan '%s': %s", argv[i], g_strerror(EINVAL));
                                        return r;
                                }
                                n->wol = strdup(argv[i]);
                        }

                        if (!n->wol)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "wolp")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_ether_address(argv[i])) {
                                log_warning("Failed to parse wolp='%s': %s", argv[i], g_strerror(-r));
                                return -EINVAL;
                        }

                        n->wolp = strdup(argv[i]);
                        if (!n->wolp)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "port")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_port(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse port='%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        n->port = strdup(argv[i]);
                        if (!n->port)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "advertise")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                _auto_cleanup_ char *a = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse advertise '%s': %s", argv[i], g_strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        r = parse_link_advertise(*d);
                                        if (r < 0) {
                                                log_warning("Failed to parse advertise '%s': %s", *d, g_strerror(EINVAL));
                                                return r;
                                        }
                                }

                                a = strv_join(" ", s);
                                if (!a) {
                                        log_warning("Failed to parse advertise '%s': %s", *d, g_strerror(EINVAL));
                                        return -EINVAL;
                                }
                                n->advertise = strdup(a);
                        } else {
                                r = parse_link_advertise(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse advertise '%s': %s", argv[i], g_strerror(EINVAL));
                                        return r;
                                }
                                n->advertise = strdup(argv[i]);
                        }

                        if (!n->advertise)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_features(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link feature: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "auton")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse auton='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->auto_nego = r;
                        continue;
                }
                if (string_equal(argv[i], "rxcsumo")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse rxcsumo='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->rx_csum_off = r;
                        continue;
                }
                if (string_equal(argv[i], "txcsumo")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse txcsumo='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->tx_csum_off = r;
                        continue;
                }
                if (string_equal(argv[i], "tso")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse tso='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->tcp_seg_off = r;
                        continue;
                }
                if (string_equal(argv[i], "tso6")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse tso6='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->tcp6_seg_off = r;
                        continue;
                }
                if (string_equal(argv[i], "gso")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse gso='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->gen_seg_off = r;
                        continue;
                }
                if (string_equal(argv[i], "grxo")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse grxo='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->gen_rx_off = r;
                        continue;
                }
                if (string_equal(argv[i], "grxoh")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse grxoh='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->gen_rx_off_hw = r;
                        continue;
                }
                if (string_equal(argv[i], "lrxo")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse lrxo='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->large_rx_off = r;
                        continue;
                }
                if (string_equal(argv[i], "rxvtha")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse rxvtha='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->rx_vlan_ctag_hw_acl = r;
                        continue;
                }
                if (string_equal(argv[i], "txvtha")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse txvtha='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->tx_vlan_ctag_hw_acl = r;
                        continue;
                }
                if (string_equal(argv[i], "rxvtf")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse rxvtf='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->rx_vlan_ctag_fltr = r;
                        continue;
                }
                if (string_equal(argv[i], "txvstha")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse txvstha='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->tx_vlan_stag_hw_acl = r;
                        continue;
                }
                if (string_equal(argv[i], "ntf")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse ntf='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->n_tpl_fltr = r;
                        continue;
                }
                if (string_equal(argv[i], "uarxc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse uarxc='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->use_adpt_rx_coal = r;
                        continue;
                }
                if (string_equal(argv[i], "uatxc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse uatxc='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->use_adpt_tx_coal = r;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_buf_size(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link feature: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "rxbuf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxbuf='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_buf = strdup(argv[i]);
                        if (!n->rx_buf) {
                                return log_oom();
                        }
                        continue;
                }
                if (string_equal(argv[i], "rxminbuf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxminbuf='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }
                        n->rx_mini_buf = strdup(argv[i]);
                        continue;
                }
                if (string_equal(argv[i], "rxjumbobuf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxjumbobuf='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }
                        n->rx_jumbo_buf = strdup(argv[i]);
                        continue;
                }
                if (string_equal(argv[i], "txbuf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txbuf='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }
                        n->tx_buf = strdup(argv[i]);
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_queue_size(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link queue size: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                unsigned v;

                if (string_equal(argv[i], "txq")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_link_queue(argv[i], &v)) {
                                log_warning("Failed to parse txq='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_queues = v;
                        continue;
                }
                if (string_equal(argv[i], "rxq")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_link_queue(argv[i], &v)) {
                                log_warning("Failed to parse rxq='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }
                        n->rx_queues = v;
                        continue;
                }
                if (string_equal(argv[i], "txqlen")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v);
                        if (r < 0) {
                                log_warning("Failed to parse txqlen='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->tx_queue_len = v;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_flow_control(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link flow control: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "rxflowctrl")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse rxflowctrl='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->rx_flow_ctrl = r;
                        continue;
                }
                if (string_equal(argv[i], "txflowctrl")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse rxflowctrl='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->tx_flow_ctrl = r;
                        continue;
                }
                if (string_equal(argv[i], "autoflowctrl")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse autoflowctrl='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }
                        n->auto_flow_ctrl = r;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_gso(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link gso: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "gsob")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_gso(argv[i], &n->gen_seg_off_bytes);
                        if (r < 0) {
                                log_warning("Failed to parse gsob='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }
                if (string_equal(argv[i], "gsos")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_gso(argv[i], &n->gen_seg_off_seg);
                        if (r < 0) {
                                log_warning("Failed to parse gsos='%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_channel(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link channel: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "rxch")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxch='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_chnl = strdup(argv[i]);
                        if (!n->rx_chnl)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "txch")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txch='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_chnl = strdup(argv[i]);
                        if (!n->tx_chnl)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "otrch")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse otrch='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->otr_chnl = strdup(argv[i]);
                        if (!n->rx_chnl)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "combch")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse combch='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->comb_chnl = strdup(argv[i]);
                        if (!n->rx_chnl)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_coalesce(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link coalesce: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "rxcs")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxcs='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coal_sec = strdup(argv[i]);
                        if (!n->rx_coal_sec)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "rxcsirq")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxcsirq='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coal_irq_sec = strdup(argv[i]);
                        if (!n->rx_coal_irq_sec)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "rxcslow")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxcslow='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coal_low_sec = strdup(argv[i]);
                        if (!n->rx_coal_low_sec)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "rxcshigh")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxcshigh='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coal_high_sec = strdup(argv[i]);
                        if (!n->rx_coal_high_sec)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "txcs")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txcs='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coal_sec = strdup(argv[i]);
                        if (!n->tx_coal_sec)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "txcsirq")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txcsirq='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coal_irq_sec = strdup(argv[i]);
                        if (!n->rx_coal_irq_sec)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "txcslow")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txcslow='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coal_low_sec = strdup(argv[i]);
                        if (!n->tx_coal_low_sec)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "txcshigh")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txcshigh='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coal_high_sec = strdup(argv[i]);
                        if (!n->tx_coal_high_sec)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_coald_frames(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link coalesce frames: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "rxmcf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxmcf='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coald_frames = strdup(argv[i]);
                        if (!n->rx_coald_frames)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "rxmcfirq")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxmcfirq='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coald_irq_frames = strdup(argv[i]);
                        if (!n->rx_coald_irq_frames)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "rxmcflow")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxmcflow='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coald_low_frames = strdup(argv[i]);
                        if (!n->rx_coald_low_frames)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "rxmcfhigh")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxmcfhigh='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coald_high_frames = strdup(argv[i]);
                        if (!n->rx_coald_high_frames)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "txmcf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txmcf='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coald_frames = strdup(argv[i]);
                        if (!n->tx_coald_frames)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "txmcfirq")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txmcfirq='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coald_irq_frames = strdup(argv[i]);
                        if (!n->tx_coald_irq_frames)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "txmcflow")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txmcflow='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coald_low_frames = strdup(argv[i]);
                        if (!n->tx_coald_low_frames)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "txmcfhigh")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txmcfhigh='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coald_high_frames = strdup(argv[i]);
                        if (!n->tx_coald_high_frames)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_coal_pkt(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link coalesce packet rate: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "cprlow")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse cprlow='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->coal_pkt_rate_low = strdup(argv[i]);
                        if (!n->coal_pkt_rate_low)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "cprhigh")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse cprhigh='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->coal_pkt_rate_high = strdup(argv[i]);
                        if (!n->coal_pkt_rate_high)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "cprsis")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse cprsis='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->coal_pkt_rate_smpl_itrvl = strdup(argv[i]);
                        if (!n->coal_pkt_rate_smpl_itrvl)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "sbcs")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse sbcs='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->sts_blk_coal_sec = strdup(argv[i]);
                        if (!n->sts_blk_coal_sec)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_sr_iov(int argc, char *argv[]) {
        _cleanup_(netdev_sriov_unrefp) SRIOV *s = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool have_vf = false;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_sriov_new(&s);
        if (r < 0) {
                log_warning("Failed to configure sriov: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                unsigned v;

                if (string_equal(argv[i], "vf")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v);
                        if (r < 0) {
                                log_warning("Failed to configure sriov vf ='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        s->vf = strdup(argv[i]);
                        if (!s->vf)
                                return log_oom();

                        have_vf = true;
                        continue;
                }
                if (string_equal(argv[i], "vlanid")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v);
                        if (r < 0) {
                                log_warning("Failed to configure sriov vlanid ='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        s->vlanid = strdup(argv[i]);
                        if (!s->vlanid)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "qos")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v);
                        if (r < 0) {
                                log_warning("Failed to configure sriov qos ='%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        s->qos = strdup(argv[i]);
                        if (!s->qos)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "vlanproto")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_sriov_vlanprotocol(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to configure sriov vlanproto ='%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        s->vlanproto = strdup(argv[i]);
                        if (!s->vlanproto)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "macspoofck")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse sriov macspoofck '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        s->macspoofck = r;
                        continue;
                }
                if (string_equal(argv[i], "qrss")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse sriov qrss '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        s->qrss = r;
                        continue;
                }
                if (string_equal(argv[i], "trust")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse sriov trust '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        s->trust = r;
                        continue;
                }
                if (string_equal(argv[i], "linkstate")) {
                        parse_next_arg(argv, argc, i);

                        if (!string_equal(argv[i], "auto")) {
                                r = parse_boolean(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse sriov linkstate '%s': %s", argv[i], g_strerror(-r));
                                        return r;
                                }
                        }

                        s->linkstate = strdup(argv[i]);
                        if (!s->linkstate)
                                return log_oom();

                        continue;
                }
                if (string_equal(argv[i], "macaddr")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_ether_address(argv[i])) {
                                log_warning("Failed to parse sriov macaddr='%s': %s", argv[i], g_strerror(-r));
                                return -EINVAL;
                        }

                        s->macaddr = strdup(argv[i]);
                        if (!s->macaddr)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        if (!have_vf) {
                log_warning("Failed to configure sriov missing VirtualFunction : %s", g_strerror(EINVAL));
                return -EINVAL;
        }

        r = netdev_sriov_configure(p, s);
        if (r < 0) {
                log_warning("Failed to configure sriov: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_altname(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link altname: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "altnamepolicy")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                _auto_cleanup_ char *altnm = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse altnamepolicy '%s': %s", argv[i], g_strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        r = parse_link_altnamepolicy(*d);
                                        if (r < 0) {
                                                log_warning("Failed to parse altnamepolicy '%s': %s", *d, g_strerror(EINVAL));
                                                return r;
                                        }
                                }

                                altnm = strv_join(" ", s);
                                if (!altnm) {
                                        log_warning("Failed to parse altnamepolicy '%s': %s", *d, g_strerror(EINVAL));
                                        return -EINVAL;
                                }
                                n->altnamepolicy = strdup(altnm);
                        } else {
                                r = parse_link_altnamepolicy(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse altnamepolicy '%s': %s", argv[i], g_strerror(EINVAL));
                                        return r;
                                }
                                n->altnamepolicy = strdup(argv[i]);
                        }

                        if (!n->altnamepolicy)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "altname")) {
                        parse_next_arg(argv, argc, i);

                        if (!argv[i]) {
                                log_warning("Failed to parse altname '%s': %s", argv[i], g_strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->altname = strdup(argv[i]);
                        if (!n->altname)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_name(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link name: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "namepolicy")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                _auto_cleanup_ char *nm = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse namepolicy '%s': %s", argv[i], g_strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        r = parse_link_namepolicy(*d);
                                        if (r < 0) {
                                                log_warning("Failed to parse namepolicy '%s': %s", *d, g_strerror(EINVAL));
                                                return r;
                                        }
                                }

                                nm = strv_join(" ", s);
                                if (!nm) {
                                        log_warning("Failed to parse namepolicy '%s': %s", *d, g_strerror(EINVAL));
                                        return -EINVAL;
                                }
                                n->namepolicy = strdup(nm);
                        } else {
                                r = parse_link_namepolicy(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse namepolicy '%s': %s", argv[i], g_strerror(EINVAL));
                                        return r;
                                }
                                n->namepolicy = strdup(argv[i]);
                        }

                        if (!n->namepolicy)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "name")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_name(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse name '%s': %s", argv[i], g_strerror(EINVAL));
                                return r;
                        }

                        n->name = strdup(argv[i]);
                        if (!n->name)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_mac(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = netdev_link_new(&n);
        if (r < 0) {
                log_warning("Failed to set link mac: %s", g_strerror(-r));
                return -errno;
        }

        for (int i = 2; i < argc; i++) {
                if (string_equal(argv[i], "macpolicy")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                _auto_cleanup_ char *pcy = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse macpolicy '%s': %s", argv[i], g_strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        r = parse_link_macpolicy(*d);
                                        if (r < 0) {
                                                log_warning("Failed to parse macpolicy '%s': %s", *d, g_strerror(EINVAL));
                                                return r;
                                        }
                                }

                                pcy = strv_join(" ", s);
                                if (!pcy) {
                                        log_warning("Failed to parse macpolicy '%s': %s", *d, g_strerror(EINVAL));
                                        return -EINVAL;
                                }
                                n->macpolicy = strdup(pcy);
                        } else {
                                r = parse_link_macpolicy(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse macpolicy '%s': %s", argv[i], g_strerror(EINVAL));
                                        return r;
                                }
                                n->macpolicy = strdup(argv[i]);
                        }

                        if (!n->macpolicy)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "macaddr")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_ether_address(argv[i])) {
                                log_warning("Failed to parse macaddr='%s': %s", argv[i], g_strerror(-r));
                                return -EINVAL;
                        }

                        n->macaddr = strdup(argv[i]);
                        if (!n->macaddr)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure link: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_proxy(int argc, char *argv[]) {
        _auto_cleanup_  char *http = NULL, *https = NULL, *ftp = NULL, *gopher = NULL, *socks = NULL, *socks5 = NULL, *no_proxy = NULL;
        int r, enable = -1;

        for (int i = 1; i < argc; i++) {
                if (string_equal(argv[i], "enable")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse enable '%s': %s", argv[i], g_strerror(-r));
                                return r;
                        }

                        enable = r;
                        continue;
                }

                if (string_equal(argv[i], "http") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                http = strdup("");
                        else
                                http = strdup(argv[i]);
                        if (!http)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "https") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                https = strdup("");
                        else
                                https = strdup(argv[i]);
                        if (!https)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "ftp") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                ftp = strdup("");
                        else
                                ftp = strdup(argv[i]);
                        if (!ftp)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "gopher") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                gopher = strdup("");
                        else
                                gopher = strdup(argv[i]);
                        if (!gopher)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "socks") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                socks = strdup("");
                        else
                                socks = strdup(argv[i]);
                        if (!socks)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "socks5") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                socks5 = strdup("");
                        else
                                socks5 = strdup(argv[i]);
                        if (!socks5)
                                return log_oom();

                        continue;
                }

                if (string_equal(argv[i], "noproxy") || string_equal(argv[i], "none")) {
                        parse_next_arg(argv, argc, i);

                        if (string_equal(argv[i], "none"))
                                no_proxy = strdup("");
                        else
                                no_proxy = strdup(argv[i]);
                        if (!no_proxy)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], g_strerror(-EINVAL));
                return -EINVAL;
        }

        r = manager_configure_proxy(enable, http, https, ftp, gopher, socks, socks5, no_proxy);
        if (r < 0) {
                log_warning("Failed to configure proxy settings: %s", g_strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_show_proxy(int argc, char *argv[]) {
        _auto_cleanup_hash_ GHashTable *table = NULL;
        char *v;
        int r;

        r = manager_parse_proxy_config(&table);
        if (r < 0) {
                log_warning("Failed to parse proxy settings: %s", g_strerror(-r));
                return r;
        }

        printf("Proxy Settings\n");

        v = g_hash_table_lookup(table, "PROXY_ENABLED");
        if(v)
                printf("      Enabled: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "HTTP_PROXY");
        if(v)
                printf("         HTTP: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "HTTPS_PROXY");
        if(v)
                printf("        HTTPS: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "FTP_PROXY");
        if(v)
                printf("          FTP: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "GOPHER_PROXY");
        if(v)
                printf("       Gopher: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "SOCKS_PROXY");
        if(v)
                printf("        Socks: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "SOCKS5_SERVER");
        if(v)
                printf("Socks5 Server: %s\n", (char *) v);

        v = g_hash_table_lookup(table, "NO_PROXY");
        if(v)
                printf("     No Proxy: %s\n", (char *) v);

        return 0;
}

_public_ int ncm_get_proxy(char ***proxy) {
        _auto_cleanup_hash_ GHashTable *table = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        char *k = NULL, *v = NULL;
        GHashTableIter iter;
        int r;

        assert(proxy);

        r = manager_parse_proxy_config(&table);
        if (r < 0)
                return r;

        g_hash_table_iter_init (&iter, table);
        for (;g_hash_table_iter_next (&iter, (gpointer *) &k, (gpointer *) &v);) {
                _auto_cleanup_ char *p = NULL;

                p = string_join(":", k, v, NULL);
                if (!p)
                        return log_oom();

                if (!s) {
                        s = strv_new(p);
                        if (!s)
                                return log_oom();
                } else {
                        r = strv_add(&s, p);
                        if (r < 0)
                                return r;
                }

                steal_pointer(p);
        }

        *proxy = steal_pointer(s);
        return 0;
}

_public_ bool ncm_is_netword_running(void) {
        if (access("/run/systemd/netif/state", F_OK) < 0) {
                log_warning("systemd-networkd is not running. Failed to continue.\n\n");
                return false;
        }

        return true;
}

_public_ int ncm_show_version(void) {
       printf("%s\n", PACKAGE_STRING);
       return 0;
}

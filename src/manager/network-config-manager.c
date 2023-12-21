/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <network-config-manager.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "arphrd-to-name.h"
#include "config-parser.h"
#include "ctl-display.h"
#include "ctl.h"
#include "dbus.h"
#include "dns.h"
#include "log.h"
#include "macros.h"
#include "netdev-link.h"
#include "network-address.h"
#include "network-json.h"
#include "network-link.h"
#include "network-manager.h"
#include "network-route.h"
#include "network-sriov.h"
#include "network-util.h"
#include "networkd-api.h"
#include "nftables.h"
#include "parse-util.h"

_public_ int ncm_link_set_mtu(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool have_mtu = false;
        uint32_t mtu;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "mtu")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_mtu(argv[i], &mtu);
                        if (r < 0) {
                                log_warning("Failed to parse mtu '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        have_mtu = true;
                        break;
                } else {
                        r = parse_mtu(argv[i], &mtu);
                        if (r < 0) {
                                log_warning("Failed to parse mtu '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        have_mtu = true;
                        break;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_mtu) {
                log_warning("Failed to parse MTU: %s", strerror(-r));
                return -EINVAL;
        }

        r = manager_set_link_mtu(p, mtu);
        if (r < 0) {
                log_warning("Failed to update MTU for '%s': %s", p->ifname, strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_acquire_mtu(const char *ifname, uint32_t *ret) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t mtu;
        int r;

        assert(ifname);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return r;

        r = netlink_acquire_link_mtu(p->ifname, &mtu);
        if (r < 0)
                return r;

        *ret = mtu;
        return 0;
}

_public_ int ncm_link_get_mtu(const char *ifname, uint32_t *ret) {
         return ncm_link_acquire_mtu(ifname, ret);
}

_public_ int ncm_link_set_mac(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *mac = NULL;
        bool have_mac = false;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "mac")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_ether_address(argv[i])) {
                                log_warning("Failed to parse MAC address: %s", argv[2]);
                                return -EINVAL;
                        }
                        mac = strdup(argv[i]);
                        if (!mac)
                                return log_oom();

                        have_mac = true;
                        break;
                } else {
                        if (!parse_ether_address(argv[i])) {
                                log_warning("Failed to parse MAC address: %s", argv[2]);
                                return -EINVAL;
                        }
                        mac = strdup(argv[i]);
                        if (!mac)
                                return log_oom();

                        have_mac = true;
                        break;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_mac) {
                log_warning("Failed to parse MAC address: %s", strerror(-r));
                return -EINVAL;
        }

        r = manager_set_link_mac_addr(p, mac);
        if (r < 0) {
                log_warning("Failed to update MAC address for device '%s': %s", p->ifname, strerror(-r) );
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
                return r;

        r = link_read_sysfs_attribute(p->ifname, "address", &mac);
        if (r < 0)
                return r;

        *ret = mac;
        return 0;
}

_public_ int ncm_link_set_mode(int argc, char *argv[]) {
        _cleanup_(config_manager_freep) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool k = true;
        int r;

        r = manager_network_link_section_configs_new(&m);
        if (r < 0) {
                log_warning("Failed to set network device section '%s'", strerror(-r));
                return r;
        }

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "manage")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse device 'manage' '%s' '%s': %s", p->ifname, argv[i], strerror(-r));
                                return r;
                        }
                        k = r;
                        break;
                } else {
                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse device 'manage' '%s' '%s': %s", p->ifname, argv[i], strerror(-r));
                                return r;
                        }
                        k = r;
                        break;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_link_flag(p, ctl_to_config(m, "manage"), bool_to_str(!k));
        if (r < 0) {
                printf("Failed to set device manage '%s': %s\n", p->ifname, strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_option(int argc, char *argv[]) {
        _cleanup_(config_manager_freep) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r = 0;
        bool k;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                 }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(ENOENT));
                return r;
        }

        r = manager_network_link_section_configs_new(&m);
        if (r < 0) {
                log_warning("Failed to set network device section '%s'", strerror(-r));
                return r;
        }

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "arp")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse arp='%s' on device '%s': %s", argv[i], p->ifname, strerror(-r));
                                return r;
                        }

                        k = r;
                        r = manager_set_link_flag(p, ctl_to_config(m, "arp"), bool_to_str(k));
                        if (r < 0) {
                                log_warning("Failed to set arp on device='%s': %s", p->ifname, strerror(-r));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "mc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse device='%s' multicast='%s': %s", p->ifname, argv[i], strerror(-r));
                                return r;
                        }

                        k = r;
                        r = manager_set_link_flag(p, ctl_to_config(m, argv[i-1]), bool_to_str(k));
                        if (r < 0) {
                                log_warning("Failed to set multicast on device '%s': %s", p->ifname, strerror(-r));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "amc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse device='%s' allmulticast='%s': %s", p->ifname, argv[i], strerror(-r));
                                return r;
                        }

                        k = r;
                        r = manager_set_link_flag(p, ctl_to_config(m, argv[i-1]), bool_to_str(k));
                        if (r < 0) {
                                printf("Failed to set device arp '%s': %s\n", p->ifname, strerror(-r));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "pcs")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse device='%s' promiscuous='%s': %s", p->ifname, argv[i], strerror(-r));
                                return r;
                        }

                        k = r;
                        r = manager_set_link_flag(p, ctl_to_config(m, argv[i-1]), bool_to_str(k));
                        if (r < 0) {
                                log_warning("Failed to set device arp on device '%s': %s", p->ifname, strerror(-r));
                                return r;
                        }
                }
        }

        return 0;
}

_public_ int ncm_link_set_group(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool have_group = false;
        uint32_t group;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "group")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_group(argv[i], &group);
                        if (r < 0) {
                                log_warning("Failed to parse device group '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        have_group = true;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_group) {
                log_warning("Failed to parse group: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_link_group(p, group);
        if (r < 0) {
                log_warning("Failed to update Group for '%s': %s", p->ifname, strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_rf_online(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *family = NULL;
        bool have_family = false;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "family") || str_eq_fold(argv[i], "f")) {
                        parse_next_arg(argv, argc, i);

                        r = address_family_name_to_type(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse RequiredFamilyForOnline '%s': %s", argv[2], strerror(EINVAL));
                                return r;
                        }
                        family = strdup(argv[i]);
                        if (!family)
                                return log_oom();

                        have_family = true;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_family) {
                log_warning("Failed to parse family: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_link_rf_online(p, family);
        if (r < 0) {
                log_warning("Failed to update RequiredFamilyForOnline= for '%s': %s", p->ifname, strerror(-r) );
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_act_policy(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *ap = NULL;
        bool have_ap = false;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "ap") || str_eq_fold(argv[i], "act-policy")) {
                        parse_next_arg(argv, argc, i);

                        r = device_activation_policy_name_to_type(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse ActivationPolicy='%s': %s", argv[2], strerror(EINVAL));
                                return r;
                        }

                        ap = strdup(argv[i]);
                        if (!ap)
                                return log_oom();

                        have_ap = true;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_ap) {
                log_warning("Failed to parse ActivationPolicy=: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_link_act_policy(p, ap);
        if (r < 0) {
                log_warning("Failed to update ActivationPolicy= for '%s': %s", p->ifname, strerror(-r) );
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_network_ipv6_mtu(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t mtu;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = parse_mtu(argv[3], &mtu);
        if (r < 0)
                return r;

        if (mtu < 1280) {
                log_warning("MTU must be greater than or equal to 1280 bytes. Failed to update MTU for '%s': %s", p->ifname, strerror(EINVAL));
                return r;
        }

        r = manager_link_set_network_ipv6_mtu(p, mtu);
        if (r < 0) {
                log_warning("Failed to update MTU for '%s': %s", p->ifname, strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_dhcp_mode(int argc, char *argv[]) {
        int r, use_dns_ipv4 = -1, use_dns_ipv6 = -1, send_release_ipv4 = -1, send_release_ipv6 = -1;
        _auto_cleanup_ IfNameIndex *p = NULL;
        DHCPClient dhcp = _DHCP_CLIENT_INVALID;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "dhcp")) {
                        parse_next_arg(argv, argc, i);

                        dhcp = dhcp_client_name_to_mode(argv[i]);
                        if (dhcp < 0) {
                                log_warning("Failed to parse dhcp: %s", argv[i]);
                                return -EINVAL;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "use-dns-ipv4")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse use-dns-ipv4='%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        use_dns_ipv4 = r;

                        continue;
                } else if (str_eq_fold(argv[i], "use-dns-ipv6")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse use-dns-ipv6='%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        use_dns_ipv6 = r;
                        continue;
                } else if (str_eq_fold(argv[i], "send-release-ipv4")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse send-release-ipv4='%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        send_release_ipv4 = r;

                        continue;
                } else if (str_eq_fold(argv[i], "send-release-ipv6")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse send-release-ipv6='%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        send_release_ipv6 = r;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (dhcp == _DHCP_CLIENT_INVALID) {
                log_warning("Failed to parse dhcp : %s", strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_link_dhcp_client(p, dhcp, use_dns_ipv4, use_dns_ipv6, send_release_ipv4, send_release_ipv6);
        if (r < 0) {
                log_warning("Failed to set DHCP configuration for device='%s': %s\n", p->ifname, strerror(-r));
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
                return r;

        r = manager_acquire_link_dhcp_client_kind(p, &mode);
        if (r < 0)
                return r;

        *ret = mode;
        return 0;
}

_public_ int ncm_link_set_dhcp4_client_identifier(int argc, char *argv[]) {
        DHCPClientIdentifier d = _DHCP_CLIENT_IDENTIFIER_INVALID;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "id")) {
                        parse_next_arg(argv, argc, i);

                        d = dhcp_client_identifier_to_mode(argv[i]);
                        if (d == _DHCP_CLIENT_IDENTIFIER_INVALID) {
                                log_warning("Failed to parse DHCP4 client identifier: %s", argv[i]);
                                return -EINVAL;
                        }

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (d == _DHCP_CLIENT_IDENTIFIER_INVALID) {
                log_warning("Failed to parse DHCP4 client identifier: %s", strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_link_dhcp4_client_identifier(p, d);
        if (r < 0) {
                log_warning("Failed to set device DHCP4 client identifier '%s': %s", p->ifname, strerror(r));
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
                return r;

        r = manager_acquire_link_dhcp4_client_identifier(p, &d);
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
        _auto_cleanup_ char *iaid = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "family") || str_eq_fold(argv[i], "f")) {
                        parse_next_arg(argv, argc, i);

                        r  = dhcp_name_to_client(argv[i]);
                        if (r < 0) {

                                log_warning("Failed to determine DHCP client type '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }
                        kind = r;

                        continue;
                } else if (str_eq_fold(argv[i], "iaid")) {
                        uint32_t v;

                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v);
                        if (r < 0) {
                                log_warning("Failed to parse IAID '%s' for device '%s': %s", argv[i], p->ifname, strerror(-r));
                                return r;
                        }

                        iaid = strdup(argv[i]);
                        if (!iaid)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (kind == _DHCP_CLIENT_INVALID) {
                log_warning("Missing DHCP client family: %s", strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_link_dhcp_client_iaid(p, kind, iaid);
        if (r < 0) {
                log_warning("Failed to set device DHCP client IAID for '%s': %s", p->ifname, strerror(r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_get_dhcp_client_iaid(char *ifname, char **ret) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return r;

        r = manager_acquire_link_dhcp_client_iaid(p, DHCP_CLIENT_IPV4, ret);
        if (r < 0)
                return r;

        return 0;
}

_public_ int ncm_link_set_dhcp_client_duid(int argc, char *argv[]) {
        DHCPClientDUIDType d = _DHCP_CLIENT_DUID_TYPE_INVALID;
        DHCPClient kind = _DHCP_CLIENT_INVALID;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *raw_data = NULL;
        bool system = false;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "system") || str_eq_fold(argv[i], "s")) {
                        parse_next_arg(argv, argc, i);

                        system = true;
                        continue;
                } else if (str_eq_fold(argv[i], "family") || str_eq_fold(argv[i], "f")) {
                        parse_next_arg(argv, argc, i);

                        r  = dhcp_name_to_client(argv[i]);
                        if (r < 0) {

                                log_warning("Failed to determine DHCP client type '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }
                        kind = r;

                        continue;
                } else if (str_eq_fold(argv[i], "duid")) {
                        parse_next_arg(argv, argc, i);

                        d = dhcp_client_duid_name_to_type(argv[i]);
                        if (d == _DHCP_CLIENT_DUID_TYPE_INVALID) {
                                log_warning("Failed to parse DHCPv4 DUID type '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "data") || str_eq_fold(argv[i], "rawdata")) {
                        parse_next_arg(argv, argc, i);

                        raw_data = strdup(argv[i]);
                        if (!raw_data)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p && !system) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (d == _DHCP_CLIENT_DUID_TYPE_INVALID) {
                log_warning("Failed to parse 'duid' type: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_link_dhcp_client_duid(p, d, raw_data, system, kind);
        if (r < 0) {
                log_warning("Failed to set device DHCP client DUID for '%s': %s\n", p->ifname, strerror(r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_link_local_address(int argc, char *argv[]) {
        _cleanup_(config_manager_freep) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        const char *s;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        s = parse_bool_or_ip_family(argv[3]);
        if (!s) {
                log_warning("Failed to parse %s=%s for device '%s': %s", argv[0], argv[2], argv[1], strerror(-r));
                return r;
        }

        r = manager_network_section_configs_new(&m);
        if (r < 0) {
                log_warning("Failed to set network section '%s'", strerror(-r));
                return r;
        }

        return manager_set_link_local_address(p, ctl_to_config(m, argv[0]), s);
}

_public_ int ncm_link_set_network_section(int argc, char *argv[]) {
        _cleanup_(config_manager_freep) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool v;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_network_section_configs_new(&m);
        if (r < 0)
                return log_oom();

        r = parse_bool(argv[3]);
        if (r < 0) {
                if (str_eq(argv[0], "set-llmnr") || str_eq(argv[0], "llmnr") ||
                    str_eq(argv[0], "set-mcast-dns") || str_eq(argv[0], "mcast-dns")) {
                        if (str_eq(argv[3], "resolve")) {
                                return manager_set_network_section(p, ctl_to_config(m, argv[0]), "resolve");
                        }
                }
                log_warning("Failed to parse '%s': %s", argv[3], strerror(-r));
                return r;
        }
        v = r;

        return manager_set_network_section_bool(p, ctl_to_config(m, argv[0]), v);
}

_public_ int ncm_link_set_network_ipv6_dad(int argc, char *argv[]) {
        _cleanup_(config_manager_freep) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = parse_bool(argv[3]);
        if (r < 0) {
                log_warning("Failed to parse '%s': %s", argv[3], strerror(-r));
                return r;
        }

        return manager_set_link_ipv6_dad(p, r);
}

_public_ int ncm_link_set_network_ipv6_link_local_address_generation_mode(int argc, char *argv[]) {
        _cleanup_(config_manager_freep) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = ipv6_link_local_address_gen_type_to_mode(argv[3]);
        if (r < 0) {
                log_warning("Failed to parse '%s': %s", argv[3], strerror(-r));
                return r;
        }

        return manager_set_link_ipv6_link_local_address_generation_mode(p, r);
}

_public_ int ncm_link_set_dhcp4_section(int argc, char *argv[]) {
        _cleanup_(config_manager_freep) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool v;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }
        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_network_dhcp4_section_configs_new(&m);
        if (r < 0)
                return log_oom();

        for (int i = 1; i < argc; i++) {
                if (ctl_to_config(m, argv[i])) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse %s=%s for device '%s': %s", argv[i-1], argv[i], p->ifname, strerror(-r));
                                return r;
                        }
                        v = r;

                        r = manager_set_dhcp_section(DHCP_CLIENT_IPV4, p, ctl_to_config(m, argv[i-1]), v);
                        if (r < 0) {
                                log_warning("Failed to set dhcp4 section %s=%s for device '%s': %s", argv[i-1], argv[i], p->ifname, strerror(-r));
                                return r;
                        }
                }
        }

        return 0;
}

_public_ int ncm_link_set_dhcp6_section(int argc, char *argv[]) {
        _cleanup_(config_manager_freep) ConfigManager *m = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool v;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_network_dhcp6_section_configs_new(&m);
        if (r < 0) {
                log_warning("Failed to set dhcp4 section for device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        for (int i = 1; i < argc; i++) {
                if (ctl_to_config(m, argv[i])) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse %s=%s for device '%s': %s", argv[i-1], argv[i], argv[1], strerror(-r));
                                return r;
                        }
                        v = r;

                        r = manager_set_dhcp_section(DHCP_CLIENT_IPV6, p, ctl_to_config(m, argv[i-1]), v);
                        if (r < 0) {
                                log_warning("Failed to dhcp4 section %s=%s for device '%s': %s", argv[i-1], argv[i], argv[1], strerror(-r));
                                return r;
                        }
                }
        }

        return 0;
}

_public_ int ncm_link_update_state(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        LinkState state;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        state = link_name_to_state(argv[3]);
        if (state < 0) {
                log_warning("Failed to find device state '%s': %s", argv[2], strerror(EINVAL));
                return r;
        }

        r = manager_set_link_state(p, state);
        if (r < 0) {
                log_warning("Failed to set device state '%s': %s", p->ifname, strerror(-r));
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

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "address") || str_eq_fold(argv[i], "a") || str_eq_fold(argv[i], "addr")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &address);
                        if (r < 0) {
                                log_warning("Failed to parse address '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "peer")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &peer);
                        if (r < 0) {
                                log_warning("Failed to parse peer address '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "label")) {
                        parse_next_arg(argv, argc, i);

                        if (!valid_address_label(argv[i])) {
                                log_warning("Invalid label %s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        label = strdup(argv[i]);
                        if (!label)
                                return log_oom();

                        continue;
                } else if (str_eq_fold(argv[i], "pref-lifetime") || str_eq_fold(argv[i], "pl") || str_eq_fold(argv[i], "pref-lft")) {
                        uint32_t lft;

                        parse_next_arg(argv, argc, i);

                        if (!str_eq_fold(argv[i], "forever") && !str_eq_fold(argv[i], "infinity")) {
                                r = parse_uint32(argv[i], &lft);
                                if (r < 0) {
                                        log_warning("Failed to parse pref-lifetime '%s': %s", argv[i], strerror(-r));
                                        return r;
                                }
                        }

                        pref_lft = strdup(argv[i]);
                        if (!pref_lft)
                                return log_oom();

                        continue;
                } else if (str_eq_fold(argv[i], "scope")) {
                        parse_next_arg(argv, argc, i);

                        if (!str_eq_fold(argv[i], "global") && !str_eq_fold(argv[i], "link") && !str_eq_fold(argv[i], "host")) {
                                uint32_t k;

                                r = parse_uint32(argv[i], &k);
                                if (r < 0) {
                                        log_warning("Failed to parse scope '%s': %s", argv[i], strerror(-r));
                                        return r;
                                }

                                if (k > 255) {
                                        log_warning("Scope '%s' is out of range [0-255]: %s", argv[i], strerror(EINVAL));
                                        return r;
                                }
                        }

                        scope = strdup(argv[i]);
                        if (!scope)
                                return log_oom();

                        continue;
                } else if (str_eq_fold(argv[i], "dad")) {
                        parse_next_arg(argv, argc, i);

                        r = ip_duplicate_address_detection_type_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse dad '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        dad = r;
                        continue;
                } else if (str_eq_fold(argv[i], "prefix-route") || str_eq_fold(argv[i], "pr")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse prefix-route '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        prefix_route = r;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_configure_link_address(p, address, peer, scope, pref_lft, dad, prefix_route, label);
        if (r < 0) {
                log_warning("Failed to configure device address: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_delete_address(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *address = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *a = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "address") || str_eq_fold(argv[i], "a") || str_eq_fold(argv[i], "addr")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &address);
                        if (r < 0) {
                                log_warning("Failed to parse address '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        a = strdup(argv[i]);
                        if (!a)
                                return log_oom();
                        break;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!a) {

                log_warning("Failed to parse address: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_delete_link_address(p, a);
        if (r < 0) {
                log_warning("Failed to remove device address '%s': %s\n", p->ifname, strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_get_addresses(const char *ifname, char ***ret) {
        _cleanup_(addresses_freep) Addresses *addr = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        assert(ifname);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return r;

        r = netlink_get_one_link_address(p->ifindex, &addr);
        if (r < 0)
                return r;

        if (!set_size(addr->addresses))
                return -ENODATA;

        g_hash_table_iter_init(&iter, addr->addresses->hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                Address *a = (Address *) g_bytes_get_data(key, &size);
                _auto_cleanup_ char *c = NULL;

                r = ip_to_str_prefix(a->family, &a->address, &c);
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

                steal_ptr(c);
        }

        *ret = steal_ptr(s);
        return 0;
}

_public_ int ncm_link_add_default_gateway(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ IPAddress *gw = NULL;
        _auto_cleanup_ Route *rt = NULL;
        int r, onlink = -1;

       for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "gateway") || str_eq_fold(argv[i], "gw")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &gw);
                        if (r < 0) {
                                log_warning("Failed to parse gateway address '%s': %s", argv[2], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "onlink")) {
                        parse_next_arg(argv, argc, i);

                        onlink = parse_bool(argv[i]);
                        if (onlink < 0) {
                                log_warning("Failed to parse onlink '%s': %s\n", argv[1], strerror(EINVAL));
                                return -EINVAL;
                        }
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
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
                log_warning("Failed to configure device default gateway on '%s': %s", argv[1], strerror(-r));
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
        bool b = false;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "gateway") || str_eq_fold(argv[i], "gw")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &gw);
                        if (r < 0) {
                                log_warning("Failed to parse route gateway address '%s': %s", argv[2], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "destination") || str_eq_fold(argv[i], "dest")) {
                        parse_next_arg(argv, argc, i);

                        if (str_eq("default", argv[i]))
                                b = true;
                        else {
                                r = parse_ip_from_str(argv[i], &dst);
                                if (r < 0) {
                                        log_warning("Failed to parse route destination address '%s': %s", argv[2], strerror(-r));
                                        return r;
                                }
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "source") || str_eq_fold(argv[i], "src")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &source);
                        if (r < 0) {
                                log_warning("Failed to parse route source address '%s': %s", argv[2], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "pref-source") || str_eq_fold(argv[i], "pfsrc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &pref_source);
                        if (r < 0) {
                                log_warning("Failed to parse route preferred source address '%s': %s", argv[2], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "metric") || str_eq_fold(argv[i], "mt")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &metric);
                        if (r < 0) {
                                log_warning("Failed to parse route metric '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "ipv6-preference") || str_eq_fold(argv[i], "ipv6-pref")) {
                        parse_next_arg(argv, argc, i);

                        r = ipv6_route_preference_type_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse route IPv6 preference '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        rt_pref = r;
                        continue;
                } else if (str_eq_fold(argv[i], "protocol") || str_eq_fold(argv[i], "proto")) {
                        parse_next_arg(argv, argc, i);

                        protocol = route_protocol_to_mode(argv[i]);
                        if (r < 0) {
                                r = parse_int(argv[i], &protocol);
                                if (r < 0) {
                                        log_warning("Failed to parse route protocol '%s': %s", argv[i], strerror(-r));
                                        return r;
                                }

                                if (protocol == 0 || protocol > 255) {
                                        log_warning("Route protocol is out of rance [1-255] '%s': %s", argv[i], strerror(EINVAL));
                                        return -EINVAL;
                                }
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "type")) {
                        parse_next_arg(argv, argc, i);

                        r = route_type_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse route type '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        type = r;
                        continue;
                } else if (str_eq_fold(argv[i], "scope")) {
                        parse_next_arg(argv, argc, i);

                        r = route_scope_type_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse route scope '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        scope = r;
                        continue;
                } else if (str_eq_fold(argv[i], "table")) {
                        parse_next_arg(argv, argc, i);

                        table = route_table_to_mode(argv[i]);
                        if (table < 0) {
                                r = parse_int(argv[i], &table);
                                if (r < 0) {
                                        log_warning("Failed to parse route table '%s': %s", argv[i], strerror(-r));
                                        return r;
                                }
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "mtu")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_mtu(argv[i], &mtu);
                        if (r < 0) {
                                log_warning("Failed to parse route mtu '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "onlink")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse route onlink '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        onlink = r;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_configure_route(p, gw, dst, source , pref_source, rt_pref, protocol, scope, type, table, mtu, metric, onlink, b);
        if (r < 0) {
                log_warning("Failed to configure route on device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_ipv6(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *gw = NULL, *address = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int accept_ra = -1, dhcp = -1;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                       continue;
                } else if (str_eq_fold(argv[i], "accept-ra") || str_eq_fold(argv[i], "ara")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse accept-ra%s': %s", argv[2], strerror(-r));
                                return r;
                        }
                        accept_ra = r;
                        continue;
                } else if (str_eq_fold(argv[i], "dhcp")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse dhcp: %s", argv[i]);
                                return -EINVAL;
                        }
                        dhcp = r;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_ipv6(p, dhcp, accept_ra);
        if (r < 0) {
                log_warning("Failed to configure IPv4 on device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_set_ipv4(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *gw = NULL, *address = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int dhcp = -1;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "gateway") || str_eq_fold(argv[i], "gw")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &gw);
                        if (r < 0) {
                                log_warning("Failed to parse route gateway address '%s': %s", argv[2], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "address") || str_eq_fold(argv[i], "a") || str_eq_fold(argv[i], "addr")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &address);
                        if (r < 0) {
                                log_warning("Failed to parse route destination address '%s': %s", argv[2], strerror(-r));
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "dhcp")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse dhcp: %s", argv[i]);
                                return -EINVAL;
                        }

                        dhcp = r;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_set_ipv4(p, dhcp, address, gw);
        if (r < 0) {
                log_warning("Failed to configure IPv4 on device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_get_routes(char *ifname, char ***ret) {
        _cleanup_(routes_freep) Routes *route = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_strv_ char **s = NULL;
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        assert(ifname);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return r;

        r = netlink_get_one_link_route(p->ifindex, &route);
        if (r < 0)
                return r;

        if (set_size(route->routes) <= 0)
                return -ENODATA;

        while (g_hash_table_iter_next (&iter, &key, &value)) {
                Route *a = (Route *) g_bytes_get_data(key, &size);
                _auto_cleanup_ char *c = NULL;

                ip_to_str(a->family, &a->gw, &c);
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

                steal_ptr(c);
        }

        *ret = steal_ptr(s);
        return 0;
}

_public_ int ncm_link_delete_gateway_or_route(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (str_eq_fold(argv[0], "delete-gateway") || str_eq_fold(argv[0], "dgw"))
                r = manager_remove_gateway_or_route(p, true);
        else
                r = manager_remove_gateway_or_route(p, false);

        if (r < 0) {
                log_warning("Failed to delete route or gatwway '%s' on '%s': %s\n", argv[0], p->ifname, strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_add_additional_gw(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *a = NULL, *gw = NULL, *destination = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ Route *rt = NULL;
        uint32_t table = random() % 999;
        bool b = false;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "address") || str_eq_fold(argv[i], "addr") || str_eq_fold(argv[i], "a")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &a);
                        if (r < 0) {
                                log_warning("Failed to parse address '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "destination") || str_eq_fold(argv[i], "dest")) {
                        parse_next_arg(argv, argc, i);
                        if (str_eq("default", argv[i]))
                                b = true;
                        else {
                                r = parse_ip_from_str(argv[i], &destination);
                                if (r < 0) {
                                        log_warning("Failed to parse destination '%s': %s", argv[i], strerror(-r));
                                        return r;
                                }
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "gw")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &gw);
                        if (r < 0) {
                                log_warning("Failed to parse gateway '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "table")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &table);
                        if (r < 0) {
                                log_warning("Failed to parse table '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = route_new(&rt);
        if (r < 0)
                return log_oom();

        *rt = (Route) {
                .family = a->family,
                .ifindex = p->ifindex,
                .table = table,
                .to_default = b,
                .gw = *gw,
        };

        if (destination) {
                rt->dst_prefixlen = destination->prefix_len;
                rt->dst = *destination;
        }

        r = manager_configure_additional_gw(p, a, rt);
        if (r < 0) {
                log_warning("Failed to add route to device '%s': %s\n", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_add_routing_policy_rules(int argc, char *argv[]) {
        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *rule = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = routing_policy_rule_new(&rule);
        if (r < 0)
                return log_oom();

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "iif")) {
                        _auto_cleanup_ IfNameIndex *idx = NULL;

                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &idx);
                        if (r < 0) {
                                log_warning("Failed to find device '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        rule->iif = strdup(idx->ifname);

                        continue;
                } else if (str_eq_fold(argv[i], "oif")) {
                        _auto_cleanup_ IfNameIndex *idx = NULL;

                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &idx);
                        if (r < 0) {
                                log_warning("Failed to find device '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        rule->oif = strdup(idx->ifname);
                        continue;
                } if (str_eq_fold(argv[i], "from")) {
                         _auto_cleanup_ IPAddress *a = NULL;

                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &a);
                        if (r < 0) {
                                log_warning("Failed to parse from address '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        rule->from = *a;
                        continue;
                } if (str_eq_fold(argv[i], "to")) {
                         _auto_cleanup_ IPAddress *a = NULL;

                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &a);
                        if (r < 0) {
                                log_warning("Failed to parse ntp address '%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        rule->to = *a;

                        continue;
                } if (str_eq_fold(argv[i], "table")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &rule->table);
                        if (r < 0) {
                                log_warning("Failed to parse table '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        continue;
                } if (str_eq_fold(argv[i], "prio")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &rule->priority);
                        if (r < 0) {
                                log_warning("Failed to parse priority '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        continue;
                } if (str_eq_fold(argv[i], "tos")) {
                        uint32_t k;

                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &k);
                        if (r < 0) {
                                log_warning("Failed to parse tos '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        if (k == 0 || k > 255) {
                                log_warning("TOS is out of range '%s': %s", strerror(EINVAL), argv[i]);
                                return -EINVAL;
                        }
                        rule->tos = k;
                        continue;
                } else if (str_eq_fold(argv[i], "invert")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse invert '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        rule->invert_rule = r;

                        continue;
                } else if (str_eq_fold(argv[i], "sport")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_port_or_range(argv[i])) {
                                log_warning("Failed to parse sport '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        rule->sport_str = strdup(argv[i]);
                        if (!rule->sport_str)
                                return log_oom();

                        continue;
                } else if (str_eq_fold(argv[i], "dport")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_port_or_range(argv[i])) {
                                log_warning("Failed to parse dport '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        rule->dport_str = strdup(argv[i]);
                        if (!rule->dport_str)
                                return log_oom();

                        continue;
                } else if (str_eq_fold(argv[i], "proto")) {
                        parse_next_arg(argv, argc, i);

                        rule->ipproto_str = strdup(argv[i]);
                        if (!rule->ipproto_str)
                                return log_oom();

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_configure_routing_policy_rules(p, rule);
        if (r < 0) {
                log_warning("Failed to configure routing policy rules: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_remove_routing_policy_rules(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_remove_routing_policy_rules(p);
        if (r < 0) {
                log_warning("Failed to remove routing policy rules: %s", strerror(-r));
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

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "dns")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &dns);
                        if (r < 0) {
                                log_warning("Failed to parse dns address '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "ntp")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &ntp);
                        if (r < 0) {
                                log_warning("Failed to parse ntp address '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "pool-offset")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &pool_offset);
                        if (r < 0) {
                                log_warning("Failed to parse pool offset '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "pool-size")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &pool_size);
                        if (r < 0) {
                                log_warning("Failed to parse pool size '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "default-lease-time")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &default_lease_time);
                        if (r < 0) {
                                log_warning("Failed to parse default lease time '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "max-lease-time")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &max_lease_time);
                        if (r < 0) {
                                log_warning("Failed to parse maximum lease time '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "emit-dns")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse emit dns '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        emit_dns = r;
                        continue;
                } else if (str_eq_fold(argv[i], "emit-ntp")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse emit ntp '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        emit_ntp = r;
                        continue;
                } else if (str_eq_fold(argv[i], "emit-router")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse emit router '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        emit_router = r;
                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_configure_dhcpv4_server(p, dns, ntp, pool_offset, pool_size, default_lease_time, max_lease_time,
                                            emit_dns, emit_ntp, emit_router);
        if (r < 0) {
                log_warning("Failed to configure DHCPv4 server on device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_remove_dhcpv4_server(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_remove_dhcpv4_server(p);
        if (r < 0) {
                log_warning("Failed to remove DHCPv4 server on device '%s': %s\n", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_add_dhcpv4_server_static_address(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *addr = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *mac = NULL;
        bool have_mac = false;
        bool have_address = false;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "mac")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_ether_address(argv[i])) {
                                log_warning("Failed to parse MAC address: %s", argv[2]);
                                return -EINVAL;
                        }
                        mac = strdup(argv[i]);
                        if (!mac)
                                return log_oom();

                        have_mac = true;
                        continue;
                } else if (str_eq_fold(argv[i], "a") || str_eq_fold(argv[i], "addr") || str_eq_fold(argv[i], "address")){
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &addr);
                        if (r < 0) {
                                log_warning("Failed to parse IPv4 address '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }


                        have_address = true;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_mac) {
                log_warning("Failed to parse MAC address: %s", strerror(-r));
                return -EINVAL;
        }

        if (!have_address) {
                log_warning("Failed to parse IP address: %s", strerror(-r));
                return -EINVAL;
        }

        r = manager_add_dhcpv4_server_static_address(p, addr, mac);
        if (r < 0) {
                log_warning("Failed to add static lease: %s", strerror(-r));
                return -EINVAL;
        }

        return 0;
}

_public_ int ncm_link_remove_dhcpv4_server_static_address(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *addr = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *mac = NULL;
        bool have_mac = false;
        bool have_address = false;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "mac")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_ether_address(argv[i])) {
                                log_warning("Failed to parse MAC address: %s", argv[2]);
                                return -EINVAL;
                        }
                        mac = strdup(argv[i]);
                        if (!mac)
                                return log_oom();

                        have_mac = true;
                        continue;
                } else if (str_eq_fold(argv[i], "a") || str_eq_fold(argv[i], "addr") || str_eq_fold(argv[i], "address")){
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &addr);
                        if (r < 0) {
                                log_warning("Failed to parse IPv4 address '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }


                        have_address = true;
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_mac && !have_address) {
                log_warning("Failed to parse MAC address or IP Address: %s", strerror(-r));
                return -EINVAL;
        }

        r = manager_remove_dhcpv4_server_static_address(p, addr, mac);
        if (r < 0) {
                log_warning("Failed to remove static lease: %s", strerror(-r));
                return -EINVAL;
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

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "prefix")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &prefix);
                        if (r < 0) {
                                log_warning("Failed to parse prefix address '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "route-prefix")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &route_prefix);
                        if (r < 0) {
                                log_warning("Failed to parse route prefix address '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "dns")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ip_from_str(argv[i], &dns);
                        if (r < 0) {
                                log_warning("Failed to parse dns address '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "domain")) {
                        parse_next_arg(argv, argc, i);

                        if (!valid_hostname(argv[i])) {
                                log_warning("Failed to parse domain '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        domain = strdup(argv[i]);
                        if (!domain)
                                log_oom();

                        continue;
                } else if (str_eq_fold(argv[i], "pref-lifetime") || str_eq_fold(argv[i], "plft")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &pref_lifetime);
                        if (r < 0) {
                                log_warning("Failed to parse pref-lifetime '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "valid-lifetime") || str_eq_fold(argv[i], "vlft")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &valid_lifetime);
                        if (r < 0) {
                                log_warning("Failed to parse valid-lifetime '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "route-lifetime") || str_eq_fold(argv[i], "rlft")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &route_lifetime);
                        if (r < 0) {
                                log_warning("Failed to parse default route-lifetime '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "dns-lifetime") || str_eq_fold(argv[i], "dlft")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &dns_lifetime);
                        if (r < 0) {
                                log_warning("Failed to parse default dns-lifetime '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "assign")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse assign '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        assign = r;
                        continue;
                } else if (str_eq_fold(argv[i], "managed")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse managed '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        managed = r;
                        continue;
                } else if (str_eq_fold(argv[i], "other")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse other '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        other = r;
                        continue;
                } else if (str_eq_fold(argv[i], "emit-dns")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse emit-dns '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        emit_dns = r;
                        continue;
                } else if (str_eq_fold(argv[i], "emit-domain")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse emit-domain '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        emit_domain = r;
                        continue;
                } else if (str_eq_fold(argv[i], "router-pref")) {
                        parse_next_arg(argv, argc, i);

                        r = ipv6_ra_preference_type_to_mode(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse router preference '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        preference = r;
                        continue;
                } else {

                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_configure_ipv6_router_advertisement(p, prefix, route_prefix, dns, domain, pref_lifetime, valid_lifetime,
                                                        dns_lifetime, route_lifetime, preference, managed, other, emit_dns, emit_domain, assign);
        if (r < 0) {
                log_warning("Failed to configure IPv6 RA on device '%s': %s\n", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_remove_ipv6_router_advertisement(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_remove_ipv6_router_advertisement(p);
        if (r < 0) {
                log_warning("Failed to remove IPv6 router advertisement on device '%s': %s\n", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_get_dns_mode(int argc, char *argv[]) {
        _auto_cleanup_ char *network = NULL, *c4 = NULL, *c6 = NULL, *c = NULL;
        _auto_cleanup_strv_ char **dns_config = NULL, **dns_lease = NULL;
        bool dhcpv4 = true, dhcpv6 = true, static_dns = false;
        _cleanup_(dns_servers_freep) DNSServers *dns = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        DHCPClient mode = DHCP_CLIENT_NO;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = network_parse_link_network_file(p->ifindex, &network);
        if (r < 0)
                return r;

        r = manager_acquire_link_dhcp_client_kind(p, &mode);
        if (r < 0 && r != -ENOENT) {
                log_warning("Failed to parse 'DHCP=' : %s",  strerror(-r));
                return r;
        }

        if (mode == DHCP_CLIENT_NO) {
                dhcpv6 = false;
                dhcpv4 = false;
        }

        r = parse_config_file(network, "Network", "DNS", &c);
        if (r < 0 && r != -ENOENT) {
                log_warning("Failed to parse 'DNS=' :%s",  strerror(-r));
                return r;
        }

        if (!isempty_str(c))
                static_dns = true;

        r = parse_config_file(network, "DHCPv4", "UseDNS", &c4);
        if (r >= 0) {
                r = parse_bool(c4);
                if (r >= 0)
                        dhcpv4 = r;
        }

        r = parse_config_file(network, "DHCPv6", "UseDNS", &c6);
        if (r >= 0) {
                r = parse_bool(c6);
                if (r >= 0)
                        dhcpv6 = r;
        }

        if (json_enabled())
                return json_acquire_dns_mode(mode, dhcpv4, dhcpv6, static_dns);

        display(beautify_enabled() ? true : false, ansi_color_bold_blue(),"DNS Mode: ");

        if ((dhcpv4 || dhcpv6) && static_dns)
                printf("merged\n");
        else {
                if (static_dns)
                        printf("static\n");
                else if ((dhcpv4 || dhcpv6) && (mode == DHCP_CLIENT_YES || mode == DHCP_CLIENT_IPV4 || mode == DHCP_CLIENT_IPV6))
                        printf("DHCP\n");
                else
                        printf("foreign\n");
        }

        return 0;
}

_public_ int ncm_show_dns_server(int argc, char *argv[]) {
        _cleanup_(dns_servers_freep) DNSServers *fallback = NULL, *dns = NULL;
        _cleanup_(json_object_putp) json_object *jobj = NULL;
        _auto_cleanup_strv_ char **dns_config = NULL;
        _auto_cleanup_ DNSServer *current = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        char buf[IF_NAMESIZE + 1] = {};
        GSequenceIter *itr;
        DNSServer *d;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (p)
                (void) manager_parse_link_dns_servers(p, &dns_config);
        else
                (void) manager_acquire_all_link_dns(&dns_config);

        r = json_acquire_and_parse_network_data(&jobj);
        if (r < 0 && json_enabled()) {
                r = json_build_dns_server(p, dns_config, 0);
                if (r < 0) {
                        log_warning("Failed acquire DNS servers: %s", strerror(-r));
                        return r;
                }

                return 0;
        } else if (json_enabled())
                return json_fill_dns_server(p, dns_config, 0, jobj);

        r = dbus_acquire_dns_servers_from_resolved("DNS", &dns);
        if (r >= 0 && dns && !g_sequence_is_empty(dns->dns_servers)) {
                display(beautify_enabled() ? true : false, ansi_color_bold_cyan(), "             DNS: ");

                for (itr = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(itr); itr = g_sequence_iter_next(itr)) {
                        _auto_cleanup_ char *pretty = NULL;

                        d = g_sequence_get(itr);
                        if (!d->ifindex)
                                continue;

                        r = ip_to_str(d->address.family, &d->address, &pretty);
                        if (r >= 0)
                                printf("%s ", str_strip(pretty));
                }
                printf("\n");
        }

        r = dbus_get_current_dns_server_from_resolved(&current);
        if (r >= 0 && current) {
                _auto_cleanup_ char *pretty = NULL;

                r = ip_to_str(current->address.family, &current->address, &pretty);
                if (r >= 0) {
                        display(beautify_enabled(), ansi_color_bold_cyan(), "CurrentDNSServer:");
                        printf(" %s\n", pretty);
                }
        }

        r = dbus_acquire_dns_servers_from_resolved("FallbackDNS", &fallback);
        if (r >= 0 && !g_sequence_is_empty(fallback->dns_servers)) {

                display(beautify_enabled(), ansi_color_bold_cyan(), "     FallbackDNS: ");
                for (itr = g_sequence_get_begin_iter(fallback->dns_servers); !g_sequence_iter_is_end(itr); itr = g_sequence_iter_next(itr)) {
                        _auto_cleanup_ char *pretty = NULL;

                        d = g_sequence_get(itr);

                        r = ip_to_str(d->address.family, &d->address, &pretty);
                        if (r >= 0)
                                printf("%s ", pretty);

                }
                printf("\n\n");
        }

        if (dns && !g_sequence_is_empty(dns->dns_servers)) {
                if (beautify_enabled())
                        printf("%5s %-20s %-14s\n", "INDEX", "LINK", "DNS");

                for (itr = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(itr); itr = g_sequence_iter_next(itr)) {
                        _auto_cleanup_ char *pretty = NULL;

                        d = g_sequence_get(itr);

                        if (!d->ifindex)
                                continue;

                        if_indextoname(d->ifindex, buf);
                        r = ip_to_str(d->address.family, &d->address, &pretty);
                        if (r >= 0)
                                printf("%5d %-16s %s\n", d->ifindex, buf, pretty);
                }
        }

        return 0;
}

_public_ int ncm_show_dns_servers_and_mode(int argc, char *argv[]) {
        _cleanup_(dns_servers_freep) DNSServers *dns = NULL;
        _cleanup_(json_object_putp) json_object *jobj = NULL;
        _auto_cleanup_strv_ char **dns_config = NULL;
        _auto_cleanup_ DNSServer *current = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        GSequenceIter *itr;
        DNSServer *d;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_parse_link_dns_servers(p, &dns_config);
        if (r < 0)
                dns_config = NULL;
        else
                /* Read all links managed by networkd and parse DNS= */
                manager_acquire_all_link_dns(&dns_config);

        r = json_acquire_and_parse_network_data(&jobj);
        if (r < 0) {
                log_warning("Failed acquire network data: %s", strerror(-r));
                return r;
        }

        if (json_enabled())
                return json_fill_dns_server(p, dns_config, p->ifindex, jobj);

        r = dbus_acquire_dns_servers_from_resolved("DNS", &dns);
        if (r >= 0 && dns && !g_sequence_is_empty(dns->dns_servers)) {

                for (itr = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(itr); itr = g_sequence_iter_next(itr)) {
                        _auto_cleanup_ char *pretty = NULL;
                        d = g_sequence_get(itr);
                        if (!d->ifindex)
                                continue;

                        r = ip_to_str(d->address.family, &d->address, &pretty);
                        if (r >= 0) {
                                static bool first = true;
                                if(first) {
                                        display(beautify_enabled() ? true : false, ansi_color_bold_cyan(), "      DNSServers: ");
                                        printf("%s ", str_strip(pretty));
                                        first = false;
                                } else
                                        printf("                  %s ", str_strip(pretty));

                                if (dns_config && strv_contains((const char **) dns_config, pretty))
                                        display(beautify_enabled() ? true : false, ansi_color_bold_blue(), "(static) \n");
                                else
                                        display(beautify_enabled() ? true : false, ansi_color_bold_blue(), "(DHCPv4) \n");
                        }
                }
                printf("\n");
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

                r = ip_to_str(d->address.family, &d->address, &k);
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

                steal_ptr(k);
        }

        *ret = steal_ptr(s);
        return 0;
}

_public_ int ncm_add_dns_server(int argc, char *argv[]) {
        _cleanup_(dns_servers_freep) DNSServers *dns = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_strv_ char **d = NULL;
        bool system = false, global = false;
        char **s;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "system"))
                        system = true;

                else if (str_eq_fold(argv[i], "global"))
                        global = true;

                if (str_eq_fold(argv[i], "dns")) {
                        parse_next_arg(argv, argc, i);

                        r = argv_to_strv(argc - 4, argv + i, &d);
                        if (r < 0) {
                                log_warning("Failed to parse dns addresses: %s", strerror(-r));
                                return r;
                        }
                }
        }

        if (!d || strv_length(d) <= 0) {
                log_warning("Failed to parse dns addresses: %s", strerror(EINVAL));
                return -EINVAL;
        }

        strv_foreach(s, d) {
                _auto_cleanup_ IPAddress *a = NULL;
                _auto_cleanup_ DNSServer *t = NULL;

                r = parse_ip(*s, &a);
                if (r < 0) {
                        log_warning("Failed to parse DNS server address: %s", *s);
                        return r;
                }

                r = dns_server_new(&t);
                if (r < 0)
                        return log_oom();

                *t = (DNSServer) {
                        .ifindex = p ? p->ifindex : 0,
                        .address = *a,
                };

                r = dns_server_add(&dns, t);
                if (r < 0) {
                        log_warning("Failed to add DNS server address: %s", *s);
                        return r;
                }

                steal_ptr(t);
        }

        r = manager_add_dns_server(p, dns, system, global);
        if (r < 0) {
                log_warning("Failed to add DNS server %s: %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_set_dns_server(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *dns = NULL;
        int ipv4 = -1, ipv6 = -1;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                } else if (str_eq_fold(argv[i], "dns")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse DNS servers '%s': %s", argv[i], strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        _auto_cleanup_ IPAddress *a = NULL;

                                        r = parse_ip(*d, &a);
                                        if (r < 0) {
                                                log_warning("Failed to parse DNS server address: %s", *d);
                                                return r;
                                        }
                                }

                                dns = strv_join(" ", s);
                                if (!dns)
                                        return log_oom();
                        }
                } else if (str_eq_fold(argv[i], "use-dns-ipv4")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse use-dns-ipv4='%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        ipv4 = r;

                        continue;
                } else if (str_eq_fold(argv[i], "use-dns-ipv6")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse use-dns-ipv6='%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        ipv6 = r;
                        continue;
                }
        }

        r = manager_set_dns_server(p, dns, ipv4, ipv6);
        if (r < 0) {
                log_warning("Failed to set DNS config %s: %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_remove_dns_server(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        return manager_remove_dns_server(p);
}

_public_ int ncm_add_dns_domains(int argc, char *argv[]) {
        _auto_cleanup_strv_ char **domains = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool system = false, global = false;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "system"))
                        system = true;

                else if (str_eq_fold(argv[i], "global"))
                        global = true;

                if (str_eq_fold(argv[i], "domains")) {
                        parse_next_arg(argv, argc, i);

                        r = argv_to_strv(argc - 4, argv + i, &domains);
                        if (r < 0) {
                                log_warning("Failed to parse domains addresses: %s", strerror(-r));
                                return r;
                        }
                }

        }

        if (!domains && strv_length(domains) <= 0) {
                log_warning("Failed to parse domains: %s", strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_add_dns_server_domain(p, domains, system, global);
        if (r < 0) {
                log_warning("Failed to add DNS domain to resolved: %s", strerror(-r));
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
                return json_fill_dns_server_domains();

        if (argc > 1 && str_eq_fold(argv[1], "system")) {
                r = parse_ifname_or_index(argv[1], &p);
                if (r < 0) {
                        log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                        return r;
                }

                r = network_parse_link_setup_state(p->ifindex, &setup);
                if (r < 0) {
                        log_warning("Failed to get device setup '%s': %s\n", p->ifname, strerror(-r));
                        return r;
                }

                if (str_eq_fold(setup, "unmanaged")) {
                       _auto_cleanup_strv_ char **a = NULL, **b = NULL;
                        char **j;

                        r = dns_read_resolv_conf(&a, &b);
                        if (r < 0) {
                                log_warning("Failed to read resolv.conf: %s", strerror(-r));
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

        if (argc >= 2 && str_eq_fold(argv[1], "system")) {
                r = manager_read_domains_from_system_config(&config_domain);
                if (r < 0) {
                        log_warning("Failed to read DNS domain from '/etc/systemd/resolved.conf': %s", strerror(-r));
                        return r;
                }

                printf("%s\n", config_domain);
                return 0;
        }

        r = dbus_acquire_dns_domains_from_resolved(&domains);
        if (r < 0){
                log_warning("Failed to fetch DNS domain from resolved: %s", strerror(-r));
                return r;
        }

        if (!domains || g_sequence_is_empty(domains->dns_domains)) {
                log_warning("No DNS Domain configured: %s", strerror(ENODATA));
                return -ENODATA;
        } else if (g_sequence_get_length(domains->dns_domains) == 1) {

                i = g_sequence_get_begin_iter(domains->dns_domains);
                d = g_sequence_get(i);

                display(beautify_enabled(), ansi_color_bold_cyan(), "DNS Domain: ");
                printf("%s\n", d->domain);
        } else {
                _cleanup_(set_freep) Set *all_domains = NULL;

                r = set_new(&all_domains, NULL, NULL);
                if (r < 0) {
                        log_debug("Failed to init set for domains: %s", strerror(-r));
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
                                log_debug("Failed to add domain to set '%s': %s", d->domain, strerror(-r));
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
                                log_warning("Failed to find device '%d': %s", d->ifindex, strerror(-r));
                                return r;
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

                        steal_ptr(k);
                }

        *ret = steal_ptr(s);
        return 0;
}

_public_ int ncm_revert_resolve_link(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int dns = -1, domain = -1;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else if (str_eq_fold(argv[i], "dns")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse dns=%s: %s", argv[i], strerror(-r));
                                return r;
                        }
                        dns = r;
                        continue;
                } else if (str_eq_fold(argv[i], "domain")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse domain=%s: %s", argv[i], strerror(-r));
                                return r;
                        }
                        domain = r;
                        continue;
                }
                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (dns < 0 && domain < 0) {
                dns = true;
                domain = true;
        }

        r = manager_revert_dns_server_and_domain(p, dns, domain);
        if (r < 0) {
                log_warning("Failed to flush resolved settings for %s: %s", p->ifname, strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_show_ntp_servers(int argc, char *argv[]) {
        _cleanup_(json_object_putp) json_object *jobj = NULL, *jntp = NULL, *j = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        json_object *ja = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        r = json_acquire_and_parse_network_data(&jobj);
        if (r < 0) {
                log_warning("Failed acquire network data: %s", strerror(-r));
                return r;
        }

        r = json_fill_ntp_servers(jobj, p ? p->ifname : NULL, &jntp);
        if (r < 0 || !jntp) {
                log_warning("Failed acquire NTP servers: %s", strerror(-r));
                return r;
        }

        j = json_object_new_object();
        if (!j)
                return log_oom();

        json_object_object_add(j, "NTP", jntp);
        if (json_enabled() && jntp) {
                printf("%s\n", json_object_to_json_string_ext(j, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
                return 0;
        }

        if (!json_object_object_get_ex(j, "NTP", &ja))
                return -ENOENT;

        display(beautify_enabled() ? true : false, ansi_color_bold_cyan(), "      NTP Servers: ");
        for (size_t i = 0; i < json_object_array_length(ja); i++) {
                json_object *ntp = json_object_array_get_idx(ja, i);
                json_object *addr = NULL;

                if (!json_object_object_get_ex(ntp, "Address", &addr))
                        continue;

                printf("%s ", json_object_get_string(addr));
        }

        if (p)
                return 0;

        if (beautify_enabled())
                printf("\n%5s %-20s %-14s\n", "INDEX", "LINK", "NTP");

        for (size_t i = 0; i < json_object_array_length(ja); i++) {
                json_object *ntp = json_object_array_get_idx(ja, i);
                json_object *name = NULL, *addr = NULL;

                if (!json_object_object_get_ex(ntp, "Name", &name))
                        continue;

                if (p && !str_eq(p->ifname, json_object_get_string(name)))
                        continue;

                if (!json_object_object_get_ex(ntp, "Address", &addr))
                        continue;

                printf("%5d %-16s %-16s\n", if_nametoindex(json_object_get_string(name)), json_object_get_string(name), json_object_get_string(addr));
        }

        return 0;
}

_public_ int ncm_set_system_hostname(int argc, char *argv[]) {
        int r;

        if (isempty_str(argv[1])) {
                log_warning("Invalid hostname. Ignoring");
                return -EINVAL;
        }

        r = dbus_set_hostname(argv[1]);
        if (r < 0) {
                log_warning("Failed to set hostname '%s': %s", argv[1], strerror(-r));
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

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                } else if (str_eq_fold(argv[i], "ntp")) {
                        parse_next_arg(argv, argc, i);

                        r = argv_to_strv(argc - 4, argv + i, &ntps);
                        if (r < 0) {
                                log_warning("Failed to parse NTP addresses: %s", strerror(-r));
                                return r;
                        }
                }
        }

        if (!ntps && strv_length(ntps) <= 0) {
                log_warning("Failed to parse NTP: %s", strerror(EINVAL));
                return -EINVAL;
        }

        strv_foreach(d, ntps) {
                _auto_cleanup_ IPAddress *a = NULL;

                r = parse_ip(*d, &a);
                if (r < 0) {
                        log_warning("Failed to parse NTP server address: %s", *d);
                        return r;
                }
        }

       if (str_eq_fold(argv[0], "set-ntp"))
               r = manager_add_ntp_addresses(p, ntps, false);
       else
               r = manager_add_ntp_addresses(p, ntps, true);
       if (r < 0) {
               log_warning("Failed to add NTP addresses '%s': %s", argv[1], strerror(-r));
               return r;
       }

       return 0;
}

_public_ int ncm_link_delete_ntp(int argc, char *argv[]) {
       _auto_cleanup_ IfNameIndex *p = NULL;
       int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

       r = manager_remove_ntp_addresses(p);
       if (r < 0) {
               log_warning("Failed to delete NTP addresses '%s': %s", argv[1], strerror(-r));
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
                return r;

        r = network_parse_link_ntp(p->ifindex, &ntp);
        if (r < 0)
                return r;

        *ret = ntp;
        return 0;
}

_public_ int ncm_link_enable_ipv6(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int b = -1;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }

                        continue;
                }

                b = parse_bool(argv[i]);
                if (b < 0) {
                        log_warning("Failed to parse '%s': %s",  argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_enable_ipv6(p, b);
        if (r < 0) {
                log_warning("Failed to configure IPv6 for on device '%s': %s", p->ifname, strerror(EINVAL));
                return -EINVAL;
        }

        return 0;
}

_public_ int ncm_network_reload(int argc, char *argv[]) {
        return manager_reload_network();
}

_public_ int ncm_link_reconfigure(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                }
        }
        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }


        return manager_reconfigure_link(p);
}

_public_ int ncm_link_show_network_config(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *config = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                 } else {
                         r = parse_ifname_or_index(argv[i], &p);
                         if (r < 0)
                                 continue;
                         break;
                }
        }
        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_show_link_network_config(p, &config);
        if (r < 0) {
                log_warning("Failed to show network configuration of device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        printf("%s\n", config);
        return 0;
}

_public_ int ncm_link_edit_network_config(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else {
                         r = parse_ifname_or_index(argv[i], &p);
                         if (r < 0)
                                 continue;
                         break;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_edit_link_network_config(p);
        if (r < 0) {
                log_warning("Failed to edit network configuration of device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_link_edit_link_config(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;
                } else {
                         r = parse_ifname_or_index(argv[i], &p);
                         if (r < 0)
                                 continue;
                         break;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        r = manager_edit_link_config(p);
        if (r < 0) {
                log_warning("Failed to edit link configuration of device '%s': %s", argv[1], strerror(-r));
                return r;
        }

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

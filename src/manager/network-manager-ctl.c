/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <getopt.h>
#include <network-config-manager.h>

#include "alloc-util.h"
#include "ctl.h"
#include "log.h"
#include "macros.h"
#include "network-manager.h"

static int generate_networkd_config_from_yaml(int argc, char *argv[]) {
        _cleanup_(g_dir_closep) GDir *dir = NULL;
        const char *file = NULL;
        int r;

        if (string_equal(argv[0], "apply-yaml-config")) {
                dir = g_dir_open("/etc/network-config-manager/yaml", 0, NULL);
                if (!dir) {
                        log_warning("Failed to open directory '/etc/network-config-manager/yaml': %m");
                        return -errno;
                }

                for (;;) {
                        _auto_cleanup_ char *path = NULL;

                        file = g_dir_read_name(dir);
                        if (!file)
                                break;

                        path = g_build_path("/", "/etc/network-config-manager/yaml", file, NULL);
                        if (!path)
                                return log_oom();

                        r = manager_generate_network_config_from_yaml(path);
                        if (r < 0)
                                return r;
                }
        } else {
                for (int i = 1; i < argc; i++) {
                        r = manager_generate_network_config_from_yaml(argv[i]);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int generate_networkd_config_from_command_line(int argc, char *argv[]) {
        _auto_cleanup_ char *argv_line = NULL;
        int r;

        if (argc <= 1)
                r = manager_generate_networkd_config_from_command_line("/proc/cmdline", NULL);
        else {
                argv_line = strv_join(" ", ++argv);
                if (!argv_line)
                        return log_oom();

                r = manager_generate_networkd_config_from_command_line(NULL, argv_line);
        }

        return r;
}

static bool runs_without_networkd(char *c) {
        _cleanup_(g_hash_table_unrefp) GHashTable *h = NULL;
        const char *cli_commands[] = {
                "generate-config-from-yaml",
                "apply-yaml-config",
                "generate-config-from-cmdline",
                "add-nft-table",
                "show-nft-tables",
                "delete-nft-table",
                "add-nft-chain",
                "show-nft-chains",
                "delete-nft-chain",
                "add-nft-rule",
                "show-nft-rules",
                "delete-nft-rule",
                "nft-run"
        };

        h = g_hash_table_new(g_str_hash, g_str_equal);
        if (!h) {
                log_oom();
                return false;
        }

        for (size_t i = 0; i < ELEMENTSOF(cli_commands); i++)
                if (!g_hash_table_insert(h, (gpointer *) cli_commands[i], (gpointer *) c))
                        continue;

        if (g_hash_table_lookup(h, c))
                return true;

        return false;
}

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Query and control the netmanager subsystem.\n\n"
               "  -h --help                    Show this help message and exit\n"
               "  -v --version                 Show package version\n"
               "  -j --json                    Show in JSON format\n"
               "  -b --no-beautify             Show without colors and headers\n"
               "\nCommands:\n"
               "  status                       [LINK] Show system or link status\n"
               "  status-links                 List links.\n"
               "  status-link                  [LINK] Show link status.\n"
               "  set-mtu                      [LINK] [MTU NUMBER] Configures Link MTU.\n"
               "  set-mac                      [LINK] [MAC] Configures Link MAC address.\n"
               "  set-link-mode                [LINK] [MODE BOOLEAN] Configures Link managed by networkd.\n"
               "  set-link-option              [LINK] [arp BOOLEAN] [mc BOOLEAN] [amc BOOLEAN] [pcs BOOLEAN] [rfo BOOLEAN] Configures Link arp, multicast, allmulticast, promiscuous and requiredforonline managed by networkd.\n"
               "  set-link-group               [LINK] [GROUP NUMBER] Configures Link Group.\n"
               "  set-link-rf-online           [LINK] [GROUP NUMBER] Configures Link RequiredFamilyForOnline.\n"
               "  set-link-act-policy          [LINK] [GROUP NUMBER] Configures Link ActivationPolicy.\n"
               "  set-dhcp-mode                [LINK] [DHCP-MODE {yes|no|ipv4|ipv6}] Configures Link DHCP setting.\n"
               "  set-dhcp4-client-identifier  [LINK] [IDENTIFIER {mac|duid|duid-only} Configures Link DHCPv4 identifier.\n"
               "  set-dhcp-iaid                [LINK] [IAID] Configures the DHCP Identity Association Identifier (IAID) for the interface, a 32-bit unsigned integer.\n"
               "  set-dhcp-duid                [LINK | system] [DUID {link-layer-time|vendor|link-layer|uuid}] [RAWDATA] Sets the DHCP Client.\n"
               "                                      Specifies how the DUID should be generated and [RAWDATA] to overides the global DUIDRawData.\n"
               "  set-link-state               [LINK] [STATE {up|down}] Configures Link State.\n"
               "  add-link-address             [LINK] address [ADDRESS] peer [ADDRESS]] label [NUMBER] pref-lifetime [{forever|infinity|0}] scope {global|link|host|NUMBER}]"
                                                      "\n\t\t\t\t      dad [DAD {none|ipv4|ipv6|both}] prefix-route [PREFIXROUTE BOOLEAN] Configures Link Address.\n"
               "  delete-link-address          [LINK] address [ADDRESS] Removes Address from Link.\n"
               "  add-default-gateway          [LINK] gw [GATEWAY ADDRESS] onlink [ONLINK BOOLEAN] Configures Link Default Gateway.\n"
               "  delete-gateway               [LINK] Removes Gateway from Link.\n"
               "  add-route                    [LINK] gw [GATEWAY ADDRESS] dest [DESTINATION ADDRESS] src [SOURCE ADDRESS] pref-src [PREFFREDSOURCE ADDRESS]"
                                                     "\n\t\t\t\t      metric [METRIC NUMBER] scope [SCOPE {global|site|link|host|nowhere}] mtu [MTU NUMBER]"
                                                     "\n\t\t\t\t      table [TABLE {default|main|local|NUMBER}] proto [PROTOCOL {boot|static|ra|dhcp|NUMBER}]"
                                                     "\n\t\t\t\t      type [TYPE {unicast|local|broadcast|anycast|multicast|blackhole|unreachable|prohibit|throw|nat|resolve}]"
                                                     "\n\t\t\t\t      ipv6-pref [IPV6PREFERENCE {low|medium|high}] onlink [{ONLINK BOOLEN}] Configures Link route.\n"
               "  delete-route                 [LINK] Removes route from Link\n"
               "  add-additional-gw            [LINK] address [ADDRESS] destination [DESTINATION address] gw [GW address] table [TABLE routing policy table NUMBER] Configures additional"
                                                      "\n\t\t\t\t      gateway for another NIC with routing policy rules.\n"
               "  add-rule                     [LINK] table [TABLE NUMBER] from [ADDRESS] to [ADDRESS] oif [LINK] iif [LINK] priority [NUMBER] tos [NUMBER]"
                                                      "\n\t\t\t\t      Configures Routing Policy Rule.\n"
               "  remove-rule                  [LINK] Removes Routing Policy Rule.\n"
               "  set-hostname                 [HOSTNAME] Configures hostname.\n"
               "  show-dns                            Show DNS Servers.\n"
               "  add-dns                      [LINK|global|system] [ADDRESS] Configures Link or global DNS servers.\n"
               "  add-domain                   [LINK|global|system] [DOMAIN] Configures Link or global Domain.\n"
               "  show-domains                        Show DNS Server Domains.\n"
               "  revert-resolve-link          [LINK] Flushes all DNS server and Domain settings of the link.\n"
               "  set-link-local-address       [LINK] [LinkLocalAddressing BOOLEAN] Configures Link link-local address auto configuration.\n"
               "  set-ipv4ll-route             [LINK] [IPv4LLRoute BOOLEAN] Configures the route needed for non-IPv4LL hosts to communicate.\n"
               "                                      with IPv4LL-only hosts.\n"
               "  set-llmnr                    [LINK] [LLMNR BOOLEAN] Configures Link Local Multicast Name Resolution.\n"
               "  set-multicast-dns            [LINK] [MulticastDNS BOOLEAN] Configures Link Multicast DNS.\n"
               "  set-lldp                     [LINK] [LLDP BOOLEAN] Configures Link Ethernet LLDP packet reception.\n"
               "  set-emit-lldp                [LINK] [EmitLLDP BOOLEAN] Configures Link Ethernet LLDP packet emission.\n"
               "  set-ipforward                [LINK] [IPForward BOOLEAN] Configures Link IP packet forwarding for the system.\n"
               "  set-ipv6acceptra             [LINK] [IPv6AcceptRA BOOLEAN] Configures Link IPv6 Router Advertisement (RA) reception support for the interface.\n"
               "  set-ipv6mtu                  [LINK] [MTU NUMBER] Configures IPv6 maximum transmission unit (MTU).\n"
               "  set-ipmasquerade             [LINK] [IPMasquerade BOOLEAN] Configures IP masquerading for the network interface.\n"
               "  set-ipv4proxyarp             [LINK] [IPv4ProxyARP BOOLEAN] Configures Link proxy ARP for IPv4.\n"
               "  set-ipv6proxyndp             [LINK] [IPv6ProxyNDP BOOLEAN] Configures Link proxy NDP for IPv6.\n"
               "  set-conf-without-carrier     [LINK] [ConfigureWithoutCarrier BOOLEAN] Allows networkd to configure link even if it has no carrier.\n"
               "  set-dhcp4-use-dns            [LINK] [UseDNS BOOLEAN] Configures Link DHCP4 Use DNS.\n"
               "  set-dhcp4-use-domains        [LINK] [UseDomains BOOLEAN] Configures Link DHCP4 Use Domains.\n"
               "  set-dhcp4-use-mtu            [LINK] [UseMTU BOOLEAN] Configures Link DHCP4 Use MTU.\n"
               "  set-dhcp4-use-ntp            [LINK] [UseNTP BOOLEAN] Configures Link DHCP4 Use NTP.\n"
               "  set-dhcp4-use-dns            [LINK] [UseDNS BOOLEAN] Configures Link DHCP4 Use DNS.\n"
               "  set-dhcp4-send-release       [LINK] [SendRelease BOOLEAN] When true, DHCPv4 client sends a DHCP release packet when it stops.\n"
               "  set-dhcp6-use-dns            [LINK] [UseDNS BOOLEAN] Configures Link DHCP6 Use DNS.\n"
               "  set-dhcp6-use-ntp            [LINK] [UseNTP BOOLEAN] Configures Link DHCP6 Use NTP.\n"
               "  add-ntp                      [LINK] [NTP] Add Link NTP server address. This option may be specified more than once.\n"
               "                                      This setting is read by systemd-timesyncd.service(8)\n"
               "  set-ntp                      [LINK] [NTP] Set Link NTP server address. This option may be specified more than once.\n"
               "                                      This setting is read by systemd-timesyncd.service(8).\n"
               "  delete-ntp                   [LINK] Delete Link NTP server addresses.\n"
               "                                      This setting is read by systemd-timesyncd.service(8).\n"
               "  add-dhcpv4-server            [LINK] pool-offset [PoolOffset NUMBER] pool-size [PoolSize NUMBER] default-lease-time [DefaultLeaseTimeSec NUMBER]"
                                                      "\n\t\t\t\t      max-lease-time [MaxLeaseTimeSec NUMBER] emit-dns [EmitDNS BOOLEAN]"
                                                      "\n\t\t\t\t      dns [DNS ADDRESS] emit-ntp [EmitNTP BOOLEAN] ntp [NTP ADDRESS]"
                                                      "\n\t\t\t\t      emit-router [EmitRouter BOOLEAN] Configures DHCPv4 server.\n"
               "  remove-dhcpv4-server         [LINK] Removes DHCPv4 server.\n"
               "  add-ipv6ra                   [LINK] prefix [Prefix ADDRESS] pref-lifetime [PreferredLifetimeSec NUMBER] valid-lifetime [ValidLifetimeSec NUMBER]"
                                                      "\n\t\t\t\t      assign [Assign BOOLEAN] managed [Managed BOOLEAN]"
                                                      "\n\t\t\t\t      other [Other BOOLEAN] dns [DNS ADDRESS] emit-dns [EmitDNS BOOLEAN]"
                                                      "\n\t\t\t\t      domain [DOMAIN ADDRESS] emit-domain [EmitDOMAIN BOOLEAN]"
                                                      "\n\t\t\t\t      router-pref [RouterPreference {low | med | high}]"
                                                      "\n\t\t\t\t      route [Prefix ADDRESS] route-lifetime [LifetimeSec NUMBER] Configures IPv6 Router Advertisement.\n"
               "  remove-ipv6ra                [LINK] Removes Ipv6 Router Advertisement.\n"
               "  disable-ipv6                 [LINK] Disables IPv6 on the link.\n"
               "  enable-ipv6                  [LINK] Enables IPv6 on the link.\n"
               "  create-vlan                  [VLAN name] dev [LINK MASTER] id [ID INTEGER] proto [PROTOCOL {802.1q|802.1ad}] Creates vlan netdev and network file\n"
               "  create-bridge                [BRIDGE name] [LINK] [LINK] ... Creates bridge netdev and sets master to device\n"
               "  create-bond                  [BOND name] mode [MODE {balance-rr|active-backup|balance-xor|broadcast|802.3ad|balance-tlb|balance-alb}]"
                                               "\n\t\t\t\t[LINK] [LINK] ... Creates bond netdev and sets master to device\n"
               "  create-vxlan                 [VXLAN name] [dev LINK] vni [INTEGER] [local ADDRESS] [remote ADDRESS] [port PORT] [independent BOOLEAN]."
                                               "\n\t\t\t\tCreates vxlan VXLAN (Virtual eXtensible Local Area Network) tunneling.\n"
               "  create-macvlan               [MACVLAN name] dev [LINK] mode [MODE {private|vepa|bridge|passthru|source}] Creates macvlan virtualized bridged networking.\n"
               "  create-macvtap               [MACVTAP name] dev [LINK] mode [MODE {private|vepa|bridge|passthru|source}] Creates macvtap virtualized bridged networking.\n"
               "  create-ipvlan                [IPVLAN name] dev [LINK] mode [MODE {l2|l3|l3s}] Creates ipvlan, virtual LAN, separates broadcast domains by adding tags to network"
                                                     "\n\t\t\t\t      packet.\n"
               "  create-ipvtap                [IPVTAP name] dev [LINK] mode [MODE {l2|l3|l3s}] Create ipvtap.\n"
               "  create-vrf                   [VRF name] table [INTEGER}] Creates Virtual routing and forwarding (VRF).\n"
               "  create-veth                  [VETH name] peer [PEER name}] Creates virtual Ethernet devices\n"
               "  create-ipip                  [IPIP name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates ipip tunnel.\n"
               "  create-sit                   [SIT name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates sit tunnel.\n"
               "  create-vti                   [VTI name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates vti tunnel.\n"
               "  create-gre                   [GRE name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates gre tunnel.\n"
               "  create-wg                    [WIREGUARD name] private-key [PRIVATEKEY] listen-port [PORT INTEGER] public-key [PUBLICKEY] preshared-key [PRESHAREDKEY]"
                                               "\n\t\t\t\t\t\t allowed-ips [IP,IP ...] endpoint [IP:PORT] Creates a wireguard tunnel.\n"
               "  remove-netdev                [LINK] kind [KIND {vlan|bridge|bond|vxlan|macvlan|macvtap|ipvlan|ipvtap|vrf|veth|ipip|sit|vti|gre|wg] \n"
               "                                      Removes .netdev and .network files.\n"
               "  reload                       Reload .network and .netdev files.\n"
               "  reconfigure                  [LINK] Reconfigure Link.\n"
               "  show-network-config          [LINK] Displays network configuration of link.\n"
               "  edit-network-config          [LINK] Edit network configuration of link.\n"
               "  set-link                     [LINK] [alias STRING] [desc STRING] [mtub STRING]  [bps STRING]  [duplex STRING] [wol STRING | List] [wolp STRING] [port STRING] [advertise STRING | List] \n"
                                                      "\t\t\t\tConfigure device's other parameters like mtubytes, bitspersecond, duplex, wakeonlan, wakeonlanpassword, port and advertise.\n"
               "  set-link-feature             [LINK] [auton BOOLEAN] [rxcsumo BOOLEAN]  [txcsumo BOOLEAN]  [tso BOOLEAN] [tso6 BOOLEAN] [gso BOOLEAN] [grxo BOOLEAN] [grxoh BOOLEAN] [lrxo BOOLEAN] [rxvtha BOOLEAN] [txvtha BOOLEAN] [rxvtf BOOLEAN] [txvstha BOOLEAN] [ntf BOOLEAN] [uarxc BOOLEAN] [uatxc BOOLEAN]\n"
                                                      "\t\t\t\tConfigure device's enable or disable features like autonegotiation, checksum offload, tcpsegmentation, genericoffload, largeoffload, vlantag acceleration, tuple filter, useadaptive coalesce.\n"
               "  set-link-mac                 [LINK] [macpolicy STRING | List]  [macaddr STRING]\n"
                                                      "\t\t\t\tConfigure device's macaddress policy or macaddress.\n"
               "  set-link-name                [LINK] [namepolicy STRING | List]  [name STRING]\n"
                                                      "\t\t\t\tConfigure device's name policy or name.\n"
               "  set-link-altname             [LINK] [altnamepolicy STRING | List]  [name STRING]\n"
                                                      "\t\t\t\tConfigure device's alternative name policy or alternative name.\n"
               "  set-link-buf                 [LINK] [rxbuf NUMBER | max] [rxminbuf NUMBER | max] [rxjumbobuf NUMBER | max] [txbuf NUMBER | max]\n"
                                                      "\t\t\t\tConfigure device's the maximum number of pending packets receive buffer. [1…4294967295 | \"max\"]\n"
               "  set-link-queue               [LINK] [rxq NUMBER] [txq NUMBER] [txqlen NUMBER]\n"
                                                      "\t\t\t\tConfigure devices's the maximum number or queue\n"
               "  set-link-flow-control        [LINK] [rxflowctrl BOOLEAN] [txflowctrl BOOLEAN] [autoflowctrl BOOLEAN]\n"
                                                      "\t\t\t\tConfigure device's the flow control\n"
               "  set-link-gso                 [LINK] [gsob NUMBER] [gsos NUMBER]\n"
                                                      "\t\t\t\tConfigure device's Generic Segment Offload (GSO)\n"
               "  set-link-channel             [LINK] [rxch NUMBER | max] [txch NUMBER | max] [otrch NUMBER | max] [combch NUMBER | max]\n"
                                                      "\t\t\t\tConfigure device's specifies the number of receive, transmit, other, or combined channels, respectively\n"
               "  set-link-coalesce            [LINK] [rxcs NUMBER | max] [rxcsirq NUMBER | max] [rxcslow NUMBER | max] [rxcshigh NUMBER | max] [txcs NUMBER | max] [txcsirq NUMBER | max] [txcslow NUMBER | max] [txcshigh NUMBER | max]\n"
                                                      "\t\t\t\tConfigure device's delay before Rx/Tx interrupts are generated after a packet is sent/received.\n"
               "  set-link-coald-frames        [LINK] [rxmcf NUMBER | max] [rxmcfirq NUMBER | max] [rxmcflow NUMBER | max] [rxmcfhigh NUMBER | max] [txmcf NUMBER | max] [txmcfirq NUMBER | max] [txmcflow NUMBER | max] [txmcfhigh NUMBER | max]\n"
                                                      "\t\t\t\tConfigure device's maximum number of frames that are sent/received before a Rx/Tx interrupt is generated.\n"
               "  set-link-coal-pkt            [LINK] [cprlow NUMBER | max] [cprhigh NUMBER | max] [cprsis NUMBER | max] [sbcs NUMBER | max]\n"
                                                      "\t\t\t\tConfigure device's low and high packet rate, sampleinterval packet rate and statistics block updates.\n"
               "  set-proxy                    [enable {BOOLEAN}] [http|https|ftp|gopher|socks|socks5|noproxy] [CONFIGURATION | none] Configure proxy.\n"
               "  show-proxy                   Shows proxy configuration.\n"
               "  generate-config-from-yaml    [FILE] Generates network file configuration from yaml file.\n"
               "  apply-yaml-config            Generates network file configuration from yaml files found in /etc/network-config-manager/yaml.\n"
               "  generate-config-from-cmdline [FILE | COMMAND LINE] Generates network file configuration from command kernel command line or command line.\n"
               "  add-nft-table                [FAMILY {ipv4|ipv6|ip}] [TABLE] adds a new table.\n"
               "  show-nft-tables              [FAMILY {ipv4|ipv6|ip}] shows nftable's tables.\n"
               "  delete-nft-table             [FAMILY {ipv4|ipv6|ip}] [TABLE] deletes a existing nftable's table.\n"
               "  add-nft-chain                [FAMILY {ipv4 |ip}] [TABLE] [CHAIN] adds a new nftable's chain.\n"
               "  show-nft-chains              [FAMILY {ipv4|ipv6|ip}] [TABLE] shows nftable's chains.\n"
               "  delete-nft-chain             [FAMILY {ipv4|ipv6|ip}] [TABLE] [CHAIN] deletes a nftable's chain from table\n"
               "  add-nft-rule                 [FAMILY {ipv4|ipv6|ip}] [TABLE] [CHAIN] [PROTOCOL {tcp|udp}] [SOURCE PORT/DESTINATION PORT {sport|dport}]"
                                                       "\n\t\t\t\t\t\t [PORT] [ACTION {accept | drop}] configures a nft rule for a port.\n"
               "  show-nft-rules               [TABLE] shows nftable's rules.\n"
               "  delete-nft-rule              [FAMILY {ipv4|ipv6|ip}] [TABLE] [CHAIN] [HANDLE] deletes a nftable's rule from table\n"
               "  nft-run                      runs a nft command. See man NFT(8)\n"
               , program_invocation_short_name
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'   },
                { "version",     no_argument,       NULL, 'v'   },
                { "json",        no_argument,       NULL, 'j'   },
                { "no-beautify", no_argument,       NULL, 'b'   },
                {}
        };
        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hv", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case 'v':
                        return ncm_show_version();
                case 'j':
                        set_json(true);
                        break;
                case 'b':
                        set_beautify(false);
                        break;
                case '?':
                        return -EINVAL;

                default:
                        assert(0);
                }
        }

        return 1;
}

static int cli_run(int argc, char *argv[]) {
        _cleanup_(ctl_unrefp) CtlManager *m = NULL;
        int r;

        static const Ctl commands[] = {
                { "status",                       WORD_ANY, WORD_ANY, true,  ncm_system_status },
                { "status-link",                  WORD_ANY, WORD_ANY, false, ncm_link_status },
                { "set-mtu",                      2,        WORD_ANY, false, ncm_link_set_mtu },
                { "set-mac",                      2,        WORD_ANY, false, ncm_link_set_mac },
                { "set-link-mode",                2,        WORD_ANY, false, ncm_link_set_mode },
                { "set-link-option",              2,        WORD_ANY, false, ncm_link_set_option },
                { "set-link-group",               2,        WORD_ANY, false, ncm_link_set_group },
                { "set-link-rf-online",           2,        WORD_ANY, false, ncm_link_set_rf_online },
                { "set-link-act-policy",          2,        WORD_ANY, false, ncm_link_set_act_policy },
                { "set-dhcp-mode",                2,        WORD_ANY, false, ncm_link_set_dhcp_mode },
                { "set-dhcp4-client-identifier",  2,        WORD_ANY, false, ncm_link_set_dhcp4_client_identifier},
                { "set-dhcp-iaid",                2,        WORD_ANY, false, ncm_link_set_dhcp_client_iaid},
                { "set-dhcp-duid",                2,        WORD_ANY, false, ncm_link_set_dhcp_client_duid},
                { "set-link-state",               2,        WORD_ANY, false, ncm_link_update_state },
                { "add-link-address",             2,        WORD_ANY, false, ncm_link_add_address },
                { "delete-link-address",          3,        WORD_ANY, false, ncm_link_delete_address },
                { "add-default-gateway",          2,        WORD_ANY, false, ncm_link_add_default_gateway },
                { "delete-gateway",               1,        WORD_ANY, false, ncm_link_delete_gateway_or_route },
                { "add-route",                    2,        WORD_ANY, false, ncm_link_add_route },
                { "delete-route",                 1,        WORD_ANY, false, ncm_link_delete_gateway_or_route },
                { "add-additional-gw",            9,        WORD_ANY, false, ncm_link_add_additional_gw },
                { "add-rule",                     3,        WORD_ANY, false, ncm_link_add_routing_policy_rules },
                { "remove-rule",                  1,        WORD_ANY, false, ncm_link_remove_routing_policy_rules },
                { "set-hostname",                 1,        WORD_ANY, false, ncm_set_system_hostname },
                { "show-dns",                     WORD_ANY, WORD_ANY, false, ncm_show_dns_server },
                { "add-dns",                      2,        WORD_ANY, false, ncm_add_dns_server },
                { "add-domain",                   1,        WORD_ANY, false, ncm_add_dns_domains },
                { "show-domains",                 WORD_ANY, WORD_ANY, false, ncm_show_dns_server_domains },
                { "revert-resolve-link",          1,        WORD_ANY, false, ncm_revert_resolve_link },
                { "set-ipv6mtu",                  2,        WORD_ANY, false, ncm_link_set_network_ipv6_mtu },
                { "set-link-local-address",       2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-ipv4ll-route",             2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-llmnr",                    2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-multicast-dns",            2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-lldp",                     2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-emit-lldp",                2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-ipforward",                2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-ipv6acceptra",             2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-ipmasquerade",             2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-ipv4proxyarp",             2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-ipv6proxyndp",             2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-conf-without-carrier",     2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-dhcp4-use-dns",            2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-use-domains",        2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-use-ntp",            2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-use-mtu",            2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-use-timezone",       2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-use-routes",         2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-send-release",       2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp6-use-dns",            2,        WORD_ANY, false, ncm_link_set_dhcp6_section },
                { "set-dhcp6-use-ntp",            2,        WORD_ANY, false, ncm_link_set_dhcp6_section },
                { "add-dhcpv4-server",            1,        WORD_ANY, false, ncm_link_add_dhcpv4_server },
                { "remove-dhcpv4-server",         1,        WORD_ANY, false, ncm_link_remove_dhcpv4_server },
                { "add-ipv6ra",                   1,        WORD_ANY, false, ncm_link_add_ipv6_router_advertisement },
                { "remove-ipv6ra",                1,        WORD_ANY, false, ncm_link_remove_ipv6_router_advertisement },
                { "add-ntp",                      2,        WORD_ANY, false, ncm_link_add_ntp },
                { "set-ntp",                      2,        WORD_ANY, false, ncm_link_add_ntp },
                { "delete-ntp",                   1,        WORD_ANY, false, ncm_link_delete_ntp },
                { "disable-ipv6",                 1,        WORD_ANY, false, ncm_link_enable_ipv6 },
                { "enable-ipv6",                  1,        WORD_ANY, false, ncm_link_enable_ipv6 },
                { "create-vlan",                  4,        WORD_ANY, false, ncm_create_vlan },
                { "create-bridge",                2,        WORD_ANY, false, ncm_create_bridge },
                { "create-bond",                  5,        WORD_ANY, false, ncm_create_bond },
                { "create-vxlan",                 2,        WORD_ANY, false, ncm_create_vxlan },
                { "create-macvlan",               5,        WORD_ANY, false, ncm_create_macvlan },
                { "create-macvtap",               5,        WORD_ANY, false, ncm_create_macvlan },
                { "create-ipvlan",                5,        WORD_ANY, false, ncm_create_ipvlan },
                { "create-ipvtap",                5,        WORD_ANY, false, ncm_create_ipvlan },
                { "create-vrf",                   3,        WORD_ANY, false, ncm_create_vrf },
                { "create-veth",                  3,        WORD_ANY, false, ncm_create_veth },
                { "create-ipip",                  3,        WORD_ANY, false, ncm_create_tunnel },
                { "create-sit",                   3,        WORD_ANY, false, ncm_create_tunnel },
                { "create-gre",                   3,        WORD_ANY, false, ncm_create_tunnel },
                { "create-vti",                   3,        WORD_ANY, false, ncm_create_tunnel },
                { "create-wg",                    3,        WORD_ANY, false, ncm_create_wireguard_tunnel },
                { "remove-netdev",                1,        WORD_ANY, false, ncm_remove_netdev },
                { "reload",                       WORD_ANY, WORD_ANY, false, ncm_network_reload },
                { "reconfigure",                  1,        WORD_ANY, false, ncm_link_reconfigure },
                { "show-network-config",          1,        WORD_ANY, false, ncm_link_show_network_config },
                { "edit-network-config",          1,        WORD_ANY, false, ncm_link_edit_network_config },
                { "set-link",                     2,        WORD_ANY, false, ncm_configure_link },
                { "set-link-feature",             2,        WORD_ANY, false, ncm_configure_link_features },
                { "set-link-mac",                 2,        WORD_ANY, false, ncm_configure_link_mac },
                { "set-link-name",                2,        WORD_ANY, false, ncm_configure_link_name },
                { "set-link-altname",             2,        WORD_ANY, false, ncm_configure_link_altname },
                { "set-link-buf",                 2,        WORD_ANY, false, ncm_configure_link_buf_size },
                { "set-link-queue",               2,        WORD_ANY, false, ncm_configure_link_queue_size },
                { "set-link-flow-control",        2,        WORD_ANY, false, ncm_configure_link_flow_control },
                { "set-link-gso",                 2,        WORD_ANY, false, ncm_configure_link_gso },
                { "set-link-channel",             2,        WORD_ANY, false, ncm_configure_link_channel },
                { "set-link-coalesce",            2,        WORD_ANY, false, ncm_configure_link_coalesce },
                { "set-link-coald-frames",        2,        WORD_ANY, false, ncm_configure_link_coald_frames },
                { "set-link-coal-pkt",            2,        WORD_ANY, false, ncm_configure_link_coal_pkt },
                { "set-proxy",                    1,        WORD_ANY, false, ncm_configure_proxy },
                { "show-proxy",                   WORD_ANY, WORD_ANY, false, ncm_show_proxy },
                { "generate-config-from-yaml",    1,        WORD_ANY, false, generate_networkd_config_from_yaml },
                { "apply-yaml-config"           , WORD_ANY, WORD_ANY, false, generate_networkd_config_from_yaml },
                { "generate-config-from-cmdline", WORD_ANY, WORD_ANY, false, generate_networkd_config_from_command_line },
                { "add-nft-table",                2,        WORD_ANY, false, ncm_nft_add_tables },
                { "show-nft-tables",              WORD_ANY, WORD_ANY, false, ncm_nft_show_tables },
                { "delete-nft-table",             2,        WORD_ANY, false, ncm_nft_delete_table },
                { "add-nft-chain",                3,        WORD_ANY, false, ncm_nft_add_chain },
                { "show-nft-chains",              WORD_ANY, WORD_ANY, false, ncm_nft_show_chains },
                { "delete-nft-chain",             3,        WORD_ANY, false, ncm_nft_delete_chain },
                { "add-nft-rule",                 7,        WORD_ANY, false, ncm_nft_add_rule_port },
                { "show-nft-rules",               1,        WORD_ANY, false, ncm_nft_show_rules },
                { "delete-nft-rule",              2,        WORD_ANY, false, ncm_nft_delete_rule },
                { "nft-run",                      WORD_ANY, WORD_ANY, false, ncm_nft_run_command },
                /* Deprecated */
                { "show",                         WORD_ANY, WORD_ANY, false, ncm_link_status },
                {}
        };

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (!isempty_string(argv[1]) && !runs_without_networkd(argv[1]))
                if (!ncm_is_netword_running())
                        exit(-1);

        r = ctl_manager_new(commands, &m);
        if (r < 0)
                return r;

        return ctl_run_command(m, argc, argv);
}

int main(int argc, char *argv[]) {
        g_log_set_default_handler (g_log_default_handler, NULL);

        return cli_run(argc, argv);
}

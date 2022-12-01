/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <getopt.h>
#include <network-config-manager.h>

#include "alloc-util.h"
#include "ctl-display.h"
#include "ctl.h"
#include "log.h"
#include "macros.h"
#include "network-manager.h"

static bool alias = false;

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
               "  -a --alias                   Show command alias\n"
               "\nCommands:\n"
               "  status                       [DEVICE] Show system or device status\n"
               "  status-devs                  List all devices.\n"
               "  set-mtu                      dev [DEVICE] mtu [MTU NUMBER] Configures device MTU.\n"
               "  set-mac                      dev [DEVICE] mac [MAC] Configures device MAC address.\n"
               "  set-manage                   dev [DEVICE] manage [MANAGE BOOLEAN] Configures whether device managed by networkd.\n"
               "  set-link-option              dev [DEVICE] [arp BOOLEAN] [mc BOOLEAN] [amc BOOLEAN] [pcs BOOLEAN]"
                                                     "\n\t\t\t\t\tConfigures device's arp, multicast, allmulticast and promiscuous.\n"
               "  set-link-group               dev [DEVICE] group [GROUP NUMBER] Configures device group.\n"
               "  set-link-rfo                 dev [DEVICE] f|family [ipv4|ipv6|both|any] Configures device required family for online.\n"
               "  set-link-ap                  dev [DEVICE] ap|act-policy [up|always-up|manual|always-down|down|bound] Configures device activation policy.\n"
               "  set-dhcp                     dev [DEVICE] dhcp [DHCP {yes|no|ipv4|ipv6}] Configures device DHCP kind client.\n"
               "  set-dhcp4-cid                dev [DEVICE] id [IDENTIFIER {mac|duid|duid-only} Configures device DHCPv4 identifier.\n"
               "  set-dhcp-iaid                dev [DEVICE] family|f iaid [IAID] Configures the DHCP Identity Association Identifier (IAID)\n"
               "  set-dhcp-duid                dev|system [DEVICE] family|f [ipv4|ipv6|4|6] duid [DUID {link-layer-time|vendor|link-layer|uuid}] data [RAWDATA]"
                                                      "\n\t\t\t\t      Sets DUID of DHCPv4 or DHCPv6 Client.\n"
               "  set-link-state               dev [DEVICE] [STATE {up|down}] Configures device State.\n"
               "  show-addr                    dev [DEVICE] [family|f ipv4|ipv6|4|6] Show device addresses\n"
               "  add-addr                     dev [DEVICE] address|a|addr [ADDRESS] peer [ADDRESS]] label [STRING] pref-lifetime|pl [{forever|infinity|0}]"
                                                      "\n\t\t\t\t      scope {global|link|host|NUMBER}] dad [DAD {none|ipv4|ipv6|both}] prefix-route|pr [PREFIXROUTE BOOLEAN]"
                                                      "\n\t\t\t\t      dad [DAD {none|ipv4|ipv6|both}] prefix-route|pr [PREFIXROUTE BOOLEAN] Configures device Address.\n"
               "  del-addr                     dev [DEVICE] address|a|addr [ADDRESS] Removes address from device.\n"
               "  add-default-gw               dev [DEVICE] gw [GATEWAY ADDRESS] onlink [ONLINK BOOLEAN] Configures device default Gateway.\n"
               "  delete-gw                    dev [DEVICE] Removes Gateway from device.\n"
               "  add-route                    dev [DEVICE] gw [GATEWAY ADDRESS] dest [DESTINATION ADDRESS] src [SOURCE ADDRESS] pref-src [PREFFREDSOURCE ADDRESS]"
                                                     "\n\t\t\t\t      metric [METRIC NUMBER] scope [SCOPE {global|site|link|host|nowhere}] mtu [MTU NUMBER]"
                                                     "\n\t\t\t\t      table [TABLE {default|main|local|NUMBER}] proto [PROTOCOL {boot|static|ra|dhcp|NUMBER}]"
                                                     "\n\t\t\t\t      type [TYPE {unicast|local|broadcast|anycast|multicast|blackhole|unreachable|prohibit|throw|nat|resolve}]"
                                                     "\n\t\t\t\t      ipv6-pref [IPV6PREFERENCE {low|medium|high}] onlink [{ONLINK BOOLEN}] Configures Link route.\n"
               "  delete-route                 dev [DEVICE] Removes route from device\n"
               "  add-addl-gw                  dev [DEVICE] address|addr|a [ADDRESS] destination|dest [DESTINATION address] gw [GW address] table [TABLE NUMBER]"
                                                      "\n\t\t\t\t Configures additional gateway for another NIC/DEVICE with routing policy rules.\n"
               "  add-rule                     dev [DEVICE] table [TABLE NUMBER] from [ADDRESS] to [ADDRESS] oif [DEVICE] iif [DEVICE] priority [NUMBER] tos [NUMBER]"
                                                      "\n\t\t\t\t      Configures Routing Policy Rule.\n"
               "  remove-rule                  dev [DEVICE] Removes Routing Policy Rule.\n"
               "  set-hostname                 [HOSTNAME] Configures hostname.\n"
               "  show-dns                            Show DNS servers.\n"
               "  add-dns                      dev|global|system [DEVICE] dns [ADDRESS] Configures Link or global DNS servers.\n"
               "  add-domain                   dev|global|system [DEVICE] domains [DOMAIN] Configures Link or global Domain.\n"
               "  show-domains                        Show DNS server Domains.\n"
               "  revert-resolve-link          dev [DEVICE] Flushes all DNS server and Domain settings of the link.\n"
               "  set-lla                      dev [DEVICE] [LinkLocalAddressing BOOLEAN|ipv6|ipv4] Configures link local address.\n"
               "  set-ipv4ll-route             dev [DEVICE] [IPv4LLRoute BOOLEAN] Configures the route needed for non-IPv4LL hosts to communicate.\n"
               "                                      with IPv4LL-only hosts.\n"
               "  set-llmnr                    dev [DEVICE] [LLMNR BOOLEAN|resolve] Configures Link Local Multicast Name Resolution.\n"
               "  set-mcast-dns                dev [DEVICE] [MulticastDNS BOOLEAN|resolve] Configures Link Multicast DNS.\n"
               "  set-lldp                     dev [DEVICE] [LLDP BOOLEAN] Configures Link Ethernet LLDP packet reception.\n"
               "  set-emit-lldp                dev [DEVICE] [EmitLLDP BOOLEAN] Configures Link Ethernet LLDP packet emission.\n"
               "  set-ipforward                dev [DEVICE] [IPForward BOOLEAN] Configures Link IP packet forwarding for the system.\n"
               "  set-ipv6acceptra             dev [DEVICE] [IPv6AcceptRA BOOLEAN] Configures Link IPv6 Router Advertisement (RA) reception support for the interface.\n"
               "  set-ipv6mtu                  dev [DEVICE] [MTU NUMBER] Configures IPv6 maximum transmission unit (MTU).\n"
               "  set-ipmasquerade             dev [DEVICE] [IPMasquerade BOOLEAN] Configures IP masquerading for the network interface.\n"
               "  set-ipv4proxyarp             dev [DEVICE] [IPv4ProxyARP BOOLEAN] Configures Link proxy ARP for IPv4.\n"
               "  set-ipv6proxyndp             dev [DEVICE] [IPv6ProxyNDP BOOLEAN] Configures Link proxy NDP for IPv6.\n"
               "  set-conf-wc                  dev [DEVICE] [ConfigureWithoutCarrier BOOLEAN] Allows networkd to configure link even if it has no carrier.\n"
               "  set-dhcp4                    dev [DEVICE] [use-dns BOOLEAN] [use-domains BOOLEAN] [use-mtu BOOLEAN] [use-ntp BOOLEAN] [send-release BOOLEAN]."
                                                     "\n\t\t\t\t     [use-hostname BOOLEAN] [use-routes BOOLEAN] [use-gw BOOLEAN] [use-tz BOOLEAN] Configures Link DHCPv4\n"
               "  set-dhcp6                    dev [DEVICE] [use-dns BOOLEAN] [use-domains BOOLEAN] [rapid-commit BOOLEAN] [use-addr BOOLEAN] [use-delegataed-prefix BOOLEAN]"
                                                     "\n\t\t\t\t     [without-ra BOOLEAN] Configures DHCPv6.\n"
               "  add-ntp                      dev [DEVICE] ntp [NTP] [NTP] ... Add Link NTP server address. This option may be specified more than once.\n"
               "  set-ntp                      dev [DEVICE] ntp [NTP] [NTP] ... Set Link NTP server address. This option may be specified more than once.\n"
               "  delete-ntp                   dev [DEVICE] Delete Link NTP server addresses.\n"
               "  add-dhcpv4-server            dev [DEVICE] pool-offset [PoolOffset NUMBER] pool-size [PoolSize NUMBER] default-lease-time [DefaultLeaseTimeSec NUMBER]"
                                                      "\n\t\t\t\t      max-lease-time [MaxLeaseTimeSec NUMBER] emit-dns [EmitDNS BOOLEAN]"
                                                      "\n\t\t\t\t      dns [DNS ADDRESS] emit-ntp [EmitNTP BOOLEAN] ntp [NTP ADDRESS]"
                                                      "\n\t\t\t\t      emit-router [EmitRouter BOOLEAN] Configures DHCPv4 server.\n"
               "  remove-dhcpv4-server         dev [DEVICE] Removes DHCPv4 server.\n"
               "  add-ipv6ra                   dev [DEVICE] prefix [Prefix ADDRESS] pref-lifetime [PreferredLifetimeSec NUMBER] valid-lifetime [ValidLifetimeSec NUMBER]"
                                                      "\n\t\t\t\t      assign [Assign BOOLEAN] managed [Managed BOOLEAN]"
                                                      "\n\t\t\t\t      other [Other BOOLEAN] dns [DNS ADDRESS] emit-dns [EmitDNS BOOLEAN]"
                                                      "\n\t\t\t\t      domain [DOMAIN ADDRESS] emit-domain [EmitDOMAIN BOOLEAN]"
                                                      "\n\t\t\t\t      router-pref [RouterPreference {low | med | high}]"
                                                      "\n\t\t\t\t      route [Prefix ADDRESS] route-lifetime [LifetimeSec NUMBER] Configures IPv6 Router Advertisement.\n"
               "  remove-ipv6ra                dev [DEVICE] Removes Ipv6 Router Advertisement.\n"
               "  enable-ipv6                  dev [DEVICE] [BOOLEAN] Enable or disables IPv6 on the link.\n"
               "  add-sr-iov                   [DEVICE] [vf INTEGER] [vlanid INTEGER] [qos INTEGER] [vlanproto STRING] [macspoofck BOOLEAN] [qrss BOOLEAN]"
                                                     "\n\t\t\t\t      [trust BOOLEAN] [linkstate BOOLEAN or STRING] [macaddr ADDRESS] Configures SR-IOV VirtualFunction, "
                                                     "\n\t\t\t\t      VLANId, QualityOfService, VLANProtocol, MACSpoofCheck, QueryReceiveSideScaling, Trust, LinkState, MACAddress \n"
               "  create-vlan                  [VLAN name] dev [MASTER DEVICE] id [ID INTEGER] proto [PROTOCOL {802.1q|802.1ad}] Creates vlan netdev and network file\n"
               "  create-bridge                [BRIDGE name] dev [DEVICE] [DEVICE] ... Creates bridge netdev and sets master to device\n"
               "  create-bond                  [BOND name] mode [MODE {balance-rr|active-backup|balance-xor|broadcast|802.3ad|balance-tlb|balance-alb}]"
                                               "\n\t\t\t\tdev [DEVICE] [DEVICE] ... Creates bond netdev and sets master to device\n"
               "  create-vxlan                 [VXLAN name] [dev DEVICE] vni [INTEGER] [local ADDRESS] [remote ADDRESS] [port PORT] [independent BOOLEAN]."
                                               "\n\t\t\t\tCreates vxlan VXLAN (Virtual eXtensible Local Area Network) tunneling.\n"
               "  create-macvlan               [MACVLAN name] dev [DEVICE] mode [MODE {private|vepa|bridge|passthru|source}] Creates macvlan virtualized bridged networking.\n"
               "  create-macvtap               [MACVTAP name] dev [DEVICE] mode [MODE {private|vepa|bridge|passthru|source}] Creates macvtap virtualized bridged networking.\n"
               "  create-ipvlan                [IPVLAN name] dev [DEVICE] mode [MODE {l2|l3|l3s}] Creates ipvlan, virtual LAN, separates broadcast domains by adding tags to network"
                                                     "\n\t\t\t\t      packet.\n"
               "  create-ipvtap                [IPVTAP name] dev [DEVICE] mode [MODE {l2|l3|l3s}] Create ipvtap.\n"
               "  create-vrf                   [VRF name] table [INTEGER}] Creates Virtual routing and forwarding (VRF).\n"
               "  create-veth                  [VETH name] peer [PEER name}] Creates virtual Ethernet devices\n"
               "  create-ipip                  [IPIP name] [dev DEVICE] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates ipip tunnel.\n"
               "  create-sit                   [SIT name] [dev DEVICE] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates sit tunnel.\n"
               "  create-vti                   [VTI name] [dev DEVICE] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates vti tunnel.\n"
               "  create-gre                   [GRE name] [dev DEVICE] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates gre tunnel.\n"
               "  create-wg                    [WIREGUARD name] private-key [PRIVATEKEY] listen-port [PORT INTEGER] public-key [PUBLICKEY] preshared-key [PRESHAREDKEY]"
                                               "\n\t\t\t\t\t\t allowed-ips [IP,IP ...] endpoint [IP:PORT] Creates a wireguard tunnel.\n"
               "  create-tun                   [TUN name] user [USER STRING] group [GROUP string] mq [MULTIQUEUE BOOL] pkt-info [PACKETINFO BOOL] vnet-hdr [VNETHEADER BOOL]"
                                               "\n\t\t\t\t\t\t kc [KEEPCARRIER bool] Creates tun.\n"
               "  create-tap                   [TAP name] user [USER STRING] group [GROUP string] mq [MULTIQUEUE BOOL] pkt-info [PACKETINFO BOOL] vnet-hdr [VNETHEADER BOOL]"
                                               "\n\t\t\t\t\t\t kc [KEEPCARRIER bool] Creates tap.\n"
               "  remove-netdev                [DEVICE] kind [KIND {vlan|bridge|bond|vxlan|macvlan|macvtap|ipvlan|ipvtap|vrf|veth|ipip|sit|vti|gre|wg] \n"
               "                                      Removes .netdev and .network files.\n"
               "  reload                       Reload .network and .netdev files.\n"
               "  reconfigure                  dev [DEVICE] Reconfigure device.\n"
               "  show-config                  dev [DEVICE] Displays network configuration of device.\n"
               "  edit                         dev [DEVICE] Edit network configuration of device.\n"
               "  set-link                     [LINK] [alias STRING] [desc STRING] [mtub STRING]  [bps STRING]  [duplex STRING] [wol STRING | List] [wolp STRING] "
                                                       "\n\t\t\t\t    [port STRING] [advertise STRING | List]"
                                                       "\n\t\t\t\t    Configure link's other parameters like mtubytes, bitspersecond, duplex, wakeonlan, wakeonlanpassword, port and advertise.\n"
               "  set-link-feature             [LINK] [auton BOOLEAN] [rxcsumo BOOLEAN]  [txcsumo BOOLEAN]  [tso BOOLEAN] [tso6 BOOLEAN] [gso BOOLEAN] [grxo BOOLEAN] "
                                                        "\n\t\t\t\t    [grxoh BOOLEAN] [lrxo BOOLEAN] [rxvtha BOOLEAN] [txvtha BOOLEAN] [rxvtf BOOLEAN] [txvstha BOOLEAN] [ntf BOOLEAN] "
                                                        "\n\t\t\t\t    [uarxc BOOLEAN] [uatxc BOOLEAN]"
                                                        "\n\t\t\t\t    Configure link's enable or disable features like autonegotiation, checksum offload, "
                                                        "\n\t\t\t\t    tcpsegmentation, genericoffload, largeoffload, vlantag acceleration, tuple filter, useadaptive coalesce.\n"
               "  set-link-mac                 [LINK] [macpolicy STRING | List]  [macaddr STRING]"
                                                      "\n\t\t\t\t    Configure link's macaddress policy or macaddress.\n"
               "  set-link-name                [LINK] [namepolicy STRING | List]  [name STRING]"
                                                      "\n\t\t\t\t    Configure link's name policy or name.\n"
               "  set-link-altname             [LINK] [altnamepolicy STRING | List]  [name STRING]"
                                                      "\n\t\t\t\t    Configure link's alternative name policy or alternative name.\n"
               "  set-link-buf                 [LINK] [rxbuf NUMBER | max] [rxminbuf NUMBER | max] [rxjumbobuf NUMBER | max] [txbuf NUMBER | max]"
                                                      "\n\t\t\t\t    Configure link's the maximum number of pending packets receive buffer. [1…4294967295 | max]\n"
               "  set-link-queue               [LINK] [rxq NUMBER] [txq NUMBER] [txqlen NUMBER]"
                                                      "\n\t\t\t\t    Configure link's the maximum number or queue\n"
               "  set-link-flow-control        [LINK] [rxflowctrl BOOLEAN] [txflowctrl BOOLEAN] [autoflowctrl BOOLEAN]"
                                                      "\n\t\t\t\t    Configure links the flow control\n"
               "  set-link-gso                 [LINK] [gsob NUMBER] [gsos NUMBER]"
                                                      "\n\t\t\t\t    Configure link's Generic Segment Offload (GSO)\n"
               "  set-link-channel             [LINK] [rxch NUMBER | max] [txch NUMBER | max] [otrch NUMBER | max] [combch NUMBER | max]"
                                                      "\n\t\t\t\t    Configure link's specifies the number of receive, transmit, other, or combined channels, respectively\n"
               "  set-link-coalesce            [LINK] [rxcs NUMBER | max] [rxcsirq NUMBER | max] [rxcslow NUMBER | max] [rxcshigh NUMBER | max] [txcs NUMBER | max]"
                                                     "\n\t\t\t\t     [txcsirq NUMBER | max] [txcslow NUMBER | max] [txcshigh NUMBER | max]"
                                                     "\n\t\t\t\t    Configure link's delay before Rx/Tx interrupts are generated after a packet is sent/received.\n"
               "  set-link-coald-frames        [LINK] [rxmcf NUMBER | max] [rxmcfirq NUMBER | max] [rxmcflow NUMBER | max] [rxmcfhigh NUMBER | max] [txmcf NUMBER | max]"
                                                     "\n\t\t\t\t     [txmcfirq NUMBER | max] [txmcflow NUMBER | max] [txmcfhigh NUMBER | max]"
                                                     "\n\t\t\t\t    Configure link's maximum number of frames that are sent/received before a Rx/Tx interrupt is generated.\n"
               "  set-link-coal-pkt            [LINK] [cprlow NUMBER | max] [cprhigh NUMBER | max] [cprsis NUMBER | max] [sbcs NUMBER | max]"
                                                      "\n\t\t\t\t    Configure link's low and high packet rate, sampleinterval packet rate and statistics block updates.\n"
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
                { "alias",       no_argument,       NULL, 'a'   },
                {}
        };
        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ahvjb", options, NULL)) >= 0) {

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
                case 'a':
                        alias = true;
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
                { "status",                        "s",                WORD_ANY, WORD_ANY, true,  ncm_system_status },
                { "status-devs",                   "sd",               WORD_ANY, WORD_ANY, false, ncm_link_status },
                { "set-mtu",                       "mtu",              3,        WORD_ANY, false, ncm_link_set_mtu },
                { "set-mac",                       "mac",              3,        WORD_ANY, false, ncm_link_set_mac },
                { "set-manage",                    "manage" ,          3,        WORD_ANY, false, ncm_link_set_mode },
                { "set-link-option",               "lopt",             4,        WORD_ANY, false, ncm_link_set_option },
                { "set-link-group",                "lgrp",             4,        WORD_ANY, false, ncm_link_set_group },
                { "set-link-rfo",                  "lrfo",             4,        WORD_ANY, false, ncm_link_set_rf_online },
                { "set-link-ap",                   "lap",              4,        WORD_ANY, false, ncm_link_set_act_policy },
                { "set-dhcp",                      "dhcp",             4,        WORD_ANY, false, ncm_link_set_dhcp_mode },
                { "set-dhcp4-cid",                 "dhcp4-cid",        3,        WORD_ANY, false, ncm_link_set_dhcp4_client_identifier},
                { "set-dhcp-iaid",                 "dhcp-iaid",        4,        WORD_ANY, false, ncm_link_set_dhcp_client_iaid},
                { "set-dhcp-duid",                 "dhcp-duid",        4,        WORD_ANY, false, ncm_link_set_dhcp_client_duid},
                { "set-link-state",                "ls",               3,        WORD_ANY, false, ncm_link_update_state },
                { "add-addr",                      "aa",               4,        WORD_ANY, false, ncm_link_add_address },
                { "show-addr",                     "a",                1,        WORD_ANY, false, ncm_display_one_link_addresses },
                { "del-addr",                      "da",               3,        WORD_ANY, false, ncm_link_delete_address },
                { "add-default-gw",                "gw",               4,        WORD_ANY, false, ncm_link_add_default_gateway },
                { "delete-gw",                     "dgw",              2,        WORD_ANY, false, ncm_link_delete_gateway_or_route },
                { "add-route",                     "ar" ,              4,        WORD_ANY, false, ncm_link_add_route },
                { "delete-route",                  "dr",               4,        WORD_ANY, false, ncm_link_delete_gateway_or_route },
                { "add-addl-gw",                   "agw",              9,        WORD_ANY, false, ncm_link_add_additional_gw },
                { "add-rule",                      "rule",             4,        WORD_ANY, false, ncm_link_add_routing_policy_rules },
                { "remove-rule",                   "rrule",            1,        WORD_ANY, false, ncm_link_remove_routing_policy_rules },
                { "set-hostname",                  "hostname",         1,        WORD_ANY, false, ncm_set_system_hostname },
                { "show-dns",                      "dns",              WORD_ANY, WORD_ANY, false, ncm_show_dns_server },
                { "add-dns",                       "adns",             2,        WORD_ANY, false, ncm_add_dns_server },
                { "add-domain",                    "adomain",          1,        WORD_ANY, false, ncm_add_dns_domains },
                { "show-domains",                  "domain",           WORD_ANY, WORD_ANY, false, ncm_show_dns_server_domains },
                { "revert-resolve-link",           "rrl",              1,        WORD_ANY, false, ncm_revert_resolve_link },
                { "set-ipv6mtu",                   "mtu6",             3,        WORD_ANY, false, ncm_link_set_network_ipv6_mtu },
                { "set-lla",                       "lla",              3,        WORD_ANY, false, ncm_link_set_link_local_address },
                { "set-ipv4ll-route",              "ipv4ll-route",     3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-llmnr",                     "llmnr",            3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-mcast-dns",                 "mcast-dns",        3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-lldp",                      "lldp",             3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-emit-lldp",                 "elldp",            3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-ipforward",                 "ipfwd",            3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-ipv6acceptra",              "ipv6ara",          3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-ipmasquerade",              "ipmasq",           3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-ipv4proxyarp",              "pxyarp4",          3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-ipv6proxyndp",              "pxyndp6",          3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-conf-wc",                   "cwc",              3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-dhcp4",                     "dhcp4",            4,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp6",                     "dhcp6",            4,        WORD_ANY, false, ncm_link_set_dhcp6_section },
                { "add-dhcpv4-server",             "dhcpv4-srv" ,      2,        WORD_ANY, false, ncm_link_add_dhcpv4_server },
                { "remove-dhcpv4-server",          "rdhcpv4-srv",      2,        WORD_ANY, false, ncm_link_remove_dhcpv4_server },
                { "add-ipv6ra",                    "ra6",              2,        WORD_ANY, false, ncm_link_add_ipv6_router_advertisement },
                { "remove-ipv6ra",                 "rra6",             2,        WORD_ANY, false, ncm_link_remove_ipv6_router_advertisement },
                { "add-ntp",                       "antp",             2,        WORD_ANY, false, ncm_link_add_ntp },
                { "set-ntp",                       "sntp" ,            2,        WORD_ANY, false, ncm_link_add_ntp },
                { "delete-ntp",                    "dntp",             1,        WORD_ANY, false, ncm_link_delete_ntp },
                { "enable-ipv6",                   "ipv6",             2,        WORD_ANY, false, ncm_link_enable_ipv6 },
                { "create-vlan",                   "vlan",             4,        WORD_ANY, false, ncm_create_vlan },
                { "create-bridge",                 "bridge",           3,        WORD_ANY, false, ncm_create_bridge },
                { "create-bond",                   "bond",             5,        WORD_ANY, false, ncm_create_bond },
                { "create-vxlan",                  "vxlan",            2,        WORD_ANY, false, ncm_create_vxlan },
                { "create-macvlan",                "macvlan",          5,        WORD_ANY, false, ncm_create_macvlan },
                { "create-macvtap",                "macvtap",          5,        WORD_ANY, false, ncm_create_macvlan },
                { "create-ipvlan",                 "ipvlan",           5,        WORD_ANY, false, ncm_create_ipvlan },
                { "create-ipvtap",                 "ipvtap",           5,        WORD_ANY, false, ncm_create_ipvlan },
                { "create-vrf",                    "vrf",              3,        WORD_ANY, false, ncm_create_vrf },
                { "create-veth",                   "veth",             3,        WORD_ANY, false, ncm_create_veth },
                { "create-ipip",                   "ipip",             3,        WORD_ANY, false, ncm_create_tunnel },
                { "create-sit",                    "sit",              3,        WORD_ANY, false, ncm_create_tunnel },
                { "create-gre",                    "gre",              3,        WORD_ANY, false, ncm_create_tunnel },
                { "create-vti",                    "vti",              3,        WORD_ANY, false, ncm_create_tunnel },
                { "create-wg",                     "wg",               3,        WORD_ANY, false, ncm_create_wireguard_tunnel },
                { "create-tun",                    "tun",              1,        WORD_ANY, false, ncm_create_tun_tap },
                { "create-tap",                    "tap",              1,        WORD_ANY, false, ncm_create_tun_tap },
                { "remove-netdev",                 "rnetdev",          1,        WORD_ANY, false, ncm_remove_netdev },
                { "reload",                        "re",               WORD_ANY, WORD_ANY, false, ncm_network_reload },
                { "reconfigure",                   "rc",               1,        WORD_ANY, false, ncm_link_reconfigure },
                { "show-config",                   "sc",               1,        WORD_ANY, false, ncm_link_show_network_config },
                { "edit",                          "e" ,               1,        WORD_ANY, false, ncm_link_edit_network_config },
                { "set-link",                      "l",                2,        WORD_ANY, false, ncm_configure_link },
                { "set-link-feature",              "lf",               2,        WORD_ANY, false, ncm_configure_link_features },
                { "set-link-mac",                  "lm",               2,        WORD_ANY, false, ncm_configure_link_mac },
                { "set-link-name",                 "ln",               2,        WORD_ANY, false, ncm_configure_link_name },
                { "set-link-altname",              "lan",              2,        WORD_ANY, false, ncm_configure_link_altname },
                { "set-link-buf",                  "lb",               2,        WORD_ANY, false, ncm_configure_link_buf_size },
                { "set-link-queue",                "lq",               2,        WORD_ANY, false, ncm_configure_link_queue_size },
                { "set-link-flow-control",         "lfc",              2,        WORD_ANY, false, ncm_configure_link_flow_control },
                { "set-link-gso",                  "lgso",             2,        WORD_ANY, false, ncm_configure_link_gso },
                { "set-link-channel",              "lchannel" ,        2,        WORD_ANY, false, ncm_configure_link_channel },
                { "set-link-coalesce",             "lcoalesce",        2,        WORD_ANY, false, ncm_configure_link_coalesce },
                { "set-link-coald-frames",         "lcf",              2,        WORD_ANY, false, ncm_configure_link_coald_frames },
                { "set-link-coal-pkt",             "lcp",              2,        WORD_ANY, false, ncm_configure_link_coal_pkt },
                { "add-sr-iov",                    "sriov",            2,        WORD_ANY, false, ncm_configure_sr_iov},
                { "set-proxy",                     "pxy",              1,        WORD_ANY, false, ncm_configure_proxy },
                { "show-proxy",                    "spxy",             WORD_ANY, WORD_ANY, false, ncm_show_proxy },
                { "generate-config-from-yaml",     "gcyml",            1,        WORD_ANY, false, generate_networkd_config_from_yaml },
                { "apply-yaml-config",             "ayml",             WORD_ANY, WORD_ANY, false, generate_networkd_config_from_yaml },
                { "generate-config-from-cmdline",  "gccmd",            WORD_ANY, WORD_ANY, false, generate_networkd_config_from_command_line },
                { "add-nft-table",                 "atable",           2,        WORD_ANY, false, ncm_nft_add_tables },
                { "show-nft-tables",               "table",            WORD_ANY, WORD_ANY, false, ncm_nft_show_tables },
                { "delete-nft-table",              "dtable",           2,        WORD_ANY, false, ncm_nft_delete_table },
                { "add-nft-chain",                 "achain",           3,        WORD_ANY, false, ncm_nft_add_chain },
                { "show-nft-chains",               "chain",            WORD_ANY, WORD_ANY, false, ncm_nft_show_chains },
                { "delete-nft-chain",              "dchain",           3,        WORD_ANY, false, ncm_nft_delete_chain },
                { "add-nft-rule",                  "anft-rule",        7,        WORD_ANY, false, ncm_nft_add_rule_port },
                { "show-nft-rules",                "nft-rule",         1,        WORD_ANY, false, ncm_nft_show_rules },
                { "delete-nft-rule",               "dnft-rule",        2,        WORD_ANY, false, ncm_nft_delete_rule },
                { "nft-run",                       "nftr",             WORD_ANY, WORD_ANY, false, ncm_nft_run_command },
                /* Deprecated */
                { "show",                          "",                 WORD_ANY, WORD_ANY, false, ncm_link_status },
                {}
        };

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (alias) {
                printf("%s   %28s\n", "Command", "Alias");
                for (size_t i = 0; i < ELEMENTSOF(commands); i++) {
                        if (!isempty_string(commands[i].alias))
                                printf("%-30s   %-30s\n", commands[i].name, commands[i].alias);
                }

                return 0;
        }

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

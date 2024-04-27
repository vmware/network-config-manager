/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <getopt.h>
#include <network-config-manager.h>

#include "alloc-util.h"
#include "ctl-display.h"
#include "file-util.h"
#include "ctl.h"
#include "log.h"
#include "macros.h"
#include "network-manager.h"
#include "parse-util.h"

#define DEFAULT_LOG_LINE_SIZE 64

static bool alias = false;

static int load_yaml_files(void) {
        g_autoptr(GHashTable) configs = NULL;
        g_autoptr(GList) config_keys = NULL;
        _cleanup_(globfree) glob_t g = {};
        int r;

        r = glob_files("/etc/network-config-manager/yaml/*.y*ml", 0, &g);
        if (r != -ENOENT)
                return r;

        configs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        if (!configs)
                return log_oom();

        for (size_t i = 0; i < g.gl_pathc; ++i)
                g_hash_table_insert(configs, g_path_get_basename(g.gl_pathv[i]), g.gl_pathv[i]);

        config_keys = g_list_sort(g_hash_table_get_keys(configs), (GCompareFunc) strcmp);

        for (GList *i = config_keys; i ; i = i->next) {
                r = manager_generate_network_config_from_yaml(g_hash_table_lookup(configs, i->data));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int generate_networkd_config_from_yaml(int argc, char *argv[]) {
        int r;

        if (streq(argv[0], "apply")) {
                r = load_yaml_files();
                if (r < 0) {
                        log_warning("Failed to process yaml directory '/etc/network-config-manager/yaml': %s", strerror(r));
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
                "apply-file",
                "apply",
                "apply-cmdline",
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
               "Query and control the systemd-networkd daemon.\n\n"
               "  -h --help                    Show this help message and exit\n"
               "  -v --version                 Show package version\n"
               "  -j --json                    Show in JSON format\n"
               "  -b --no-beautify             Show without colors and headers\n"
               "  -a --alias                   Show command alias\n"
               "\nCommands:\n"
               "  status                       [DEVICE] Show system or device status\n"
               "  status-devs                  List all devices.\n"
               "  show-ipv4-status             dev [DEVICE] Show device ipv4 address, address mode and gateway\n"
               "  set-mtu                      dev [DEVICE] mtu [MTU NUMBER] Configures device MTU.\n"
               "  set-mac                      dev [DEVICE] mac [MAC] Configures device MAC address.\n"
               "  set-manage                   dev [DEVICE] manage [MANAGE BOOLEAN] Configures whether device managed by networkd.\n"
               "  set-link-option              dev [DEVICE] [arp BOOLEAN] [mc BOOLEAN] [amc BOOLEAN] [pcs BOOLEAN]"
                                                     "\n\t\t\t\t\tConfigures device's arp, multicast, allmulticast and promiscuous.\n"
               "  set-link-group               dev [DEVICE] group [GROUP NUMBER] Configures device group.\n"
               "  set-link-rfo                 dev [DEVICE] f|family [ipv4|ipv6|yes] Configures device required family for online.\n"
               "  set-link-ap                  dev [DEVICE] ap|act-policy [up|always-up|manual|always-down|down|bound] Configures device activation policy.\n"
               "  set-dhcp                     dev [DEVICE] dhcp [DHCP {yes|no|ipv4|ipv6}] use-dns-ipv4 [BOOLEAN] use-dns-ipv6 [BOOLEAN]"
                                                      "\n\t\t\t\t use-domains-ipv4 [BOOLEAN] use-domains-ipv6 [BOOLEAN] send-release-ipv4 [BOOLEAN] send-release-ipv6 [BOOLEAN] Configures DHCP client.\n"
               "  set-dhcp4-cid                dev [DEVICE] id [IDENTIFIER {mac|duid|duid-only} Configures device DHCPv4 identifier.\n"
               "  set-dhcp-iaid                dev [DEVICE] family|f iaid [IAID] Configures the DHCP Identity Association Identifier (IAID)\n"
               "  set-dhcp-duid                dev|system [DEVICE] family|f [ipv4|ipv6|4|6] type [DUIDType {link-layer-time|vendor|link-layer|uuid|0…65535}] data [RAWDATA]"
                                                      "\n\t\t\t\t      Sets DUID of DHCPv4 or DHCPv6 Client.\n"
               "  set-link-state               dev [DEVICE] [STATE {up|down}] Configures device State.\n"
               "  show-addr                    dev [DEVICE] [family|f ipv4|ipv6|4|6] Show device addresses\n"
               "  add-addr                     dev [DEVICE] address|a|addr [ADDRESS] peer [ADDRESS]] label [STRING] pref-lifetime|pl [{forever|infinity|0}]"
                                                      "\n\t\t\t\t      scope {global|link|host|NUMBER}] dad [DAD {none|ipv4|ipv6|both}] prefix-route|pr [PREFIXROUTE BOOLEAN]"
                                                      "\n\t\t\t\t      prefix-route|pr [PREFIXROUTE BOOLEAN] many [ADDRESS1,ADDRESS2...] Configures device Address.\n"
               "  remove-addr                  dev [DEVICE] address|a|addr [ADDRESS] many [ADDRESS1,ADDRESS2...] f|family [ipv4|ipv6|yes] Removes address or family of addresses from device.\n"
               "  replace-addr                 dev [DEVICE] address|a|addr [ADDRESS] many [ADDRESS1,ADDRESS2...] f|family [ipv4|ipv6|yes] Replaces family of addresses, address with a address or many\n"
               "  set-gw                       dev [DEVICE] gw [GATEWAY ADDRESS] onlink [ONLINK BOOLEAN] keep [BOOLEAN] Configures device default Gateway.\n"
               "  set-gw-family                dev [DEVICE] gw4 [IPv4 GATEWAY ADDRESS] gw6 [IPv6 GATEWAY ADDRESS] Configures device default IPv4/IPv6 Gateway.\n"
               "  remove-gw                    dev [DEVICE] f|family [ipv4|ipv6|yes] Removes Gateway from device.\n"
               "  add-route                    dev [DEVICE] gw [GATEWAY ADDRESS] dest [DESTINATION ADDRESS] src [SOURCE ADDRESS] pref-src [PREFFREDSOURCE ADDRESS]"
                                                     "\n\t\t\t\t      metric [METRIC NUMBER] scope [SCOPE {global|site|link|host|nowhere}] mtu [MTU NUMBER]"
                                                     "\n\t\t\t\t      table [TABLE {default|main|local|NUMBER}] proto [PROTOCOL {boot|static|ra|dhcp|NUMBER}]"
                                                     "\n\t\t\t\t      type [TYPE {unicast|local|broadcast|anycast|multicast|blackhole|unreachable|prohibit|throw|nat|resolve}]"
                                                     "\n\t\t\t\t      ipv6-pref [IPV6PREFERENCE {low|medium|high}] onlink [{ONLINK BOOLEN}] Configures Link route.\n"
               "  remove-route                 dev [DEVICE] f|family [ipv4|ipv6|yes] Removes route from device\n"
               "  set-dynamic                  dev [DEVICE] dhcp [DHCP {BOOLEAN|ipv4|ipv6}] use-dns-ipv4 [BOOLEAN] use-dns-ipv6 [BOOLEAN] send-release-ipv4 [BOOLEAN] send-release-ipv6 [BOOLEAN]"
                                                      "\n\t\t\t\t use-domains-ipv4 [BOOLEAN] use-domains-ipv6 [BOOLEAN] accept-ra [BOOLEAN] client-id-ipv4|dhcp4-client-id [DHCPv4 IDENTIFIER {mac|duid|duid-only}"
               "                                       \n\t\t\t\t iaid-ipv4|dhcpv4-iaid  [DHCPv4 IAID] iaid-ipv6|dhcp6-iaid [DHCPv6 IAID] lla [BOOLEAN|ipv6|ipv4] keep [BOOLEAN] Configures dynamic configuration of the device (IPv4|IPv6|RA).\n"
               "  set-static                   dev [DEVICE] address|a|addr [ADDRESS] gw|gateway|g [GATEWAY ADDRESS] dns [SERVER1,SERVER2...] ... lla [BOOLEAN|ipv6|ipv4] keep [BOOLEAN] Configures static configuration of the device\n"
               "  set-network                  dev [DEVICE] dhcp [DHCP {BOOLEAN|ipv4|ipv6}] use-dns-ipv4 [BOOLEAN] use-dns-ipv6 [BOOLEAN] send-release-ipv4 [BOOLEAN] send-release-ipv6 [BOOLEAN]"
                                                      "\n\t\t\t\t use-domains-ipv4 [BOOLEAN] use-domains-ipv6 [BOOLEAN] accept-ra [BOOLEAN] client-id-ipv4|dhcp4-client-id [DHCPv4 IDENTIFIER {mac|duid|duid-only}"
               "                                       \n\t\t\t\t iaid-ipv4|dhcpv4-iaid  [DHCPv4 IAID] iaid-ipv6|dhcp6-iaid [DHCPv6 IAID] address|a|addr [ADDRESS] gw|gateway|g [GATEWAY ADDRESS] dns [SERVER1,SERVER2...]"
               "                                       \n\t\t\t\t lla [BOOLEAN|ipv6|ipv4] keep [BOOLEAN] Configures dynamic and static configuration of the device.\n"
               "  set-rule                     dev [DEVICE] address|addr|a [ADDRESS] destination|dest [DESTINATION address] gw [GW address] table [TABLE NUMBER]"
                                                      "\n\t\t\t\t Configures device address and gateway with routing policy rules.\n"
               "  add-rule                     dev [DEVICE] table [TABLE NUMBER] [from ADDRESS] [to ADDRESS] [oif DEVICE] [iif DEVICE] [priority NUMBER] [tos NUMBER]"
                                                "\n\t\t\t\t [invert BOOLEAN] [sport NUMBER] [dport NUMBER] [proto tcp|udp|sctp] Configures Routing Policy Rule.\n"
               "  remove-rule                  dev [DEVICE] Removes Routing Policy Rule.\n"
               "  set-hostname                 [HOSTNAME] Configures system Static hostname.\n"
               "  show-dns                                  Show DNS servers.\n"
               "  set-dns                      dev [DEVICE] dns [SERVER1,SERVER2...] use-dns-ipv4 [BOOLEAN] use-dns-ipv6 [BOOLEAN] keep [BOOLEAN].\n"
               "  set-dns-domains              dev [DEVICE] domains [DOMAIN1,DOMAIN2 ...] keep [BOOLEAN] Configures device Search Domains.\n"
               "  show-domains                              Show DNS Search Domains.\n"
               "  revert-resolve-link          dev [DEVICE] dns [BOOLEAN] domain [BOOLEAN] Flushes all DNS server and Domain settings of the device.\n"
               "  set-ntp                      dev [DEVICE] ntp [NTP1,NTP2...] keep [BOOLEAN] Set device NTP server address. This option may be specified more than once.\n"
               "  remove-ntp                   dev [DEVICE] Removes devices NTP servers.\n"
               "  show-ntp                                  Show NTP servers.\n"
               "  set-lla                      dev [DEVICE] [LinkLocalAddressing BOOLEAN|ipv6|ipv4] Configures link local address.\n"
               "  set-ipv4ll-route             dev [DEVICE] [IPv4LLRoute BOOLEAN] Configures the route needed for non-IPv4LL hosts to communicate.\n"
               "                                      with IPv4LL-only hosts.\n"
               "  set-llmnr                    dev [DEVICE] [LLMNR BOOLEAN|resolve] Configures Link Local Multicast Name Resolution.\n"
               "  set-mcast-dns                dev [DEVICE] [MulticastDNS BOOLEAN|resolve] Configures Link Multicast DNS.\n"
               "  set-lldp                     dev [DEVICE] receive [BOOLEAN] emit [BOOLEAN] Configures Link Ethernet LLDP.\n"
               "  set-ipforward                dev [DEVICE] [IPForward BOOLEAN] Configures Link IP packet forwarding for the system.\n"
               "  set-ipv6acceptra             dev [DEVICE] [IPv6AcceptRA BOOLEAN] Configures Link IPv6 Router Advertisement (RA) reception support for the interface.\n"
               "  set-ipv6mtu                  dev [DEVICE] [MTU NUMBER] Configures IPv6 maximum transmission unit (MTU).\n"
               "  set-ipmasquerade             dev [DEVICE] [IPMasquerade BOOLEAN] Configures IP masquerading for the network interface.\n"
               "  set-ipv4proxyarp             dev [DEVICE] [IPv4ProxyARP BOOLEAN] Configures Link proxy ARP for IPv4.\n"
               "  set-ipv6proxyndp             dev [DEVICE] [IPv6ProxyNDP BOOLEAN] Configures Link proxy NDP for IPv6.\n"
               "  set-conf-wc                  dev [DEVICE] [ConfigureWithoutCarrier BOOLEAN] Allows networkd to configure link even if it has no carrier.\n"
               "  set-ipv6dad                  dev [DEVICE] [IPv6DuplicateAddressDetection BOOLEAN] Allows Configures the amount of IPv6 Duplicate Address Detection (DAD) probes to send.\n"
               "  set-ipv6-ll-addr-gen-mode    dev [DEVICE] [IPv6LinkLocalAddressGenerationMode eui64|stable-privacy|none|random] Specifies how IPv6 link-local address is generated.\n"
               "  set-conf-wc                  dev [DEVICE] [ConfigureWithoutCarrier BOOLEAN] Allows networkd to configure link even if it has no carrier.\n"
               "  set-dhcp4                    dev [DEVICE] [use-dns BOOLEAN] [use-domains BOOLEAN] [use-mtu BOOLEAN] [use-ntp BOOLEAN] [send-release BOOLEAN]."
                                                     "\n\t\t\t\t     [use-hostname BOOLEAN] [use-routes BOOLEAN] [use-gw BOOLEAN] [use-tz BOOLEAN] Configures Link DHCPv4\n"
               "  set-dhcp6                    dev [DEVICE] [use-dns BOOLEAN] [use-domains BOOLEAN] [rapid-commit BOOLEAN] [use-addr BOOLEAN] [use-delegataed-prefix BOOLEAN]"
                                                     "\n\t\t\t\t     [without-ra BOOLEAN] [use-ntp BOOLEAN] [use-hostname BOOLEAN] [send-release BOOLEAN] Configures DHCPv6.\n"
               "  add-dhcpv4-server            dev [DEVICE] pool-offset [PoolOffset NUMBER] pool-size [PoolSize NUMBER] default-lease-time [DefaultLeaseTimeSec NUMBER]"
                                                      "\n\t\t\t\t      max-lease-time [MaxLeaseTimeSec NUMBER] emit-dns [EmitDNS BOOLEAN]"
                                                      "\n\t\t\t\t      dns [DNS ADDRESS] emit-ntp [EmitNTP BOOLEAN] ntp [NTP ADDRESS]"
                                                      "\n\t\t\t\t      emit-router [EmitRouter BOOLEAN] Configures DHCPv4 server.\n"
               "  remove-dhcpv4-server         dev [DEVICE] Removes DHCPv4 server.\n"
               "  add-dhcpv4-static-addr       dev [DEVICE] mac [MACADDRESS] addr [ADDRESS]. Adds a DHCPv4 server static address\n"
               "  remove-dhcpv4-static-addr    dev [DEVICE] mac [MACADDRESS] addr [ADDRESS]. Removes a DHCPv4 server static address\n"
               "  add-ipv6ra                   dev [DEVICE] prefix [Prefix ADDRESS] pref-lifetime [PreferredLifetimeSec NUMBER] valid-lifetime [ValidLifetimeSec NUMBER]"
                                                      "\n\t\t\t\t      assign [Assign BOOLEAN] managed [Managed BOOLEAN]"
                                                      "\n\t\t\t\t      other [Other BOOLEAN] dns [DNS ADDRESS] emit-dns [EmitDNS BOOLEAN]"
                                                      "\n\t\t\t\t      domain [DOMAIN ADDRESS] emit-domain [EmitDOMAIN BOOLEAN]"
                                                      "\n\t\t\t\t      router-pref [RouterPreference {low | med | high}]"
                                                      "\n\t\t\t\t      route [Prefix ADDRESS] route-lifetime [LifetimeSec NUMBER] Configures IPv6 Router Advertisement.\n"
               "  remove-ipv6ra                dev [DEVICE] Removes Ipv6 Router Advertisement.\n"
               "  enable-ipv6                  dev [DEVICE] [BOOLEAN] Enable or disables IPv6 on the link.\n"
               "  set-ipv4                     dev [DEVICE] dhcp [BOOLEAN] addr [ADDRESS] many [ADDRESS1,ADDRESS2...] gw|gw4|g [GATEWAY] dns [SERVER1,SERVER2...]"
                                                      "\n\t\t\t\t     lla [BOOLEAN|ipv6|ipv4] use-dns [BOOLEAN send-release [BOOLEAN] keep [BOOLEAN] Configures device IPv4.\n"
               "  set-ipv6                     dev [DEVICE] accept-ra [BOOLEAN] dhcp [BOOLEAN] address|a|addr [ADDRESS] many [ADDRESS1,ADDRESS2...] gw|gw6|g [GATEWAY]"
                                                      "\n\t\t\t\t     lla [BOOLEAN|ipv6|ipv4] dns [SERVER1,SERVER2...] use-dns [BOOLEAN] send-release [BOOLEAN] keep [BOOLEAN] Configures device IPv6.\n"
               "  add-sr-iov                   dev [DEVICE] [vf INTEGER] [vlanid INTEGER] [qos INTEGER] [vlanproto STRING] [macspoofck BOOLEAN] [qrss BOOLEAN]"
                                                     "\n\t\t\t\t      [trust BOOLEAN] [linkstate BOOLEAN or STRING] [macaddr ADDRESS] Configures SR-IOV VirtualFunction, "
                                                     "\n\t\t\t\t      VLANId, QualityOfService, VLANProtocol, MACSpoofCheck, QueryReceiveSideScaling, Trust, LinkState, MACAddress \n"
               "  create-vlan                  [VLAN name] dev [MASTER DEVICE] id [ID INTEGER] proto [PROTOCOL {802.1q|802.1ad}] [gvrp BOOLEAN] [mvrp BOOLEAN] "
                                                     "\n\t\t\t\t    [loose-binding BOOLEAN] [reorder-hdr BOOLEAN] Creates vlan netdev and network file\n"
               "  create-bridge                [BRIDGE name] [stp BOOLEAN] [vlan-protocol BOOLEAN] [vlan-filtering BOOLEAN] [mcast-snooping BOOLEAN] "
                                               "\n\t\t\t\t [mcast-querier BOOLEAN] dev [DEVICE,DEVICE ...] Creates bridge netdev and sets master to device\n"
               "  create-bond                  [BOND name] mode [MODE {balance-rr|active-backup|balance-xor|broadcast|802.3ad|balance-tlb|balance-alb}]"
                                               "\n\t\t\t\t[xmit-hash-policy layer2|layer2+3|layer3+4|encap2+3|encap3+4|vlan+srcmac] dev [DEVICE,DEVICE ...] Creates a bond and sets master to devices\n"
               "  create-vxlan                 [VXLAN name] [dev DEVICE] vni [INTEGER] [local ADDRESS] [remote ADDRESS] [dport PORT] [independent BOOLEAN]."
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
               "  create-wg                    [WIREGUARD name] private-key [PRIVATEKEY] private-key-file [PRIVATEKEYFILE] listen-port [PORT INTEGER] public-key [PUBLICKEY] "
                                               "\n\t\t\t\t\t\t preshared-key [PRESHAREDKEY] preshared-key-file [PRESHAREDKEYFILE] "
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
               "  show-dns-mode                dev [DEVICE] Displays dns mode of device.\n"
               "  show-dhcp-mode               dev [DEVICE] Displays dhcp mode of device.\n"
               "  edit                         dev [DEVICE] Edit network configuration of device.\n"
               "  edit-link                    dev [DEVICE] Edit link configuration of device.\n"
               "  set-link                     [LINK] [alias STRING] [desc STRING] [mtu STRING]  [bps STRING]  [duplex STRING] [wol STRING | List] [wolp STRING] "
                                                       "\n\t\t\t\t    [port STRING] [advertise STRING | List]"
                                                       "\n\t\t\t\t    Configure link's other parameters like mtuytes, bitspersecond, duplex, wakeonlan, wakeonlanpassword, port and advertise.\n"
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
               "  add-link-sr-iov              [LINK] [vf INTEGER] [vlanid INTEGER] [qos INTEGER] [vlanproto STRING] [macspoofck BOOLEAN] [qrss BOOLEAN]"
                                                     "\n\t\t\t\t      [trust BOOLEAN] [linkstate BOOLEAN or STRING] [macaddr ADDRESS] Configures SR-IOV VirtualFunction, "
                                                     "\n\t\t\t\t      VLANId, QualityOfService, VLANProtocol, MACSpoofCheck, QueryReceiveSideScaling, Trust, LinkState, MACAddress \n"

               "  set-proxy                    [enable {BOOLEAN}] [http|https|ftp|gopher|socks|socks5|noproxy] [CONFIGURATION | none] Configure proxy.\n"
               "  show-proxy                   Shows proxy configuration.\n"
               "  apply-file                   [FILE] Generates network file configuration from yaml file.\n"
               "  apply                        Generates network file configuration from yaml files found in /etc/network-config-manager/yaml.\n"
               "  apply-cmdline                [FILE | COMMAND LINE] Generates network file configuration from command kernel command line or command line.\n"
               "  set-systemd-networkd-debug   debug [BOOLEAN] sets sytstemd-networkd into debug mode.\n"
#if HAVE_NFTABLES
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
#endif
               , program_invocation_short_name
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x604,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'   },
                { "version",     no_argument,       NULL, 'v'   },
                { "json",        no_argument,       NULL, 'j'   },
                { "network",     no_argument,       NULL, 'n'   },
                { "no-beautify", no_argument,       NULL, 'b'   },
                { "alias",       no_argument,       NULL, 'a'   },
                { "log",         optional_argument, NULL, 'l'   },
                {}
        };
        int r, c, l = 0;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ahvjnbl", options, 0)) >= 0) {
                switch (c) {
                case 'h':
                        return help();
                case 'v':
                        return ncm_show_version();
                case 'j':
                        set_json(true);
                        break;
                case 'n':
                        set_network_json(true);
                        break;
                case 'b':
                        set_beautify(false);
                        break;
                case 'a':
                        alias = true;
                        break;
                case 'l':
                        for (int i = optind; i < argc; ++i) {
                                r = parse_int(argv[i], &l);
                                if (r < 0) {
                                        printf("Failed to parse log line: %s\n", argv[i]);
                                        return -EINVAL;
                                }
                        }

                        if (l == 0)
                                l = DEFAULT_LOG_LINE_SIZE;
                        set_log(true, l);
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
        _cleanup_(ctl_freep) CtlManager *m = NULL;
        int r;

        static const Ctl commands[] = {
                { "status",                        "s",                WORD_ANY, WORD_ANY, true,  ncm_system_status },
                { "status-devs",                   "sd",               WORD_ANY, WORD_ANY, false, ncm_link_status },
                { "show-ipv4-status",              "s4s",              1,        WORD_ANY, false, ncm_system_ipv4_status },
                { "set-mtu",                       "mtu",              3,        WORD_ANY, false, ncm_link_set_mtu },
                { "set-mac",                       "mac",              3,        WORD_ANY, false, ncm_link_set_mac },
                { "set-manage",                    "manage" ,          3,        WORD_ANY, false, ncm_link_set_mode },
                { "set-link-option",               "lopt",             4,        WORD_ANY, false, ncm_link_set_option },
                { "set-link-group",                "lgrp",             4,        WORD_ANY, false, ncm_link_set_group },
                { "set-link-rfo",                  "lrfo",             4,        WORD_ANY, false, ncm_link_set_rf_online },
                { "set-link-ap",                   "lap",              4,        WORD_ANY, false, ncm_link_set_act_policy },
                { "set-dhcp",                      "dhcp",             4,        WORD_ANY, false, ncm_link_set_dhcp_client_kind },
                { "set-dhcp4-cid",                 "dhcp4-cid",        3,        WORD_ANY, false, ncm_link_set_dhcp4_client_identifier},
                { "set-dhcp-iaid",                 "dhcp-iaid",        4,        WORD_ANY, false, ncm_link_set_dhcp_client_iaid},
                { "set-dhcp-duid",                 "dhcp-duid",        4,        WORD_ANY, false, ncm_link_set_dhcp_client_duid},
                { "set-link-state",                "ls",               3,        WORD_ANY, false, ncm_link_update_state },
                { "show-addr",                     "a",                1,        WORD_ANY, false, ncm_display_one_link_addresses },
                { "add-addr",                      "aa",               4,        WORD_ANY, false, ncm_link_add_address },
                { "remove-addr",                   "raddr",            3,        WORD_ANY, false, ncm_link_remove_address },
                { "replace-addr",                  "repa",             3,        WORD_ANY, false, ncm_link_replace_address },
                { "set-gw",                        "sgw",              4,        WORD_ANY, false, ncm_link_set_default_gateway },
                { "set-gw-family",                 "sgwf",             4,        WORD_ANY, false, ncm_link_set_default_gateway_family },
                { "remove-gw",                     "rgw",              2,        WORD_ANY, false, ncm_link_remove_gateway },
                { "add-route",                     "ar" ,              4,        WORD_ANY, false, ncm_link_add_route },
                { "set-dynamic",                   "sd" ,              2,        WORD_ANY, false, ncm_link_set_dynamic },
                { "set-static",                    "ss" ,              2,        WORD_ANY, false, ncm_link_set_static },
                { "set-network",                   "sn" ,              2,        WORD_ANY, false, ncm_link_set_network },
                { "remove-route",                  "rr",               4,        WORD_ANY, false, ncm_link_remove_route },
                { "set-rule",                      "srule",              9,      WORD_ANY, false, ncm_link_set_routing_policy_rule },
                { "add-rule",                      "rule",             4,        WORD_ANY, false, ncm_link_add_routing_policy_rules },
                { "remove-rule",                   "rrule",            1,        WORD_ANY, false, ncm_link_remove_routing_policy_rules },
                { "set-hostname",                  "hostname",         1,        WORD_ANY, false, ncm_set_system_hostname },
                { "show-dns",                      "dns",              WORD_ANY, WORD_ANY, false, ncm_show_dns_server },
                { "set-dns",                       "sdns",             2,        WORD_ANY, false, ncm_set_dns_server },
                { "set-dns-domains",               "sdnsdomains",      4,        WORD_ANY, false, ncm_set_dns_domains },
                { "show-domains",                  "domain",           WORD_ANY, WORD_ANY, false, ncm_show_dns_server_domains },
                { "revert-resolve-link",           "rrl",              1,        WORD_ANY, false, ncm_revert_resolve_link },
                { "show-ntp",                      "ntp",              WORD_ANY, WORD_ANY, false, ncm_show_ntp_servers },
                { "set-ipv6mtu",                   "mtu6",             3,        WORD_ANY, false, ncm_link_set_network_ipv6_mtu },
                { "set-lla",                       "lla",              3,        WORD_ANY, false, ncm_link_set_link_local_address },
                { "set-ipv4ll-route",              "ipv4ll-route",     3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-llmnr",                     "llmnr",            3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-mcast-dns",                 "mcast-dns",        3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-lldp",                      "lldp",             3,        WORD_ANY, false, ncm_link_set_network_section_lldp },
                { "set-ipforward",                 "ipfwd",            3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-ipv6acceptra",              "ipv6ara",          3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-ipmasquerade",              "ipmasq",           3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-ipv4proxyarp",              "pxyarp4",          3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-ipv6proxyndp",              "pxyndp6",          3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-conf-wc",                   "cwc",              3,        WORD_ANY, false, ncm_link_set_network_section },
                { "set-ipv6dad",                   "ipv6dad",          3,        WORD_ANY, false, ncm_link_set_network_ipv6_dad },
                { "set-ipv6-ll-addr-gen-mode",     "ipv6llagm",        3,        WORD_ANY, false, ncm_link_set_network_ipv6_link_local_address_generation_mode},
                { "set-dhcp4",                     "dhcp4",            4,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp6",                     "dhcp6",            4,        WORD_ANY, false, ncm_link_set_dhcp6_section },
                { "add-dhcpv4-server",             "adhcp4-srv" ,      2,        WORD_ANY, false, ncm_link_add_dhcpv4_server },
                { "remove-dhcpv4-server",          "rdhcp4-srv",       2,        WORD_ANY, false, ncm_link_remove_dhcpv4_server },
                { "add-dhcpv4-static-addr",        "adhcp4-srv-sa",    6,        WORD_ANY, false, ncm_link_add_dhcpv4_server_static_address },
                { "remove-dhcpv4-static-addr",     "rdhcp4-srv-sa",    4,        WORD_ANY, false, ncm_link_remove_dhcpv4_server_static_address },
                { "add-ipv6ra",                    "ra6",              2,        WORD_ANY, false, ncm_link_add_ipv6_router_advertisement },
                { "remove-ipv6ra",                 "rra6",             2,        WORD_ANY, false, ncm_link_remove_ipv6_router_advertisement },
                { "set-ntp",                       "sntp" ,            2,        WORD_ANY, false, ncm_link_set_ntp },
                { "remove-ntp",                    "rntp",             1,        WORD_ANY, false, ncm_link_remove_ntp },
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
                { "show-dns-mode",                 "sdm",              1,        WORD_ANY, false, ncm_get_dns_mode },
                { "show-dhcp-mode",                "sdhm",             1,        WORD_ANY, false, ncm_get_dhcp_mode },
                { "edit",                          "e" ,               1,        WORD_ANY, false, ncm_link_edit_network_config },
                { "edit-link",                     "el" ,              1,        WORD_ANY, false, ncm_link_edit_link_config },
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
                { "add-link-sr-iov",               "lsriov",           2,        WORD_ANY, false, ncm_configure_sr_iov},
                { "add-sr-iov",                    "sriov",            2,        WORD_ANY, false, ncm_configure_sr_iov},
                { "set-proxy",                     "pxy",              1,        WORD_ANY, false, ncm_configure_proxy },
                { "show-proxy",                    "spxy",             WORD_ANY, WORD_ANY, false, ncm_show_proxy },
                { "apply-file",                    "af",               1,        WORD_ANY, false, generate_networkd_config_from_yaml },
                { "apply",                         "apply",            WORD_ANY, WORD_ANY, false, generate_networkd_config_from_yaml },
                { "apply-cmdline",                 "applycmd",         WORD_ANY, WORD_ANY, false, generate_networkd_config_from_command_line },
                { "set-systemd-networkd-debug",    "debug",            WORD_ANY, WORD_ANY, false, ncm_enable_networkd_debug},
#if HAVE_NFTABLES
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
#endif
                /* VCSA */
                { "set-ipv4",                      "sip4" ,            4,        WORD_ANY, false, ncm_link_set_ipv4 },
                { "set-ipv6",                      "sip6" ,            4,        WORD_ANY, false, ncm_link_set_ipv6 },

                /* Deprecated */
                { "show",                          "",                 WORD_ANY, WORD_ANY, false, ncm_link_status },
                { "add-dns",                       "adns",             2,        WORD_ANY, false, ncm_set_dns_server },
                { "add-domain",                    "adomain",          1,        WORD_ANY, false, ncm_set_dns_domains },
                { "delete-gw",                     "dgw",              2,        WORD_ANY, false, ncm_link_remove_gateway },
                { "delete-route",                  "dr",               4,        WORD_ANY, false, ncm_link_remove_route },
                { "delete-ntp",                    "dntp",             1,        WORD_ANY, false, ncm_link_remove_ntp },
                { "del-addr",                      "da",               3,        WORD_ANY, false, ncm_link_remove_address },
                { "add-default-gw",                "gw",               4,        WORD_ANY, false, ncm_link_set_default_gateway },
                {}
        };

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (alias) {
                printf("%s   %28s\n", "Command", "Alias");
                for (size_t i = 0; i < ELEMENTSOF(commands); i++) {
                        if (!isempty(commands[i].alias))
                                printf("%-30s   %-30s\n", commands[i].name, commands[i].alias);
                }

                return 0;
        }

        if (!isempty(argv[1]) && !runs_without_networkd(argv[1]))
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

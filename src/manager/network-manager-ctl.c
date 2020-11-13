/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <getopt.h>
#include <network-config-manager.h>

#include "alloc-util.h"
#include "cli.h"
#include "log.h"
#include "macros.h"
#include "network-manager.h"

static int generate_networkd_config_from_yaml(int argc, char *argv[]) {
        _cleanup_(g_dir_unrefp) GDir *dir = NULL;
        const char *file = NULL;
        int r, i;

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
                for (i = 1; i < argc; i++) {
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
        uint32_t i;

        h = g_hash_table_new(g_str_hash, g_str_equal);
        if (!h) {
                log_oom();
                return false;
        }

        for (i = 0; i < ELEMENTSOF(cli_commands); i++)
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
               "\nCommands:\n"
               "  show                         Show system status\n"
               "  status                       List links\n"
               "  status                       [LINK] Show link status\n"
               "  set-mtu                      [LINK] [MTU] Set Link MTU\n"
               "  set-mac                      [LINK] [MAC] Set Link MAC\n"
               "  set-link-mode                [LINK] [MODE { yes | no | on | off | 1 | 0} ] Set Link managed by networkd\n"
               "  set-dhcp-mode                [LINK] [DHCP-MODE { yes | no | ipv4 | ipv6 } ] Set Link DHCP setting\n"
               "  set-dhcp4-client-identifier  [LINK] [IDENTIFIER { mac | duid | duid-only}\n"
               "  set-dhcp-iaid                [LINK] [IAID] Sets the DHCP Identity Association Identifier (IAID) for the interface, a 32-bit unsigned integer.\n"
               "  set-dhcp-duid                [LINK | system] [DUID { link-layer-time | vendor | link-layer | uuid } ] [RAWDATA] Sets the DHCP Client\n"
               "                                      DUID type which specifies how the DUID should be generated and [RAWDATA] to overides the global DUIDRawData.\n"
               "  set-link-state               [LINK] [STATE { up | down } ] Set Link State\n"
               "  add-link-address             [LINK] [ADDRESS] [PEER] ] Add Link Address\n"
               "  delete-link-address          [LINK] Removes Address from Link\n"
               "  add-default-gateway          [LINK] [GW address] onlink [ONLINK { yes | no | on | off | 1 | 0}] Add Link Default Gateway\n"
               "  delete-gateway               [LINK] Removes Gateway from Link\n"
               "  add-route                    [LINK] [GW address] metric [METRIC { number }] Set Link route\n"
               "  delete-route                 [LINK] Removes route from Link\n"
               "  add-additional-gw            [LINK] [ADDRESS] [ROUTE address] [GW address] [ROUTING POLICY TABLE number] configures additional gateway for"
                                                      "\n\t\t\t\t\t\t another NIC with routing policy rules\n"
               "  set-hostname                 [HOSTNAME] Sets hostname\n"
               "  show-dns                            Show DNS Servers\n"
               "  add-dns                      [LINK | system] [ADDRESS] Set Link DNS servers\n"
               "  add-domain                   [LINK | system] [DOMAIN] Set Link DOMAIN \n"
               "  show-domains                        Show DNS Server DOMAINS\n"
               "  revert-resolve-link          [LINK] Flushes all DNS server and Domain settings of the link\n"
               "  set-link-local-address       [LINK] [LinkLocalAddressing { yes | no | on | off | 1 | 0}] Set Link link-local address autoconfiguration\n"
               "  set-ipv4ll-route             [LINK] [IPv4LLRoute { yes | no | on | off | 1 | 0}] Set the route needed for non-IPv4LL hosts to communicate\n"
               "                                      with IPv4LL-only hosts\n"
               "  set-llmnr                    [LINK] [LLMNR { yes | no | on | off | 1 | 0}] Set Link Link-Local Multicast Name Resolution\n"
               "  set-multicast-dns            [LINK] [MulticastDNS { yes | no | on | off | 1 | 0}] Set Link Multicast DNS\n"
               "  set-lldp                     [LINK] [LLDP { yes | no | on | off | 1 | 0}] Set Link Ethernet LLDP packet reception\n"
               "  set-emit-lldp                [LINK] [EmitLLDP { yes | no | on | off | 1 | 0}] Set Link Ethernet LLDP packet emission\n"
               "  set-ipforward                [LINK] [IPForward { yes | no | on | off | 1 | 0}] Set Link IP packet forwarding for the system\n"
               "  set-ipv6acceptra             [LINK] [IPv6AcceptRA { yes | no | on | off | 1 | 0}] Set Link IPv6 Router Advertisement (RA) reception support for the interface\n"
               "  set-ipmasquerade             [LINK] [IPMasquerade { yes | no | on | off | 1 | 0}] Set IP masquerading for the network interface\n"
               "  set-dhcp4-use-dns            [LINK] [UseDNS { yes | no | on | off | 1 | 0}] Set Link DHCP4 Use DNS\n"
               "  set-dhcp4-use-domains        [LINK] [UseDomains { yes | no | on | off | 1 | 0}] Set Link DHCP4 Use DOMAINS\n"
               "  set-dhcp4-use-mtu            [LINK] [UseMTU { yes | no | on | off | 1 | 0}] Set Link DHCP4 Use MTU\n"
               "  set-dhcp4-use-ntp            [LINK] [UseNTP { yes | no | on | off | 1 | 0}] Set Link DHCP4 Use NTP\n"
               "  set-dhcp4-use-dns            [LINK] [UseDNS { yes | no | on | off | 1 | 0}] Set Link DHCP4 Use DNS\n"
               "  set-dhcp6-use-dns            [LINK] [UseDNS { yes | no | on | off | 1 | 0}] Set Link DHCP6 Use DNS\n"
               "  set-dhcp6-use-ntp            [LINK] [UseNTP { yes | no | on | off | 1 | 0}] Set Link DHCP6 Use NTP\n"
               "  add-ntp                      [LINK] [NTP] Add Link NTP server address. This option may be specified more than once.\n"
               "                                      This setting is read by systemd-timesyncd.service(8)\n"
               "  set-ntp                      [LINK] [NTP] Set Link NTP server address. This option may be specified more than once.\n"
               "                                      This setting is read by systemd-timesyncd.service(8)\n"
               "  delete-ntp                   [LINK] Delete Link NTP server addresses.\n"
               "                                      This setting is read by systemd-timesyncd.service(8)\n"
               "  disable-ipv6                 [LINK] Disables IPv6 on the interface.\n"
               "  enable-ipv6                  [LINK] Enables IPv6 on the interface.\n"
               "  create-vlan                  [VLAN name] dev [LINK master] id [ID INTEGER] Creates vlan netdev and sets master to device\n"
               "  create-bridge                [BRIDGE name] [LINK] [LINK] ... Creates bridge netdev and sets master to device\n"
               "  create-bond                  [BOND name] mode [MODE {balance-rr | active-backup | balance-xor | broadcast | 802.3ad | balance-tlb | balance-alb}]"
                                               "\n\t\t\t\t[LINK] [LINK] ... Creates bond netdev and sets master to device\n"
               "  create-vxlan                 [VXLAN name] [dev LINK] vni [INTEGER] [local ADDRESS] [remote ADDRESS] [port PORT] [independent { yes | no | on | off | 1 | 0}]."
                                               "\n\t\t\t\tCreates vxlan VXLAN (Virtual eXtensible Local Area Network) tunneling.\n"
               "  create-macvlan               [MACVLAN name] dev [LINK] mode [MODE {private | vepa | bridge | passthru | source}] Creates macvlan virtualized bridged networking.\n"
               "  create-macvtap               [MACVTAP name] dev [LINK] mode [MODE {private | vepa | bridge | passthru | source}] Creates macvtap virtualized bridged networking.\n"
               "  create-ipvlan                [IPVLAN name] dev [LINK] mode [MODE {l2 | l3 | l3s}] Creates ipvlan, virtual LAN, separates broadcast domains by adding tags to network packet.\n"
               "  create-ipvtap                [IPVTAP name] dev [LINK] mode [MODE {l2 | l3 | l3s}] Create ipvtap.\n"
               "  create-vrf                   [VRF name] table [INTEGER}] Creates Virtual routing and forwarding (VRF).\n"
               "  create-veth                  [VETH name] peer [PEER name}] Creates virtual Ethernet devices\n"
               "  create-ipip                  [IPIP name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent { yes | no | on | off | 1 | 0}] Creates ipip tunnel.\n"
               "  create-sit                   [SIT name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent { yes | no | on | off | 1 | 0}] Creates sit tunnel.\n"
               "  create-vti                   [VTI name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent { yes | no | on | off | 1 | 0}] Creates vti tunnel.\n"
               "  create-gre                   [GRE name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent { yes | no | on | off | 1 | 0}] Creates gre tunnel.\n"
               "  create-wg                    [WIREGUARD name] private-key [PRIVATEKEY] listen-port [PORT INTEGER] public-key [PUBLICKEY] preshared-key [PRESHAREDKEY]"
                                               "\n\t\t\t\t\t\t allowed-ips [IP,IP ...] endpoint [IP:PORT] Creates a wireguard tunnel.\n"
               "  reload                       Reload .network and .netdev files.\n"
               "  reconfigure                  [LINK] Reconfigure Link.\n"
               "  generate-config-from-yaml    [FILE] Generates network file configuration from yaml file.\n"
               "  apply-yaml-config            Generates network file configuration from yaml files found in /etc/network-config-manager/yaml.\n"
               "  generate-config-from-cmdline [FILE | COMMAND LINE] Generates network file configuration from command kernel command line or command line.\n"
               "  add-nft-table                [FAMILY {ipv4 | ipv6 | ip}] [TABLE] adds a new table.\n"
               "  show-nft-tables              [FAMILY {ipv4 | ipv6 | ip}] shows nftable's tables.\n"
               "  delete-nft-table             [FAMILY {ipv4 | ipv6 | ip}] [TABLE] deletes a existing nftable's table.\n"
               "  add-nft-chain                [FAMILY {ipv4 | ip}] [TABLE] [CHAIN] adds a new nftable's chain.\n"
               "  show-nft-chains              [FAMILY {ipv4 | ipv6 | ip}] [TABLE] shows nftable's chains.\n"
               "  delete-nft-chain             [FAMILY {ipv4 | ipv6 | ip}] [TABLE] [CHAIN] deletes a nftable's chain from table\n"
               "  add-nft-rule                 [FAMILY {ipv4 | ipv6 | ip}] [TABLE] [CHAIN] [PROTOCOL { tcp | udp}] [SOURCE PORT / DESTINATION PORT {sport|dport}]"
                                                       "\n\t\t\t\t\t\t [PORT] [ACTION {accept | drop}] configures a nft rule for a port.\n"
               "  show-nft-rules               [TABLE] shows nftable's rules.\n"
               "  delete-nft-rule              [FAMILY {ipv4 | ipv6 | ip}] [TABLE] [CHAIN] [HANDLE] deletes a nftable's rule from table\n"
               "  nft-run                      runs a nft command.  See man NFT(8)\n"
               , program_invocation_short_name
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'   },
                { "version",   no_argument,       NULL, 'v'   },
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

                case '?':
                        return -EINVAL;

                default:
                        assert(0);
                }
        }

        return 1;
}

static int cli_run(int argc, char *argv[]) {
        _cleanup_(cli_unrefp) CliManager *m = NULL;
        int r;

        static const Cli commands[] = {
                { "status",                       WORD_ANY, WORD_ANY, true,  ncm_system_status },
                { "show",                         WORD_ANY, WORD_ANY, false, ncm_link_status },
                { "set-mtu",                      2,        WORD_ANY, false, ncm_link_set_mtu },
                { "set-mac",                      2,        WORD_ANY, false, ncm_link_set_mac },
                { "set-link-mode",                2,        WORD_ANY, false, ncm_link_set_mode },
                { "set-dhcp-mode",                2,        WORD_ANY, false, ncm_link_set_dhcp_mode },
                { "set-dhcp4-client-identifier",  2,        WORD_ANY, false, ncm_link_set_dhcp4_client_identifier},
                { "set-dhcp-iaid",                2,        WORD_ANY, false, ncm_link_set_dhcp_client_iaid},
                { "set-dhcp-duid",                2,        WORD_ANY, false, ncm_link_set_dhcp_client_duid},
                { "set-link-state",               2,        WORD_ANY, false, ncm_link_update_state },
                { "add-link-address",             2,        WORD_ANY, false, ncm_link_add_address },
                { "delete-link-address",          1,        WORD_ANY, false, ncm_link_delete_address },
                { "add-default-gateway",          2,        WORD_ANY, false, ncm_link_add_default_gateway },
                { "delete-gateway",               1,        WORD_ANY, false, ncm_link_delete_gateway_or_route },
                { "add-route",                    2,        WORD_ANY, false, ncm_link_add_route },
                { "delete-route",                 1,        WORD_ANY, false, ncm_link_delete_gateway_or_route },
                { "add-additional-gw",            5,        WORD_ANY, false, ncm_link_add_additional_gw },
                { "set-hostname",                 1,        WORD_ANY, false, ncm_set_system_hostname },
                { "show-dns",                     WORD_ANY, WORD_ANY, false, ncm_show_dns_server },
                { "add-dns",                      2,        WORD_ANY, false, ncm_add_dns_server },
                { "add-domain",                   1,        WORD_ANY, false, ncm_add_dns_domains },
                { "show-domains",                 WORD_ANY, WORD_ANY, false, ncm_show_dns_server_domains },
                { "revert-resolve-link",          1,        WORD_ANY, false, ncm_revert_resolve_link },
                { "set-link-local-address",       2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-ipv4ll-route",             2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-llmnr",                    2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-multicast-dns",            2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-lldp",                     2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-emit-lldp",                2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-ipforward",                2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-ipv6acceptra",             2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-ipmasquerade",             2,        WORD_ANY, false, ncm_link_set_network_section_bool },
                { "set-dhcp4-use-dns",            2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-use-domains",        2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-use-ntp",            2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-use-mtu",            2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-use-timezone",       2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp4-use-routes",         2,        WORD_ANY, false, ncm_link_set_dhcp4_section },
                { "set-dhcp6-use-dns",            2,        WORD_ANY, false, ncm_link_set_dhcp6_section },
                { "set-dhcp6-use-ntp",            2,        WORD_ANY, false, ncm_link_set_dhcp6_section },
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
                { "reload",                       WORD_ANY, WORD_ANY, false, ncm_network_reload },
                { "reconfigure",                  1,        WORD_ANY, false, ncm_link_reconfigure },
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
                {}
        };

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (!isempty_string(argv[1]) && !runs_without_networkd(argv[1]))
                if (!ncm_is_netword_running())
                        exit(-1);

        r = cli_manager_new(commands, &m);
        if (r < 0)
                return r;

        return cli_run_command(m, argc, argv);
}

int main(int argc, char *argv[]) {
        g_log_set_default_handler (g_log_default_handler, NULL);

        return cli_run(argc, argv);
}

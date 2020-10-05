#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright © 2020 VMware, Inc.

import os
import sys
import subprocess
import time
import shutil
import configparser
import pytest
import collections

networkd_unit_file_path = '/etc/systemd/network'

network_config_manager_ci_path = '/run/network-config-manager-ci'
network_config_manager_ci_yaml_path = '/run/network-config-manager-ci/yaml'

network_config_manager_config_path = '/etc/network-config-manager'
network_config_manager_yaml_config_path = '/etc/network-config-manager/yaml'

network_config_manager_wpa_supplilant_conf_file = '/etc/network-config-manager/wpa_supplicant.conf'

units = ["10-test99.network", "10-test98.network", "10-wlan1.network", "10-wlan0.network"]

def link_exits(link):
    return os.path.exists(os.path.join('/sys/class/net', link))

def link_remove(link):
    if os.path.exists(os.path.join('/sys/class/net', link)):
        subprocess.call(['ip', 'link', 'del', 'dev', link])

def link_add_dummy(link):
    subprocess.call(['ip', 'link', 'add', 'dev', link, 'type', 'dummy'])

def unit_exits(unit):
    return os.path.exists(os.path.join(networkd_unit_file_path, unit))

def wifi_wpa_supplilant_conf_exits():
    return os.path.exists(network_config_manager_wpa_supplilant_conf_file)

def remove_units_from_netword_unit_path():
    for i in units:
        if (os.path.exists(os.path.join(networkd_unit_file_path, i))):
            os.remove(os.path.join(networkd_unit_file_path, i))

def restart_networkd():
    subprocess.call(['systemctl', 'restart', 'systemd-networkd'])
    subprocess.check_call(['sleep', '5'])

def dequote(s):
    if len(s) < 2:
        return v

    s = s.replace('"', '')

    return s

def read_wpa_supplicant_conf(conf_file):
    networks = None

    if not os.path.isfile(conf_file):
        print("File path {} does not exist".format(conf_file))
        return None

    with open(conf_file) as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.startswith('network'):
                networks = collections.OrderedDict()
                continue

            if line.startswith('}'):
                break

            if (networks is None):
                continue

            x = line.split('=', 1)
            k = x[0].strip()
            v = dequote(x[1].strip())
            networks[k] = v

    return networks

class TestNetworkConfigManagerYAML:
    yaml_configs = [
        "dhcp.yaml",
        "dhcp-client-identifier.yaml",
        "network-section-dhcp-section.yaml",
        "static-network.yaml",
        "static-route-network.yaml",
    ]

    def copy_yaml_file_to_netmanager_yaml_path(self, config_file):
        shutil.copy(os.path.join(network_config_manager_ci_yaml_path, config_file), network_config_manager_yaml_config_path)

    def remove_units_from_netmanager_yaml_path(self):
        for config_file in self.yaml_configs:
            if (os.path.exists(os.path.join(network_config_manager_yaml_config_path, config_file))):
                os.remove(os.path.join(network_config_manager_yaml_config_path, config_file))

    def setup_method(self):
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()

    def teardown_method(self):
        self.remove_units_from_netmanager_yaml_path()
        remove_units_from_netword_unit_path()

    def test_basic_dhcp(self):
        self.copy_yaml_file_to_netmanager_yaml_path('dhcp.yaml')

        subprocess.check_call(['nmctl', 'apply-yaml-config'])
        assert(unit_exits('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'yes')

    def test_dhcp_client_identifier(self):
        self.copy_yaml_file_to_netmanager_yaml_path('dhcp-client-identifier.yaml')

        subprocess.check_call(['nmctl', 'apply-yaml-config'])
        assert(unit_exits('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'yes')
        assert(parser.get('DHCPv4', 'ClientIdentifier') == 'mac')

    def test_network_and_dhcp4_section(self):
        self.copy_yaml_file_to_netmanager_yaml_path('network-section-dhcp-section.yaml')

        subprocess.check_call(['nmctl', 'apply-yaml-config'])
        assert(unit_exits('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'yes')
        assert(parser.get('Network', 'LLDP') == 'yes')
        assert(parser.get('Network', 'LinkLocalAddressing') == 'yes')
        assert(parser.get('Network', 'IPv6AcceptRA') == 'yes')

        assert(parser.get('DHCPv4', 'UseDNS') == 'yes')
        assert(parser.get('DHCPv4', 'UseDomains') == 'yes')
        assert(parser.get('DHCPv4', 'UseMTU') == 'yes')
        assert(parser.get('DHCPv4', 'UseNTP') == 'yes')

    def test_network_and_dhcp6_section(self):
        self.copy_yaml_file_to_netmanager_yaml_path('network-section-dhcp6-section.yaml')

        subprocess.check_call(['nmctl', 'apply-yaml-config'])
        assert(unit_exits('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'yes')
        assert(parser.get('Network', 'LinkLocalAddressing') == 'yes')
        assert(parser.get('Network', 'IPv6AcceptRA') == 'yes')

        assert(parser.get('DHCPv6', 'UseDNS') == 'yes')
        assert(parser.get('DHCPv6', 'UseNTP') == 'yes')

    @pytest.mark.skip(reason="skipping")
    def test_network_static_configuration(self):
        self.copy_yaml_file_to_netmanager_yaml_path('static-network.yaml')

        subprocess.check_call(['nmctl', 'apply-yaml-config'])
        assert(unit_exits('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

        assert(parser.get('Network', 'DNS') == "8.8.8.8 192.168.0.1")
        assert(parser.get('Network', 'NTP') == "8.8.8.1 192.168.0.2")

        assert(parser.get('Address', 'Address') == '192.168.1.45/24')

        assert(parser.get('Route', 'Gateway') == '192.168.1.1/24')
        assert(parser.get('Route', 'GatewayOnlink') == 'yes')

    def test_network_static_route_configuration(self):
        self.copy_yaml_file_to_netmanager_yaml_path('static-route-network.yaml')

        subprocess.check_call(['nmctl', 'apply-yaml-config'])
        assert(unit_exits('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

        assert(parser.get('Network', 'DNS') == "8.8.8.8 192.168.0.1")
        assert(parser.get('Network', 'NTP') == "8.8.8.1 192.168.0.2")

        assert(parser.get('Address', 'Address') == '192.168.1.101/24')

        assert(parser.get('Route', 'Gateway') == '9.0.0.1')

class TestKernelCommandLine:
    def teardown_method(self):
        remove_units_from_netword_unit_path()

    def test_network_kernel_command_line_ip_dhcp(self):
        ''' ip=<interface>:{dhcp|on|any|dhcp6|auto6} '''

        subprocess.check_call(['nmctl', 'generate-config-from-cmdline', 'ip=test99:dhcp'])
        assert(unit_exits('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')

    def test_network_kernel_command_line_multiple_ip_dhcp(self):
        ''' ip=<interface>:{dhcp|on|any|dhcp6|auto6} '''

        subprocess.check_call(['nmctl', 'generate-config-from-cmdline', 'ip=test99:dhcp ip=test98:dhcp'])
        assert(unit_exits('10-test99.network') == True)
        assert(unit_exits('10-test98.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')

        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'DHCP') == 'ipv4')

    def test_network_kernel_command_line_ip_static(self):
        ''' ip=<client-IP>:[ <server-id>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off}'''

        subprocess.check_call(['nmctl', 'generate-config-from-cmdline', 'ip=192.168.1.34::192.168.1.1:::test99:dhcp'])
        assert(unit_exits('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')
        assert(parser.get('Route', 'Gateway') == '192.168.1.1/32')
        assert(parser.get('Address', 'Address') == '192.168.1.34')

class TestCLI:
    def setup_method(self):
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        link_remove('test99')

    def test_cli_set_mtu(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-mtu', 'test99', '1400'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'MTUBytes') == '1400')

    def test_cli_set_mac(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-mac', 'test99', '00:0c:29:3a:bc:11'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'MACAddress') == '00:0c:29:3a:bc:11')

    def test_cli_set_dhcp_type(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-dhcp-mode', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'yes')

    def test_cli_set_dhcp_iaid(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-dhcp-mode', 'test99', 'ipv4'])
        subprocess.check_call(['nmctl', 'set-dhcp-iaid', 'test99', '5555'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCP', 'IAID') == '5555')

    def test_cli_add_static_address(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'add-link-address', 'test99', '192.168.1.45/24'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Address', 'Address') == '192.168.1.45/24')

    def test_cli_add_default_gateway(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'add-link-address', 'test99', '192.168.1.45/24'])
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Address', 'Address') == '192.168.1.45/24')

        subprocess.check_call(['nmctl', 'set-link-state', 'test99', 'up'])

        subprocess.check_call(['nmctl', 'add-default-gateway', 'test99', '192.168.1.1', 'onlink', 'true'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Route', 'Gateway') == '192.168.1.1')

    def test_cli_add_route(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'add-link-address', 'test99', '192.168.1.45/24'])
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Address', 'Address') == '192.168.1.45/24')

        subprocess.check_call(['nmctl', 'add-route', 'test99', '10.10.10.10'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Route', 'Destination') == '10.10.10.10')

    def test_cli_add_dns(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'add-dns', 'test99', '192.168.1.45', '192.168.1.46'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

    def test_cli_add_domain(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'add-domain', 'test99', 'domain1', 'domain2'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'Domains') == 'domain2 domain1')

    def test_cli_add_ntp(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'add-ntp', 'test99', '192.168.1.34', '192.168.1.45'])
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'NTP') == '192.168.1.45 192.168.1.34')

    def test_cli_set_ip_v6_router_advertisement(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-ipv6acceptra', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPv6AcceptRA') == 'true')

    def test_cli_set_link_local_addressing(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['nmctl', 'set-link-local-address', 'test99', 'yes'])

        subprocess.check_call(['sleep', '5'])
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LinkLocalAddressing') == 'true')

    def test_cli_set_ipv4_link_local_route(self):
        assert(link_exits('test99') == True);

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-ipv4ll-route', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPv4LLRoute') == 'true')

    def test_cli_set_llmnr(self):
        assert(link_exits('test99') == True);

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['nmctl', 'set-llmnr', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LLMNR') == 'true')

    def test_cli_set_multicast_dns(self):
        assert(link_exits('test99') == True);

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])

        subprocess.check_call(['nmctl', 'set-multicast-dns', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'MulticastDNS') == 'true')

    def test_cli_set_ip_masquerade(self):
        assert(link_exits('test99') == True);

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-ipmasquerade', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPMasquerade') == 'true')


    def test_cli_set_dhcp4_client_identifier(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-dhcp4-client-identifier', 'test99', 'mac'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'ClientIdentifier') == 'mac')

    def test_cli_set_dhcp4_use_dns(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-dhcp4-use-dns', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseDNS') == 'true')

    def test_cli_set_dhcp4_use_mtu(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-dhcp4-use-mtu', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

    def test_cli_set_dhcp4_use_domains(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-dhcp4-use-domains', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseDomains') == 'true')

    def test_cli_set_dhcp4_use_ntp(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-dhcp4-use-ntp', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseNTP') == 'true')

    def test_cli_set_dhcp4_use_routes(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['nmctl', 'set-dhcp4-use-routes', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseRoutes') == 'true')

    def test_cli_set_link_lldp(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-lldp', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LLDP') == 'true')

    def test_cli_set_link_emit_lldp(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-emit-lldp', 'test99', 'yes'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'EmitLLDP') == 'true')


class TestWifiWPASupplicantConf:
    yaml_configs = [
        "name-password-wifi-dhcp.yaml",
        "name-password-wifi-static.yaml",
        "wpa-eap-tls-wifi.yaml",
        "wpa-eap-ttls.yaml",
    ]

    def copy_yaml_file_to_netmanager_yaml_path(self, config_file):
        shutil.copy(os.path.join(network_config_manager_ci_yaml_path, config_file), network_config_manager_yaml_config_path)

    def remove_units_from_netmanager_yaml_path(self):
        for config_file in self.yaml_configs:
            if (os.path.exists(os.path.join(network_config_manager_yaml_config_path, config_file))):
                os.remove(os.path.join(network_config_manager_yaml_config_path, config_file))

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        self.remove_units_from_netmanager_yaml_path()

    def test_wifi_wpa_supplicant_name_password_dhcp(self):
        self.copy_yaml_file_to_netmanager_yaml_path('name-password-wifi-dhcp.yaml')

        subprocess.check_call(['nmctl', 'apply-yaml-config'])
        assert(unit_exits('10-wlan1.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-wlan1.network'))

        assert(parser.get('Match', 'Name') == 'wlan1')
        assert(parser.get('Network', 'DHCP') == 'yes')

        assert(wifi_wpa_supplilant_conf_exits() == True)

        network = read_wpa_supplicant_conf(network_config_manager_wpa_supplilant_conf_file)
        assert(network["ssid"] == "network_ssid_name1")
        assert(network["password"] == "test123")

    def test_wifi_wpa_supplicant_name_password_static(self):
        self.copy_yaml_file_to_netmanager_yaml_path('name-password-wifi-static.yaml')

        subprocess.check_call(['nmctl', 'apply-yaml-config'])
        assert(unit_exits('10-wlan1.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-wlan1.network'))

        assert(parser.get('Match', 'Name') == 'wlan1')
        assert(parser.get('Route', 'Gateway') == '192.168.1.1/24')
        assert(parser.get('Route', 'GatewayOnlink') == 'yes')

        assert(wifi_wpa_supplilant_conf_exits() == True)

        network = read_wpa_supplicant_conf(network_config_manager_wpa_supplilant_conf_file)
        if network is None:
            assert(False)

        assert(network["ssid"] == "network_ssid_name1")
        assert(network["password"] == "test123")

    def atest_wifi_wpa_supplicant_eap_tls_dhcp(self):
        self.copy_yaml_file_to_netmanager_yaml_path('wpa-eap-tls-wifi.yaml')

        subprocess.check_call(['nmctl', 'apply-yaml-config'])
        assert(unit_exits('10-wlan1.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-wlan1.network'))

        assert(parser.get('Match', 'Name') == 'wlan1')
        assert(parser.get('Network', 'DHCP') == 'yes')

        assert(wifi_wpa_supplilant_conf_exits() == True)

        network = read_wpa_supplicant_conf(network_config_manager_wpa_supplilant_conf_file)
        if network is None:
            assert(False)

        assert(network["ssid"] == "network_ssid_name1")
        assert(network["eap"] == "PEAP")
        assert(network["identity"] == "cert-max@test.example.com")
        assert(network["anonymous_identity"] == "@test.example.com")
        assert(network["ca_cert"] == "/etc/ssl/cust-cacrt.pem")
        assert(network["client_cert"] == "/etc/ssl/cust-crt.pem")
        assert(network["private_key"] == "/etc/ssl/cust-key.pem")
        assert(network["private_key_passwd"] == "QZTrSEtq:h_d.W7_")

    def test_wifi_wpa_supplicant_eap_ttls_dhcp(self):
        self.copy_yaml_file_to_netmanager_yaml_path('wpa-eap-ttls.yaml')

        subprocess.check_call(['nmctl', 'apply-yaml-config'])
        assert(unit_exits('10-wlan0.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-wlan0.network'))

        assert(parser.get('Match', 'Name') == 'wlan0')
        assert(parser.get('Network', 'DHCP') == 'yes')

        assert(wifi_wpa_supplilant_conf_exits() == True)

        network = read_wpa_supplicant_conf(network_config_manager_wpa_supplilant_conf_file)
        if network is None:
            assert(False)

        assert(network["ssid"] == "network_ssid_name1")
        assert(network["identity"] == "max@internal.example.com")
        assert(network["anonymous_identity"] == "@test.example.com")
        assert(network["password"] == "test123")

def setUpModule():
    if not os.path.exists(network_config_manager_yaml_config_path):
        os.makedirs(network_config_manager_yaml_config_path)

    if not os.path.exists(network_config_manager_yaml_config_path):
        shutil.mkdirs(network_config_manager_yaml_config_path)

def tearDownModule():
    if os.path.exists(network_config_manager_ci_path):
        shutil.rmtree(network_config_manager_ci_path)

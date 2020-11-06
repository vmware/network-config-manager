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
import unittest

networkd_unit_file_path = '/etc/systemd/network'

network_config_manager_ci_path = '/run/network-config-manager-ci'
network_config_manager_ci_yaml_path = '/run/network-config-manager-ci/yaml'

network_config_manager_config_path = '/etc/network-config-manager'
network_config_manager_yaml_config_path = '/etc/network-config-manager/yaml'

network_config_manager_wpa_supplilant_conf_file = '/etc/network-config-manager/wpa_supplicant.conf'

units = ["10-test99.network",
         "10-test98.network",
         '10-test-99.network',
         "10-wlan1.network",
         "10-wlan0.network",
         '10-test98.network',
         '10-vlan-98.network',
         '10-vlan-98.netdev',
         '10-vlan-98.network',
         '10-vxlan-98.network',
         '10-vxlan-98.netdev',
         '10-bridge-98.netdev',
         '10-bridge-98.network',
         '10-bond-98.netdev',
         '10-bond-98.network']

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

    @pytest.mark.skip(reason="skipping")
    def test_network_kernel_command_line_ip_dhcp(self):
        ''' ip=<interface>:{dhcp|on|any|dhcp6|auto6} '''

        subprocess.check_call(['nmctl', 'generate-config-from-cmdline', 'ip=test99:dhcp'])
        assert(unit_exits('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')

    @pytest.mark.skip(reason="skipping")
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

    @pytest.mark.skip(reason="skipping")
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

class TestCLINetwork:
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

    def test_cli_set_ntp(self):
        assert(link_exits('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mode', 'test99', 'yes'])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['nmctl', 'set-ntp', 'test99', '192.168.1.34', '192.168.1.45'])
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

class TestCLINetDev:
    def setup_method(self):
        link_remove('test98')
        link_add_dummy('test98')
        restart_networkd()

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        link_remove('test98')

    def test_cli_create_vlan(self):
        assert(link_exits('test98') == True)

        subprocess.check_call(['nmctl', 'create-vlan', 'test98', 'vlan-98', 'id', '11'])
        assert(unit_exits('10-test98.network') == True)
        assert(unit_exits('10-vlan-98.netdev') == True)
        assert(unit_exits('10-vlan-98.network') == True)

        subprocess.check_call(['sleep', '5'])

        assert(link_exits('vlan-98') == True)

        vlan_parser = configparser.ConfigParser()
        vlan_parser.read(os.path.join(networkd_unit_file_path, '10-vlan-98.netdev'))

        assert(vlan_parser.get('NetDev', 'Name') == 'vlan-98')
        assert(vlan_parser.get('NetDev', 'kind') == 'vlan')
        assert(vlan_parser.get('VLAN', 'id') == '11')

        vlan_network_parser = configparser.ConfigParser()
        vlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-vlan-98.network'))

        assert(vlan_network_parser.get('Match', 'Name') == 'vlan-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'VLAN') == 'vlan-98')

        link_remove('vlan-98')

    def test_cli_create_vxlan(self):
        assert(link_exits('test98') == True)

        subprocess.check_call(['nmctl', 'create-vxlan', 'dev', 'test98', 'vxlan-98', 'vni', '32', 'local', '192.168.1.2', 'remote', '192.168.1.3', 'port', '7777'])
        assert(unit_exits('10-test98.network') == True)
        assert(unit_exits('10-vxlan-98.network') == True)
        assert(unit_exits('10-vxlan-98.netdev') == True)

        subprocess.check_call(['sleep', '5'])

        assert(link_exits('vxlan-98') == True)

        vxlan_parser = configparser.ConfigParser()
        vxlan_parser.read(os.path.join(networkd_unit_file_path, '10-vxlan-98.netdev'))

        assert(vxlan_parser.get('NetDev', 'Name') == 'vxlan-98')
        assert(vxlan_parser.get('NetDev', 'kind') == 'vxlan')
        assert(vxlan_parser.get('VXLAN', 'VNI') == '32')
        assert(vxlan_parser.get('VXLAN', 'Local') == '192.168.1.2')
        assert(vxlan_parser.get('VXLAN', 'Remote') == '192.168.1.3')
        assert(vxlan_parser.get('VXLAN', 'DestinationPort') == '7777')

        vxlan_network_parser = configparser.ConfigParser()
        vxlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-vxlan-98.network'))

        assert(vxlan_network_parser.get('Match', 'Name') == 'vxlan-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'VXLAN') == 'vxlan-98')

        link_remove('vxlan-98')

    def test_cli_create_bridge(self):
        link_add_dummy('test-99')
        assert(link_exits('test98') == True)
        assert(link_exits('test-99') == True)

        subprocess.check_call(['nmctl', 'create-bridge', 'bridge-98', 'test98', 'test-99'])
        assert(unit_exits('10-test98.network') == True)
        assert(unit_exits('10-test-99.network') == True)
        assert(unit_exits('10-bridge-98.network') == True)
        assert(unit_exits('10-bridge-98.netdev') == True)

        subprocess.check_call(['sleep', '5'])

        assert(link_exits('bridge-98') == True)

        bridge_parser = configparser.ConfigParser()
        bridge_parser.read(os.path.join(networkd_unit_file_path, '10-bridge-98.netdev'))

        assert(bridge_parser.get('NetDev', 'Name') == 'bridge-98')
        assert(bridge_parser.get('NetDev', 'kind') == 'bridge')

        bridge_network_parser = configparser.ConfigParser()
        bridge_network_parser.read(os.path.join(networkd_unit_file_path, '10-bridge-98.network'))

        assert(bridge_network_parser.get('Match', 'Name') == 'bridge-98')

        test98_parser = configparser.ConfigParser()
        test98_parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(test98_parser.get('Match', 'Name') == 'test98')
        assert(test98_parser.get('Network', 'Bridge') == 'bridge-98')

        test99_parser = configparser.ConfigParser()
        test99_parser.read(os.path.join(networkd_unit_file_path, '10-test-99.network'))

        assert(test99_parser.get('Match', 'Name') == 'test-99')
        assert(test99_parser.get('Network', 'Bridge') == 'bridge-98')

        link_remove('bridge-98')
        link_remove('test-99')

    def test_cli_create_bond(self):
        link_add_dummy('test-99')
        assert(link_exits('test98') == True)
        assert(link_exits('test-99') == True)

        subprocess.check_call(['nmctl', 'create-bond', 'bond-98', 'mode', 'balance-rr', 'test98', 'test-99'])
        assert(unit_exits('10-test98.network') == True)
        assert(unit_exits('10-test-99.network') == True)
        assert(unit_exits('10-bond-98.network') == True)
        assert(unit_exits('10-bond-98.netdev') == True)

        subprocess.check_call(['sleep', '5'])

        assert(link_exits('bond-98') == True)

        bond_parser = configparser.ConfigParser()
        bond_parser.read(os.path.join(networkd_unit_file_path, '10-bond-98.netdev'))

        assert(bond_parser.get('NetDev', 'Name') == 'bond-98')
        assert(bond_parser.get('NetDev', 'kind') == 'bond')
        assert(bond_parser.get('Bond', 'Mode') == 'balance-rr')

        bond_network_parser = configparser.ConfigParser()
        bond_network_parser.read(os.path.join(networkd_unit_file_path, '10-bond-98.network'))

        assert(bond_network_parser.get('Match', 'Name') == 'bond-98')

        test98_parser = configparser.ConfigParser()
        test98_parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(test98_parser.get('Match', 'Name') == 'test98')
        assert(test98_parser.get('Network', 'Bond') == 'bond-98')

        test99_parser = configparser.ConfigParser()
        test99_parser.read(os.path.join(networkd_unit_file_path, '10-test-99.network'))

        assert(test99_parser.get('Match', 'Name') == 'test-99')
        assert(test99_parser.get('Network', 'Bond') == 'bond-98')

        link_remove('bond-98')
        link_remove('test-99')


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

    @pytest.mark.skip(reason="skipping")
    def test_wifi_wpa_supplicant_eap_tls_dhcp(self):
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

class TestNFTable(unittest.TestCase):
    def tearDown(self):
        subprocess.call(['nft', 'delete', 'table', 'testtable99'])

    def test_nmctl_add_table(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])

        output = subprocess.check_output(['nft', 'list', 'tables'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'table ip testtable99')

    def test_nmctl_show_table(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])

        output = subprocess.check_output(['nmctl', 'show-nft-tables'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')

    def test_nmctl_delete_table(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])

        output = subprocess.check_output(['nft', 'list', 'tables'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'table ip testtable99')
        subprocess.check_call(['nmctl', 'delete-nft-table', 'ipv4', 'testtable99'])

        output = subprocess.check_output(['nft', 'list', 'tables'], universal_newlines=True).rstrip()
        print(output)

        self.assertNotRegex(output, 'table ip testtable99')

    def test_nmctl_add_chain(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

    def test_nmctl_show_chain(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nmctl', 'show-nft-chains', 'ipv4', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

    def test_nmctl_delete_chain(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nmctl', 'show-nft-chains', 'ipv4', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['nmctl', 'delete-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertNotRegex(output, 'testchain99')

    def test_nmctl_add_rule_tcp_accept(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nmctl', 'show-nft-chains', 'ipv4', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['nmctl', 'add-nft-rule', 'ipv4', 'testtable99', 'testchain99', 'tcp', 'dport', '9999', 'accept'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'tcp dport 9999 counter packets 0 bytes 0 accept')

    def test_nmctl_add_rule_tcp_drop(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nmctl', 'show-nft-chains', 'ipv4', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['nmctl', 'add-nft-rule', 'ipv4', 'testtable99', 'testchain99', 'tcp', 'dport', '9999', 'drop'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'tcp dport 9999 counter packets 0 bytes 0 drop')

    def test_nmctl_add_rule_tcp_drop_sport(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nmctl', 'show-nft-chains', 'ipv4', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['nmctl', 'add-nft-rule', 'ipv4', 'testtable99', 'testchain99', 'tcp', 'sport', '9999', 'drop'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'tcp sport 9999 counter packets 0 bytes 0 drop')


    def test_nmctl_add_rule_tcp_drop_accept_sport(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nmctl', 'show-nft-chains', 'ipv4', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['nmctl', 'add-nft-rule', 'ipv4', 'testtable99', 'testchain99', 'tcp', 'sport', '9999', 'accept'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'tcp sport 9999 counter packets 0 bytes 0 accept')

    def test_nmctl_add_rule_udp_accept_sport(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nmctl', 'show-nft-chains', 'ipv4', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['nmctl', 'add-nft-rule', 'ipv4', 'testtable99', 'testchain99', 'udp', 'sport', '9999', 'accept'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'udp sport 9999 counter packets 0 bytes 0 accept')

    def test_nmctl_add_rule_udp_drop_dport(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nmctl', 'show-nft-chains', 'ipv4', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['nmctl', 'add-nft-rule', 'ipv4', 'testtable99', 'testchain99', 'udp', 'dport', '9999', 'drop'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'udp dport 9999 counter packets 0 bytes 0 drop')

    def test_nmctl_add_rule_udp_accept_dport(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nmctl', 'show-nft-chains', 'ipv4', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['nmctl', 'add-nft-rule', 'ipv4', 'testtable99', 'testchain99', 'udp', 'dport', '9999', 'accept'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'udp dport 9999 counter packets 0 bytes 0 accept')

    def test_nmctl_delete_rule(self):
        subprocess.check_call(['nmctl', 'add-nft-table', 'ipv4', 'testtable99'])
        subprocess.check_call(['nmctl', 'add-nft-chain', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nmctl', 'show-nft-chains', 'ipv4', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['nmctl', 'add-nft-rule', 'ipv4', 'testtable99', 'testchain99', 'udp', 'dport', '9999', 'accept'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'udp dport 9999 counter packets 0 bytes 0 accept')

        subprocess.check_call(['nmctl', 'delete-nft-rule', 'ipv4', 'testtable99', 'testchain99'])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)
        self.assertNotRegex(output, 'udp dport 9999 counter packets 0 bytes 0 accept')

def setUpModule():
    if not os.path.exists(network_config_manager_yaml_config_path):
        os.makedirs(network_config_manager_yaml_config_path)

    if not os.path.exists(network_config_manager_yaml_config_path):
        shutil.mkdirs(network_config_manager_yaml_config_path)

def tearDownModule():
    if os.path.exists(network_config_manager_ci_path):
        shutil.rmtree(network_config_manager_ci_path)

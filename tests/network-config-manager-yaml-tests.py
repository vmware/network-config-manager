#!/usr/bin/python3
# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

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

def link_exist(link):
    return os.path.exists(os.path.join('/sys/class/net', link))

def link_remove(link):
    if os.path.exists(os.path.join('/sys/class/net', link)):
        subprocess.call(['ip', 'link', 'del', 'dev', link])

def link_add_dummy(link):
    subprocess.call(['ip', 'link', 'add', 'dev', link, 'type', 'dummy'])

def unit_exist(unit):
    return os.path.exists(os.path.join(networkd_unit_file_path, unit))

def wifi_wpa_supplilant_conf_exits():
    return os.path.exists(network_config_manager_wpa_supplilant_conf_file)

def remove_units_from_netword_unit_path():
    for i in units:
        if (os.path.exists(os.path.join(networkd_unit_file_path, i))):
            os.remove(os.path.join(networkd_unit_file_path, i))

def reload_networkd():
    subprocess.check_output("networkctl reload", shell=True)
    subprocess.check_output("sleep 1", shell=True)

    subprocess.check_output("/lib/systemd/systemd-networkd-wait-online --any", shell=True)

def dequote(s):
    if len(s) < 2:
        return v

    s = s.replace('"', '')

    return s

def call_shell(*command, **kwargs):
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, check=False, universal_newlines=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs).returncode

class TestLinkConfigManagerYAML:
    yaml_configs = [
        "link.yml",
    ]

    def copy_yaml_file_to_netmanager_yaml_path(self, config_file):
        shutil.copy(os.path.join(network_config_manager_ci_yaml_path, config_file), network_config_manager_yaml_config_path)

    def remove_units_from_netmanager_yaml_path(self):
        for config_file in self.yaml_configs:
            if (os.path.exists(os.path.join(network_config_manager_yaml_config_path, config_file))):
                os.remove(os.path.join(network_config_manager_yaml_config_path, config_file))

    def setup_method(self):
        link_add_dummy('test99')
        reload_networkd()

    def teardown_method(self):
        self.remove_units_from_netmanager_yaml_path()
        remove_units_from_netword_unit_path()

    def test_link(self):
        assert(link_exist('test99') == True)
        self.copy_yaml_file_to_netmanager_yaml_path('link.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'ReceiveChecksumOffload') == 'yes')
        assert(parser.get('Link', 'TransmitChecksumOffload') == 'yes')
        assert(parser.get('Link', 'TCPSegmentationOffload') == 'yes')
        assert(parser.get('Link', 'TCP6SegmentationOffload') == 'yes')
        assert(parser.get('Link', 'GenericSegmentationOffload') == 'yes')
        assert(parser.get('Link', 'GenericReceiveOffload') == 'yes')
        assert(parser.get('Link', 'LargeReceiveOffload') == 'yes')
        assert(parser.get('Link', 'TransmitQueueLength') == '1024')
        assert(parser.get('Link', 'ReceiveQueues') == '4096')
        assert(parser.get('Link', 'TransmitQueues') == '4096')
        assert(parser.get('Link', 'RxBufferSize') == 'max')
        assert(parser.get('Link', 'OtherChannels') == '429496729')
        assert(parser.get('Link', 'TxChannels') == '656756677')
        assert(parser.get('Link', 'RxChannels') == 'max')
        assert(parser.get('Link', 'RxFlowControl') == 'yes')
        assert(parser.get('Link', 'TxFlowControl') == 'no')
        assert(parser.get('Link', 'NTupleFilter') == 'no')
        assert(parser.get('Link', 'TransmitVLANSTAGHardwareAcceleration') == 'yes')
        assert(parser.get('Link', 'ReceiveVLANCTAGFilter') == 'no')
        assert(parser.get('Link', 'TransmitVLANCTAGHardwareAcceleration') == 'no')
        assert(parser.get('Link', 'ReceiveVLANCTAGHardwareAcceleration') == 'yes')
        assert(parser.get('Link', 'AutoNegotiation') == 'no')
        assert(parser.get('Link', 'Port') == 'mii')
        assert(parser.get('Link', 'WakeOnLanPassword') == 'cb:a9:87:65:43:21')
        assert(parser.get('Link', 'WakeOnLan') == 'phy unicast broadcast multicast arp magic secureon')
        assert(parser.get('Link', 'Duplex') == 'full')
        assert(parser.get('Link', 'BitsPerSecond') == '5G')

class TestNetworkConfigManagerYAML:
    yaml_configs = [
        "dhcp4.yml",
        "match-driver.yml",
        "static-address-label.yml",
        "dhcp-overrides.yml",
        "dhcp-client-identifier.yml",
        "gw-onlink.yml",
        "ipv6-config.yml",
        "static-gw.yml",
        "network-link.yml",
        "network-network.yml",
        "routing-policy-rule.yml",
        "vlan.yml",
        "bond.yml",
        "bridge.yml",
        "tunnel.yml",
        "tunnel-keys.yml",
        "vrf.yml",
        "vxlan.yml",
        "wireguard.yml",
        "wg-multiple.yml",
        "multiple-rt.yml",
    ]

    def copy_yaml_file_to_network_config_manager_yaml_path(self, config_file):
        shutil.copy(os.path.join(network_config_manager_ci_yaml_path, config_file), network_config_manager_yaml_config_path)

    def remove_units_from_ncm_yaml_path(self):
        for config_file in self.yaml_configs:
            if (os.path.exists(os.path.join(network_config_manager_yaml_config_path, config_file))):
                os.remove(os.path.join(network_config_manager_yaml_config_path, config_file))

    def setup_method(self):
        link_add_dummy('test99')
        link_add_dummy('test98')
        reload_networkd()

    def teardown_method(self):
        self.remove_units_from_ncm_yaml_path()
        link_remove('test99')
        link_remove('test98')

    def test_cmocka(self):
        subprocess.check_call("/usr/bin/nmctl-tests")

    def test_match_driver(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('match-driver.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Match', 'Driver') == 'test-driver')

    def test_network_link(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('network-link.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'ActivationPolicy') == 'up')
        assert(parser.get('Link', 'MACAddress') == 'c2:b0:bb:e3:4d:88')

    def test_network_network(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('network-network.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPv6LinkLocalAddressGenerationMode') == 'eui64')
        assert(parser.get('Network', 'IPv6PrivacyExtensions') == 'no')
        assert(parser.get('Network', 'IPv6MTUBytes') == '1800')

    def test_basic_dhcp4(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('dhcp4.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')

    def test_dhcp4_client_identifier(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('dhcp-client-identifier.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')
        assert(parser.get('DHCPv4', 'ClientIdentifier') == 'mac')

    def test_dhcp4_overrides(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('dhcp-overrides.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)
        assert(unit_exist('10-dummy95.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')
        assert(parser.get('DHCPv4', 'RouteMetric') == '200')
        assert(parser.get('DHCPv6', 'UseDNS') == 'yes')

    def test_network_static_address_label_configuration(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('static-address-label.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Address', 'Address') == '10.100.1.39/24')
        assert(parser.get('Address', 'Label') == 'test99:some-label')
        assert(parser.get('Address', 'PreferredLifetime') == '2000')

    def test_network_gw_onlink(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('gw-onlink.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Address', 'Address') == '10.10.10.1/24')
        assert(parser.get('Route', 'Destination') == '0.0.0.0/0')
        assert(parser.get('Route', 'Gateway') == '9.9.9.9')
        assert(parser.get('Route', 'Onlink') == 'yes')

    def test_network_static_gw(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('static-gw.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

    def test_network_routing_policy_rule(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('routing-policy-rule.yml')

        subprocess.check_call("nmctl apply" , shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Address', 'Address') == '10.100.1.5/24')

        assert(parser.get('Route', 'Destination') == '0.0.0.0/0')
        assert(parser.get('Route', 'Gateway') == '10.100.1.1')

        assert(parser.get('RoutingPolicyRule', 'From') == '10.100.1.5/24')
        assert(parser.get('RoutingPolicyRule', 'To') == '10.100.1.5/24')
        assert(parser.get('RoutingPolicyRule', 'Table') == '101')
        assert(parser.get('RoutingPolicyRule', 'Priority') == '11')
        assert(parser.get('RoutingPolicyRule', 'TypeOfService') == '31')
        assert(parser.get('RoutingPolicyRule', 'FirewallMark') == '21')

    def test_network_ipv6(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('ipv6-config.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Address', 'Address') == '2001:cafe:face:beef::dead:dead/64')
        assert(parser.get('Route', 'Destination') == '::/0')
        assert(parser.get('Route', 'Gateway') == '2001:cafe:face::1')
        assert(parser.get('Route', 'Onlink') == 'yes')

    def test_netdev_vlan(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('vlan.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-vlan10.netdev') == True)

        assert(unit_exist('10-test99.network') == True)
        assert(unit_exist('10-vlan10.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Network', 'VLAN') == 'vlan10')

        parsera = configparser.ConfigParser()
        parsera.read(os.path.join(networkd_unit_file_path, '10-vlan10.netdev'))

        assert(parsera.get('VLAN', 'Id') == '10')

    def test_netdev_bond(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('bond.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-bond0.netdev') == True)

        assert(unit_exist('10-bond0.network') == True)
        assert(unit_exist('10-test99.network') == True)
        assert(unit_exist('10-test98.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))
        assert(parser.get('Network', 'Bond') == 'bond0')

        parsera = configparser.ConfigParser()
        parsera.read(os.path.join(networkd_unit_file_path, '10-test98.network'))
        assert(parsera.get('Network', 'Bond') == 'bond0')

        parserb = configparser.ConfigParser()
        parserb.read(os.path.join(networkd_unit_file_path, '10-bond0.netdev'))
        assert(parserb.get('Bond', 'Mode') == 'active-backup')
        assert(parserb.get('Bond', 'LACPTransmitRate') == 'fast')
        assert(parserb.get('Bond', 'ARPValidate') == 'active')
        assert(parserb.get('Bond', 'FailOverMACPolicy') == 'active')
        assert(parserb.get('Bond', 'AdSelect') == 'bandwidth')
        assert(parserb.get('Bond', 'PrimaryReselectPolicy') == 'better')
        assert(parserb.get('Bond', 'TransmitHashPolicy') == 'layer3+4')
        assert(parserb.get('Bond', 'MIIMonitorSec') == '300')
        assert(parserb.get('Bond', 'MinLinks') == '3')
        assert(parserb.get('Bond', 'ARPIntervalSec') == '30')
        assert(parserb.get('Bond', 'UpDelaySec') == '12')
        assert(parserb.get('Bond', 'DownDelaySec') == '15')
        assert(parserb.get('Bond', 'LearnPacketIntervalSec') == '32')
        assert(parserb.get('Bond', 'ResendIGMP') == '45')
        assert(parserb.get('Bond', 'PacketsPerSlave') == '11')
        assert(parserb.get('Bond', 'GratuitousARP') == '15')
        assert(parserb.get('Bond', 'AllSlavesActive') == 'yes')
        assert(parserb.get('Bond', 'ARPIPTargets') == '192.168.5.1 192.168.5.34')
        assert(parserb.get('Bond', 'ARPValidate') == 'active')

        parserc = configparser.ConfigParser()
        parserc.read(os.path.join(networkd_unit_file_path, '10-bond0.network'))
        assert(parserc.get('Network', 'DHCP') == 'ipv4')

    def test_netdev_bridge(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('bridge.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-br0.netdev') == True)

        assert(unit_exist('10-br0.network') == True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))
        assert(parser.get('Network', 'Bridge') == 'br0')


        parserb = configparser.ConfigParser()
        parserb.read(os.path.join(networkd_unit_file_path, '10-br0.netdev'))
        assert(parserb.get('NetDev', 'Name') == 'br0')
        assert(parserb.get('Bridge', 'STP') == 'yes')
        assert(parserb.get('Bridge', 'ForwardDelaySec') == '12')
        assert(parserb.get('Bridge', 'HelloTimeSec') == '6')
        assert(parserb.get('Bridge', 'AgeingTimeSec') == '50')
        assert(parserb.get('Bridge', 'MaxAgeSec') == '24')

        parserc = configparser.ConfigParser()
        parserc.read(os.path.join(networkd_unit_file_path, '10-br0.network'))
        assert(parserc.get('Network', 'DHCP') == 'ipv4')

    def test_netdev_tunnel(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('tunnel.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-he-ipv6.netdev') == True)

        assert(unit_exist('10-he-ipv6.network') == True)
        assert(unit_exist('10-test99.network') == True)

        parserb = configparser.ConfigParser()
        parserb.read(os.path.join(networkd_unit_file_path, '10-he-ipv6.netdev'))

        assert(parserb.get('NetDev', 'Name') == 'he-ipv6')
        assert(parserb.get('NetDev', 'Kind') == 'sit')

        assert(parserb.get('Tunnel', 'Independent') == 'yes')
        assert(parserb.get('Tunnel', 'Local') == '1.1.1.1')
        assert(parserb.get('Tunnel', 'Remote') == '2.2.2.2')
        assert(parserb.get('Tunnel', 'Key') == '1111')
        assert(parserb.get('Tunnel', 'InputKey') == '2222')
        assert(parserb.get('Tunnel', 'OutputKey') == '3333')
        assert(parserb.get('Tunnel', 'TTL') == '100')

    def test_netdev_tunnel_keys(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('tunnel-keys.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-he-ipv6.netdev') == True)

        assert(unit_exist('10-he-ipv6.network') == True)
        assert(unit_exist('10-test99.network') == True)

        parserb = configparser.ConfigParser()
        parserb.read(os.path.join(networkd_unit_file_path, '10-he-ipv6.netdev'))

        assert(parserb.get('NetDev', 'Name') == 'he-ipv6')
        assert(parserb.get('NetDev', 'Kind') == 'sit')

        assert(parserb.get('Tunnel', 'Independent') == 'yes')
        assert(parserb.get('Tunnel', 'Local') == '1.1.1.1')
        assert(parserb.get('Tunnel', 'Remote') == '2.2.2.2')
        assert(parserb.get('Tunnel', 'InputKey') == '1234')
        assert(parserb.get('Tunnel', 'OutputKey') == '5678')

    def test_netdev_vrf(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('vrf.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-vrf1005.netdev') == True)

        assert(unit_exist('10-vrf1005.network') == True)
        assert(unit_exist('10-test99.network') == True)
        assert(unit_exist('10-test98.network') == True)

        parsera = configparser.ConfigParser()
        parsera.read(os.path.join(networkd_unit_file_path, '10-vrf1005.netdev'))

        assert(parsera.get('NetDev', 'Name') == 'vrf1005')
        assert(parsera.get('NetDev', 'Kind') == 'vrf')

        assert(parsera.get('VRF', 'Table') == '1005')

        parserb = configparser.ConfigParser()
        parserb.read(os.path.join(networkd_unit_file_path, '10-test99.network'))
        assert(parserb.get('Network', 'VRF') == 'vrf1005')

        parserc = configparser.ConfigParser()
        parserc.read(os.path.join(networkd_unit_file_path, '10-test98.network'))
        assert(parserc.get('Network', 'VRF') == 'vrf1005')

    def test_netdev_vxlan(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('vxlan.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-vxlan1.netdev') == True)

        assert(unit_exist('10-vxlan1.network') == True)
        assert(unit_exist('10-test99.network') == True)

        parsera = configparser.ConfigParser()
        parsera.read(os.path.join(networkd_unit_file_path, '10-vxlan1.netdev'))

        assert(parsera.get('NetDev', 'Name') == 'vxlan1')
        assert(parsera.get('NetDev', 'Kind') == 'vxlan')

        assert(parsera.get('VXLAN', 'VNI') == '1')
        assert(parsera.get('VXLAN', 'Local') == '192.168.1.34')
        assert(parsera.get('VXLAN', 'Remote') == '192.168.1.35')
        assert(parsera.get('VXLAN', 'TOS') == '11')
        assert(parsera.get('VXLAN', 'MacLearning') == 'yes')
        assert(parsera.get('VXLAN', 'FDBAgeingSec') == '300')
        assert(parsera.get('VXLAN', 'ReduceARPProxy') == 'yes')
        assert(parsera.get('VXLAN', 'FlowLabel') == '5555')
        assert(parsera.get('VXLAN', 'MaximumFDBEntries') == '20')
        assert(parsera.get('VXLAN', 'UDPChecksum') == 'yes')
        assert(parsera.get('VXLAN', 'UDP6ZeroChecksumTx') == 'yes')
        assert(parsera.get('VXLAN', 'UDP6ZeroChecksumRx') == 'yes')
        assert(parsera.get('VXLAN', 'RemoteChecksumTx') == 'yes')
        assert(parsera.get('VXLAN', 'RemoteChecksumRx') == 'yes')
        assert(parsera.get('VXLAN', 'GroupPolicyExtension') == 'yes')
        assert(parsera.get('VXLAN', 'GenericProtocolExtension') == 'yes')
        assert(parsera.get('VXLAN', 'IPDoNotFragment') == 'yes')
        assert(parsera.get('VXLAN', 'PortRange') == '42-442')
        assert(parsera.get('VXLAN', 'RouteShortCircuit') == 'yes')

        parserb = configparser.ConfigParser()
        parserb.read(os.path.join(networkd_unit_file_path, '10-test99.network'))
        assert(parserb.get('Network', 'VXLAN') == 'vxlan1')

    def test_netdev_wireguard(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('wireguard.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-home0.netdev') == True)
        assert(unit_exist('10-home0.network') == True)

        parsera = configparser.ConfigParser()
        parsera.read(os.path.join(networkd_unit_file_path, '10-home0.netdev'))

        assert(parsera.get('NetDev', 'Name') == 'home0')
        assert(parsera.get('NetDev', 'Kind') == 'wireguard')

        assert(parsera.get('WireGuard', 'PrivateKeyFile') == '/etc/wireguard/laptop-private.key')
        assert(parsera.get('WireGuard', 'ListenPort') == '51000')

        assert(parsera.get('WireGuardPeer', 'PublicKey') == 'syR+psKigVdJ+PZvpEkacU5niqg9WGYxepDZT/zLGj8=')
        assert(parsera.get('WireGuardPeer', 'Endpoint') == '10.48.132.39:51000')
        assert(parsera.get('WireGuardPeer', 'AllowedIPs') == '10.10.11.0/24 10.10.10.0/24')

    def test_netdev_wireguard_multiple_peer(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('wg-multiple.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-wg0.netdev') == True)
        assert(unit_exist('10-wg1.netdev') == True)
        assert(unit_exist('10-wg1.network') == True)
        assert(unit_exist('10-wg0.network') == True)

        parsera = configparser.ConfigParser()
        parsera.read(os.path.join(networkd_unit_file_path, '10-wg0.netdev'))

        assert(parsera.get('NetDev', 'Name') == 'wg0')
        assert(parsera.get('NetDev', 'Kind') == 'wireguard')

        assert(parsera.get('WireGuard', 'PrivateKey') == '4GgaQCy68nzNsUE5aJ9fuLzHhB65tAlwbmA72MWnOm8=')
        assert(parsera.get('WireGuard', 'ListenPort') == '51820')
        assert(parsera.get('WireGuard', 'FwMark') == '42')

        assert(parsera.get('WireGuardPeer', 'PublicKey') == 'M9nt4YujIOmNrRmpIRTmYSfMdrpvE7u6WkG8FY8WjG4=')
        assert(parsera.get('WireGuardPeer', 'PresharedKey') == '7voRZ/ojfXgfPOlswo3Lpma1RJq7qijIEEUEMShQFV8=')
        assert(parsera.get('WireGuardPeer', 'AllowedIPs') == '20.20.20.10/24')

        parserb = configparser.ConfigParser()
        parserb.read(os.path.join(networkd_unit_file_path, '10-wg1.netdev'))

        assert(parserb.get('NetDev', 'Name') == 'wg1')
        assert(parserb.get('NetDev', 'Kind') == 'wireguard')

        assert(parserb.get('WireGuard', 'PrivateKey') == 'KPt9BzQjejRerEv8RMaFlpsD675gNexELOQRXt/AcH0=')

        assert(parserb.get('WireGuardPeer', 'PublicKey') == 'rlbInAj0qV69CysWPQY7KEBnKxpYCpaWqOs/dLevdWc=')
        assert(parserb.get('WireGuardPeer', 'PresharedKey') == '7voRZ/ojfXgfPOlswo3Lpma1RJq7qijIEEUEMShQFV8=')
        assert(parserb.get('WireGuardPeer', 'PersistentKeepalive') == '21')

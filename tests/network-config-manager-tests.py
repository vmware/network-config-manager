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

network_config_manager_wpa_supplilant_conf_file = '/etc/network-config-manager/wpa_supplicant.conf'

units = ["10-test99.network",
         "10-test99.link",
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
         '10-bond-98.network'
         '10-macvlan-98.netdev',
         '10-macvlan-98.network'
         '10-macvtap-98.netdev',
         '10-macvtap-98.network'
         '10-ipvlan-98.netdev',
         '10-ipvtap-98.network',
         '10-vrf-98.netdev',
         '10-vrf-98.network',
         '10-veth-98.netdev',
         '10-veth-98.network'
         '10-ipip-98.netdev',
         '10-ipip-98.network'
         '10-sit-98.netdev',
         '10-sit-98.network'
         '10-gre-98.netdev',
         '10-gre-98.network'
         '10-vti-98.netdev',
         '10-vri-98.network'
         '10-wg99.netdev',
         '10-wg99.network',
         '10-eni99np1.network',
         '10-test99.link']

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

def restart_networkd():
    subprocess.check_output("systemctl restart systemd-networkd", shell=True)
    subprocess.check_output("sleep 5", shell=True)

    subprocess.check_output("/lib/systemd/systemd-networkd-wait-online --any", shell=True)

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

def call_shell(*command, **kwargs):
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, check=False, universal_newlines=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs).returncode

def expectedFailureIfNetdevsimWithSRIOVIsNotAvailable():
    def f(func):
        def finalize(func, supported):
            call_shell('rmmod netdevsim')
            return func if supported else unittest.expectedFailure(func)

        if call_shell('modprobe netdevsim') != 0:
            return finalize(func, False)

        try:
            with open('/sys/bus/netdevsim/new_device', mode='w', encoding='utf-8') as f:
                f.write('99 1')
        except OSError:
            return finalize(func, False)

        return finalize(func, os.path.exists('/sys/bus/netdevsim/devices/netdevsim99/sriov_numvfs'))

    return f

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
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()

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

    def copy_yaml_file_to_netmanager_yaml_path(self, config_file):
        shutil.copy(os.path.join(network_config_manager_ci_yaml_path, config_file), network_config_manager_yaml_config_path)

    def remove_units_from_netmanager_yaml_path(self):
        for config_file in self.yaml_configs:
            if (os.path.exists(os.path.join(network_config_manager_yaml_config_path, config_file))):
                os.remove(os.path.join(network_config_manager_yaml_config_path, config_file))

    def setup_method(self):
        link_add_dummy('test99')
        link_add_dummy('test98')
        restart_networkd()

    def teardown_method(self):
        self.remove_units_from_netmanager_yaml_path()
        remove_units_from_netword_unit_path()
        link_remove('test99')
        link_remove('test98')

    def test_cmocka(self):
        subprocess.check_call("/usr/bin/nmctl-tests")

    def test_match_driver(self):
        self.copy_yaml_file_to_netmanager_yaml_path('match-driver.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Match', 'Driver') == 'test-driver')

    def test_network_link(self):
        self.copy_yaml_file_to_netmanager_yaml_path('network-link.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'ActivationPolicy') == 'up')
        assert(parser.get('Link', 'MACAddress') == 'c2:b0:bb:e3:4d:88')

    def test_network_network(self):
        self.copy_yaml_file_to_netmanager_yaml_path('network-network.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPv6LinkLocalAddressGenerationMode') == 'eui64')
        assert(parser.get('Network', 'IPv6PrivacyExtensions') == 'no')
        assert(parser.get('Network', 'IPv6MTUBytes') == '1800')

    def test_basic_dhcp4(self):
        self.copy_yaml_file_to_netmanager_yaml_path('dhcp4.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')

    def test_dhcp4_client_identifier(self):
        self.copy_yaml_file_to_netmanager_yaml_path('dhcp-client-identifier.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')
        assert(parser.get('DHCPv4', 'ClientIdentifier') == 'mac')

    def test_dhcp4_overrides(self):
        self.copy_yaml_file_to_netmanager_yaml_path('dhcp-overrides.yml')

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
        self.copy_yaml_file_to_netmanager_yaml_path('static-address-label.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Address', 'Address') == '10.100.1.39/24')
        assert(parser.get('Address', 'Label') == 'test99:some-label')
        assert(parser.get('Address', 'PreferredLifetime') == '2000')

    def test_network_gw_onlink(self):
        self.copy_yaml_file_to_netmanager_yaml_path('gw-onlink.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Address', 'Address') == '10.10.10.1/24')
        assert(parser.get('Route', 'Destination') == '0.0.0.0/0')
        assert(parser.get('Route', 'Gateway') == '9.9.9.9')
        assert(parser.get('Route', 'Onlink') == 'yes')

    def test_network_static_gw(self):
        self.copy_yaml_file_to_netmanager_yaml_path('static-gw.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

    def test_network_routing_policy_rule(self):
        self.copy_yaml_file_to_netmanager_yaml_path('routing-policy-rule.yml')

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
        self.copy_yaml_file_to_netmanager_yaml_path('ipv6-config.yml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Address', 'Address') == '2001:cafe:face:beef::dead:dead/64')
        assert(parser.get('Route', 'Destination') == '::/0')
        assert(parser.get('Route', 'Gateway') == '2001:cafe:face::1')
        assert(parser.get('Route', 'Onlink') == 'yes')

    def test_netdev_vlan(self):
        self.copy_yaml_file_to_netmanager_yaml_path('vlan.yml')

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
        self.copy_yaml_file_to_netmanager_yaml_path('bond.yml')

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
        self.copy_yaml_file_to_netmanager_yaml_path('bridge.yml')

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
        self.copy_yaml_file_to_netmanager_yaml_path('tunnel.yml')

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
        self.copy_yaml_file_to_netmanager_yaml_path('tunnel-keys.yml')

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
        self.copy_yaml_file_to_netmanager_yaml_path('vrf.yml')

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
        self.copy_yaml_file_to_netmanager_yaml_path('vxlan.yml')

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
        self.copy_yaml_file_to_netmanager_yaml_path('wireguard.yml')

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
        self.copy_yaml_file_to_netmanager_yaml_path('wg-multiple.yml')

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


class TestKernelCommandLine:
    def teardown_method(self):
        remove_units_from_netword_unit_path()

    def test_network_kernel_command_line_ip_dhcp(self):
        ''' ip=<interface>:{dhcp|on|any|dhcp6|auto6} '''

        subprocess.check_call(['nmctl', 'apply-cmdline', 'ip=test99:dhcp'])
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')

    def test_network_kernel_command_line_multiple_ip_dhcp(self):
        ''' ip=<interface>:{dhcp|on|any|dhcp6|auto6} '''

        subprocess.check_call(['nmctl', 'apply-cmdline', 'ip=test99:dhcp ip=test98:dhcp'])
        assert(unit_exist('10-test99.network') == True)
        assert(unit_exist('10-test98.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')

        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'DHCP') == 'ipv4')

    def test_network_kernel_command_line_ip_static(self):
        ''' ip=<client-IP>:[ <server-id>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off}'''

        subprocess.check_call(['nmctl', 'apply-cmdline', 'ip=192.168.1.34::192.168.1.1:::test99:dhcp'])
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'ipv4')
        assert(parser.get('Address', 'Address') == '192.168.1.34')
        assert(parser.get('Route', 'Gateway') == '192.168.1.1')

class TestCLINetwork:
    def setup_method(self):
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        link_remove('test99')

    def test_cli_link_status(self):
        subprocess.check_call("nmctl status 2", text=True, shell = True)

    def test_cli_link_status(self):
        subprocess.check_call("nmctl", text=True, shell = True)

    def test_cli_show_dns(self):
        subprocess.check_call("nmctl dns", text=True, shell = True)

    def test_cli_show_domains(self):
        subprocess.check_call("nmctl add-domain dev test99 domains domain1 domain2", shell = True)
        subprocess.check_call("nmctl domain", text=True, shell = True)

    def test_cli_add_dns(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-manage dev test99 manage yes", shell = True)
        subprocess.check_call("nmctl add-dns dev test99 dns 192.168.1.45 192.168.1.46", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

        dns = parser.get('Network', 'DNS')
        print(dns)
        assert(dns.find("192.168.1.46") != -1)
        assert(dns.find("192.168.1.45") != -1)

    def test_cli_add_domain(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-manage dev test99 manage yes", shell = True)
        subprocess.check_call("nmctl add-domain dev test99 domains domain1 domain2", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

        d = parser.get('Network', 'Domains')
        print(d)
        assert(d.find("domain1") != -1)
        assert(d.find("domain2") != -1)

    def test_cli_enable_ipv6(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl ipv6 dev test99 yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LinkLocalAddressing') == 'ipv6')

    def test_cli_disable_ipv6(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl ipv6 dev test99 no", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LinkLocalAddressing') == 'no')

    def test_cli_set_hostname(self):
        subprocess.check_call("nmctl hostname Zeus", shell = True)

    def test_cli_set_mtu(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-mtu dev test99 mtu 1400", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'MTUBytes') == '1400')

    def test_cli_set_mtu_without_kind(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-mtu dev test99 1400", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'MTUBytes') == '1400')

    def test_cli_set_ipv6_mtu(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-ipv6mtu  dev test99 1500", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPv6MTUBytes') == '1500')

    def test_cli_set_mac(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-mac dev test99 mac 00:0c:29:3a:bc:11", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'MACAddress') == '00:0c:29:3a:bc:11')

    def test_cli_set_mac_without_kind(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-mac dev test99 00:0c:29:3a:bc:11", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'MACAddress') == '00:0c:29:3a:bc:11')

    def test_cli_set_manage(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-manage dev test99 manage yes", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'Unmanaged') == 'no')

    def test_cli_set_manage_without_kind(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-manage dev test99 yes", shell = True)
        assert(unit_exist('10-test99.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'Unmanaged') == 'no')

    def test_cli_set_link_option(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-manage dev test99 manage yes", shell = True)
        assert(unit_exist('10-test99.network') == True)

        subprocess.check_call("nmctl set-link-option dev test99 arp yes mc yes amc 0 pcs false", shell = True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'ARP') == 'yes')
        assert(parser.get('Link', 'Multicast') == 'yes')
        assert(parser.get('Link', 'AllMulticast') == 'no')
        assert(parser.get('Link', 'Promiscuous') == 'no')

    def test_cli_set_group(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-link-group dev test99 group 2147483647", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'Group') == '2147483647')

    def test_cli_set_rf_online(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-link-rfo dev test99 f ipv4", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'RequiredFamilyForOnline') == 'ipv4')

    def test_cli_set_act_policy(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-link-ap dev test99 ap always-up", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'ActivationPolicy') == 'always-up')

    def test_cli_set_dhcp_client_type(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp dev test99 dhcp yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'yes')

    def test_cli_set_dhcp4_iaid(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp dev test99 dhcp ipv4", shell = True)
        subprocess.check_call("nmctl set-dhcp-iaid dev test99 f 4 iaid 5555", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'IAID') == '5555')

    def test_cli_set_dhcp6_iaid(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp dev test99 dhcp ipv4", shell = True)
        subprocess.check_call("nmctl set-dhcp-iaid dev test99 f 6 iaid 5555", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv6', 'IAID') == '5555')

    def test_cli_set_dhcp4_duid(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp dev test99 dhcp ipv4", shell = True)
        subprocess.check_call("nmctl set-dhcp-duid dev test99 f 4 duid vendor data 00:00:ab:11:f9:2a:c2:77:29:f9:5c:01", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'DUIDType') == 'vendor')
        assert(parser.get('DHCPv4', 'DUIDRawData') == '00:00:ab:11:f9:2a:c2:77:29:f9:5c:01')

    def test_cli_set_dhcp6_duid(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp dev test99 dhcp ipv4", shell = True)
        subprocess.check_call("nmctl set-dhcp-duid dev test99 f 6 duid vendor data 00:00:ab:11:f9:2a:c2:77:29:f9:5c:01", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv6', 'DUIDType') == 'vendor')
        assert(parser.get('DHCPv6', 'DUIDRawData') == '00:00:ab:11:f9:2a:c2:77:29:f9:5c:01')

    def test_cli_add_static_address(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl add-addr dev test99 a 192.168.1.45/24 peer 192.168.1.46/24 dad ipv4 scope "
                              "link pref-lifetime forever prefix-route yes label test", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Address', 'Address') == '192.168.1.45/24')
        assert(parser.get('Address', 'Peer') == '192.168.1.46/24')
        assert(parser.get('Address', 'Scope') == 'link')
        assert(parser.get('Address', 'PreferredLifetime') == 'forever')
        assert(parser.get('Address', 'AddPrefixRoute') == 'yes')
        assert(parser.get('Address', 'DuplicateAddressDetection') == 'ipv4')
        assert(parser.get('Address', 'Label') == 'test')

    def test_cli_add_default_gateway(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl add-addr dev test99 a 192.168.1.45/24 peer 192.168.1.46/24 dad "
                              "ipv4 scope link pref-lifetime forever prefix-route yes label 3434", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Address', 'Address') == '192.168.1.45/24')

        subprocess.check_call("nmctl add-default-gw dev test99 gw 192.168.1.1 onlink True", shell = True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Route', 'Gateway') == '192.168.1.1')
        assert(parser.get('Route', 'GatewayOnLink') == 'yes')

    def test_cli_add_route(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl add-addr dev test99 a 192.168.1.45/24 peer 192.168.1.46/24 dad ipv4 scope link "
                              "pref-lifetime forever prefix-route yes label 3434", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Address', 'Address') == '192.168.1.45/24')

        subprocess.check_call("nmctl add-route dev test99 gw 192.168.1.1 dest 192.168.1.2 metric 111 scope "
                               "link mtu 1400 table local proto static type unicast onlink yes ipv6-pref "
                               "medium src 192.168.1.4", shell = True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Route', 'Destination') == '192.168.1.2')
        assert(parser.get('Route', 'Gateway') == '192.168.1.1')
        assert(parser.get('Route', 'GatewayOnLink') == 'yes')
        assert(parser.get('Route', 'Metric') == '111')
        assert(parser.get('Route', 'MTUBytes') == '1400')
        assert(parser.get('Route', 'Protocol') == 'static')
        assert(parser.get('Route', 'Scope') == 'link')
        assert(parser.get('Route', 'Table') == 'local')
        assert(parser.get('Route', 'IPv6Preference') == 'medium')
        assert(parser.get('Route', 'Source') == '192.168.1.4')

    def test_cli_add_routing_policy_rule(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl add-rule dev test99 table 10 to 192.168.1.2/24 from 192.168.1.3/24 "
                               "oif test99 iif test99 tos 0x12 sport 1000-2000 dport 1000-2100 invert yes proto tcp", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

        assert(parser.get('RoutingPolicyRule', 'Table') == '10')
        assert(parser.get('RoutingPolicyRule', 'From') == '192.168.1.3/24')
        assert(parser.get('RoutingPolicyRule', 'To') == '192.168.1.2/24')
        assert(parser.get('RoutingPolicyRule', 'TypeOfService') == '18')
        assert(parser.get('RoutingPolicyRule', 'OutgoingInterface') == 'test99')
        assert(parser.get('RoutingPolicyRule', 'IncomingInterface') == 'test99')
        assert(parser.get('RoutingPolicyRule', 'Invert') == 'yes')
        assert(parser.get('RoutingPolicyRule', 'SourcePort') == '1000-2000')
        assert(parser.get('RoutingPolicyRule', 'DestinationPort') == '1000-2100')
        assert(parser.get('RoutingPolicyRule', 'IPProtocol') == 'tcp')

    def test_cli_set_link_local_address(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-lla dev test99 ipv6", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LinkLocalAddressing') == 'ipv6')

    def test_cli_set_ip_v6_router_advertisement(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-ipv6acceptra dev test99 yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPv6AcceptRA') == 'yes')

    def test_cli_set_ipv4_link_local_route(self):
        assert(link_exist('test99') == True);

        subprocess.check_call("nmctl set-ipv4ll-route dev test99 yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPv4LLRoute') == 'yes')

    def test_cli_set_llmnr(self):
        assert(link_exist('test99') == True);

        subprocess.check_call("nmctl set-llmnr dev test99 yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LLMNR') == 'yes')

    def test_cli_set_llmnr(self):
        assert(link_exist('test99') == True);

        subprocess.check_call("nmctl llmnr dev test99 resolve", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LLMNR') == 'resolve')

    def test_cli_set_multicast_dns(self):
        assert(link_exist('test99') == True);

        subprocess.check_call("nmctl set-mcast-dns dev test99 yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'MulticastDNS') == 'yes')

    def test_cli_set_ip_masquerade(self):
        assert(link_exist('test99') == True);

        subprocess.check_call("nmctl set-ipmasquerade dev test99 yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPMasquerade') == 'yes')

    def test_cli_set_dhcp4_client_identifier(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp4-cid dev test99 id mac", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'ClientIdentifier') == 'mac')

    def test_cli_set_dhcp4_use_dns(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp4 dev test99 use-dns yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseDNS') == 'yes')

    def test_cli_set_dhcp4_use_mtu(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp4 dev test99 use-mtu yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

    def test_cli_set_dhcp4_use_domains(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp4 dev test99 use-domains yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseDomains') == 'yes')

    def test_cli_set_dhcp4_use_ntp(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp4 dev test99 use-ntp yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseNTP') == 'yes')

    def test_cli_set_dhcp4_section(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp4 dev test99 use-routes yes use-hostname yes use-gw yes use-tz no", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseRoutes') == 'yes')
        assert(parser.get('DHCPv4', 'UseHostname') == 'yes')
        assert(parser.get('DHCPv4', 'UseRoutes') == 'yes')
        assert(parser.get('DHCPv4', 'UseGateway') == 'yes')
        assert(parser.get('DHCPv4', 'UseTimezone') == 'no')

    def test_cli_set_dhcp6_section(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-dhcp6 dev test99 use-dns yes use-ntp yes use-domains yes use-mtu no rapid-commit yes use-addr yes use-delegataed-prefix no without-ra yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv6', 'UseDNS') == 'yes')
        assert(parser.get('DHCPv6', 'UseNTP') == 'yes')
        assert(parser.get('DHCPv6', 'UseDomains') == 'yes')
        assert(parser.get('DHCPv6', 'UseMTU') == 'no')
        assert(parser.get('DHCPv6', 'RapidCommit') == 'yes')
        assert(parser.get('DHCPv6', 'UseAddress') == 'yes')
        assert(parser.get('DHCPv6', 'UseDelegatedPrefix') == 'no')
        assert(parser.get('DHCPv6', 'WithoutRA') == 'yes')

    def test_cli_set_link_lldp(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-lldp dev test99 yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LLDP') == 'yes')

    def test_cli_set_link_emit_lldp(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-emit-lldp dev test99 yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'EmitLLDP') == 'yes')

    def test_cli_add_ntp(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl add-ntp dev test99 ntp 192.168.1.34 192.168.1.45", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'NTP') == '192.168.1.45 192.168.1.34')

    def test_cli_set_ntp(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-ntp dev test99 ntp 192.168.1.34 192.168.1.45", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'NTP') == '192.168.1.45 192.168.1.34')

    def test_cli_add_dns_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-manage dev test99 manag yes") != 0)
        assert(call_shell("nmctl add-dns dev test99 ds 192.168.1.45 192.168.1.46") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_add_domain_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-manage dev test99 maage yes") != 0)
        assert(call_shell("nmctl add-domain dev test99 doains domain1 domain2") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_enable_ipv6_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl ipv dev test99 yes") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_hostname_failure(self):
        assert(call_shell("nmctl host Zeus") != 0)

    def test_cli_set_mtu_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-mtu dev test99 mt 1400") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_mtu_without_kind_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-mu dev test99 1400") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_ipv6_mtu_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-ipmtu dev test99 notint") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_mac_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-mac dev test99 macc 00:0c:29:3a:bc:11") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_mac_without_kind_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-mac dev test99 00:0c:29:3a") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_link_option_failure(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl set-manage dev test99 manage yes", shell = True)
        assert(unit_exist('10-test99.network') == True)

        assert(call_shell("nmctl set-link-option dev test99 arp 121 mc yes 0 pcs false") != 0)

    def test_cli_set_act_policy_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-link-ap dev test99 app always-up") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_dhcp_client_type_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-dhcp dev test99 dhcppp yes") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_dhcp4_iaid_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-dhcp dev test99 dh ipv4") != 0)
        assert(call_shell("nmctl set-dhcp-iaid dev test99 f 4 5555") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_dhcp6_iaid_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set dev test99 dhcp ipv4") != 0)
        assert(call_shell("nmctl set-iaid dev test99 f 6 iaid 5555") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_dhcp4_duid_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-dhcp dev test99 dhcp ipv") != 0)
        assert(call_shell("nmctl set-dhcp-duid dev test99 f 4 duid") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_add_static_address_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl add-addr dev test99 a 192.168.1.45/24 peerrr 192.168.1.46/24 ipv4 scope "
                              "link pref-time forever yes label test") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_add_default_gateway_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl add-addr dev test99 peer 192.168.1.46/24 dad link prefix-route yes") != 0)

        assert(unit_exist('10-test99.network') == False)

        assert(call_shell("nmctl add-default-gw dev test99 xgw 192.168.1.1 onlink") != 0)

    def test_cli_add_route_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl add-addr dev test99 a 19245/24 peer ipv4 scope link") != 0)

        assert(unit_exist('10-test99.network') == False)

        assert(call_shell("nmctl add-route dev test99 gw 192.168.1.1 destttttt 192.168.1.2 scope") != 0)

    def test_cli_add_additional_gateway_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl add-addl-gw dev test99 192.168.10.5/24 dest 0.0.0.0 gw table 100 ") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_add_routing_policy_rule_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl add-rule dev test99 tbe 10 to frrrom 192.168.1.3/24 iif test99 toos 0x12") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_ip_v6_router_advertisement_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-ipv6tra dev test99 yes") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_llmnr_failure(self):
        assert(link_exist('test99') == True);

        assert(call_shell("nmctl llmnr dev test99 ") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_dhcp4_client_identifier_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-dhcp4-cid dev test99 id") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_dhcp4_use_dns_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-dhcp4 dev test99 use-dns") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_set_dhcp4_section_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-dhcp4 dev test99 use yes hostname yes use-gw use-tz 2") != 0)

        assert(unit_exist('10-test99.network') == False)

    def test_cli_add_ntp_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl add-ntp dev test99 ntttp 192.168.1.34 192.168.1.45") != 0)

        assert(unit_exist('10-test99.network') == False)

class TestCLIDHCPv4Server:
    def setup_method(self):
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        link_remove('test99')

    def test_cli_configure_dhcpv4_server(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl add-dhcpv4-server dev test99 pool-offset "
                               "10 pool-size 20 default-lease-time 100 "
                               "max-lease-time 200 emit-dns yes dns 192.168.1.1 "
                               "emit-router yes", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

        assert(parser.get('Network', 'DHCPServer') == 'yes')

        assert(parser.get('DHCPServer', 'PoolOffset') == '10')
        assert(parser.get('DHCPServer', 'PoolSize') == '20')
        assert(parser.get('DHCPServer', 'DefaultLeaseTimeSec') == '100')
        assert(parser.get('DHCPServer', 'MaxLeaseTimeSec') == '200')
        assert(parser.get('DHCPServer', 'EmitDNS') == 'yes')
        assert(parser.get('DHCPServer', 'DNS') == '192.168.1.1')
        assert(parser.get('DHCPServer', 'EmitRouter') == 'yes')

    def test_cli_configure_dhcpv4_server_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl add-dhcpv4-server dev test99 10 pool-size 20 default-lease-time 100 emit-router") != 0)

        assert(unit_exist('10-test99.network') == False)

class TestCLIIPv6RA:
    def setup_method(self):
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        link_remove('test99')

    def test_cli_configure_ipv6ra(self):
        assert(link_exist('test99') == True)

        subprocess.check_call("nmctl add-ipv6ra dev test99 prefix 2002:da8:1:0::/64 "
                              "pref-lifetime 100 valid-lifetime 200 assign yes "
                              "managed yes emit-dns yes dns 2002:da8:1:0::1 "
                              "domain test.com emit-domain yes dns-lifetime 100 router-pref medium "
                              "route-prefix 2001:db1:fff::/64 route-lifetime 1000", shell = True)

        assert(unit_exist('10-test99.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

        assert(parser.get('Network', 'IPv6SendRA') == 'yes')

        assert(parser.get('IPv6Prefix', 'Prefix') == '2002:da8:1::/64')
        assert(parser.get('IPv6Prefix', 'PreferredLifetimeSec') == '100')
        assert(parser.get('IPv6Prefix', 'ValidLifetimeSec') == '200')

        assert(parser.get('IPv6SendRA', 'RouterPreference') == 'medium')
        assert(parser.get('IPv6SendRA', 'DNS') == '2002:da8:1::1')
        assert(parser.get('IPv6SendRA', 'EmitDNS') == 'yes')
        assert(parser.get('IPv6SendRA', 'Assign') == 'yes')
        assert(parser.get('IPv6SendRA', 'DNSLifetimeSec') == '100')
        assert(parser.get('IPv6SendRA', 'Domains') == 'test.com')

        assert(parser.get('IPv6RoutePrefix', 'LifetimeSec') == '1000')
        assert(parser.get('IPv6RoutePrefix', 'Route') == '2001:db1:fff::/64')

    def test_cli_configure_ipv6ra_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl add-ipv6ra dev test99 prrefefix 2002:da8:1:0::/64 route-prefix 1000") != 0)

        assert(unit_exist('10-test99.network') == False)

class TestCLINetDev:
    def setup_method(self):
        link_remove('test98')
        link_add_dummy('test98')
        restart_networkd()

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        link_remove('test98')

    def test_cli_create_vlan(self):
        assert(link_exist('test98') == True)

        subprocess.check_call("nmctl create-vlan vlan-98 dev test98 id 11 proto 802.1q gvrp yes mvrp yes loose-binding yes reorder-hdr yes", shell = True)
        assert(unit_exist('10-test98.network') == True)
        assert(unit_exist('10-vlan-98.netdev') == True)
        assert(unit_exist('10-vlan-98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '10'])

        assert(link_exist('vlan-98') == True)

        vlan_parser = configparser.ConfigParser()
        vlan_parser.read(os.path.join(networkd_unit_file_path, '10-vlan-98.netdev'))

        assert(vlan_parser.get('NetDev', 'Name') == 'vlan-98')
        assert(vlan_parser.get('NetDev', 'kind') == 'vlan')

        assert(vlan_parser.get('VLAN', 'id') == '11')
        assert(vlan_parser.get('VLAN', 'Protocol') == '802.1q')
        assert(vlan_parser.get('VLAN', 'GVRP') == 'yes')
        assert(vlan_parser.get('VLAN', 'MVRP') == 'yes')
        assert(vlan_parser.get('VLAN', 'LooseBinding') == 'yes')
        assert(vlan_parser.get('VLAN', 'ReorderHeader') == 'yes')

        vlan_network_parser = configparser.ConfigParser()
        vlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-vlan-98.network'))

        assert(vlan_network_parser.get('Match', 'Name') == 'vlan-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'VLAN') == 'vlan-98')

        subprocess.check_call("nmctl remove-netdev vlan-98 kind vlan" , shell = True)
        assert(unit_exist('10-vlan-98.netdev') == False)
        assert(unit_exist('10-vlan-98.network') == False)

    def test_cli_create_macvlan(self):
        assert(link_exist('test98') == True)

        subprocess.check_call("nmctl create-macvlan macvlan-98 dev test98 mode private", shell = True)
        assert(unit_exist('10-macvlan-98.netdev') == True)
        assert(unit_exist('10-macvlan-98.network') == True)
        assert(unit_exist('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '3'])

        assert(link_exist('macvlan-98') == True)

        macvlan_parser = configparser.ConfigParser()
        macvlan_parser.read(os.path.join(networkd_unit_file_path, '10-macvlan-98.netdev'))

        assert(macvlan_parser.get('NetDev', 'Name') == 'macvlan-98')
        assert(macvlan_parser.get('NetDev', 'kind') == 'macvlan')
        assert(macvlan_parser.get('MACVLAN', 'Mode') == 'private')

        macvlan_network_parser = configparser.ConfigParser()
        macvlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-macvlan-98.network'))

        assert(macvlan_network_parser.get('Match', 'Name') == 'macvlan-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'MACVLAN') == 'macvlan-98')

        subprocess.check_call("nmctl remove-netdev macvlan-98 kind macvlan" , shell = True)
        assert(unit_exist('10-macvlan-98.netdev') == False)
        assert(unit_exist('10-macvlan-98.network') == False)

    def test_cli_create_macvtap(self):
        assert(link_exist('test98') == True)

        subprocess.check_call("nmctl create-macvtap macvtap-98 dev test98 mode private", shell = True)
        assert(unit_exist('10-macvtap-98.netdev') == True)
        assert(unit_exist('10-macvtap-98.network') == True)
        assert(unit_exist('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '3'])

        assert(link_exist('macvtap-98') == True)

        macvlan_parser = configparser.ConfigParser()
        macvlan_parser.read(os.path.join(networkd_unit_file_path, '10-macvtap-98.netdev'))

        assert(macvlan_parser.get('NetDev', 'Name') == 'macvtap-98')
        assert(macvlan_parser.get('NetDev', 'kind') == 'macvtap')
        assert(macvlan_parser.get('MACVTAP', 'Mode') == 'private')

        macvlan_network_parser = configparser.ConfigParser()
        macvlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-macvtap-98.network'))

        assert(macvlan_network_parser.get('Match', 'Name') == 'macvtap-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'MACVTAP') == 'macvtap-98')

        subprocess.check_call("nmctl remove-netdev macvtap-98 kind macvtap" , shell = True)
        assert(unit_exist('10-macvtap-98.netdev') == False)
        assert(unit_exist('10-macvtap-98.network') == False)

    def test_cli_create_ipvlan(self):
        assert(link_exist('test98') == True)

        subprocess.check_call("nmctl create-ipvlan ipvlan-98 dev test98 mode l2", shell = True)
        assert(unit_exist('10-ipvlan-98.netdev') == True)
        assert(unit_exist('10-ipvlan-98.network') == True)
        assert(unit_exist('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '3'])

        assert(link_exist('ipvlan-98') == True)

        ipvlan_parser = configparser.ConfigParser()
        ipvlan_parser.read(os.path.join(networkd_unit_file_path, '10-ipvlan-98.netdev'))

        assert(ipvlan_parser.get('NetDev', 'Name') == 'ipvlan-98')
        assert(ipvlan_parser.get('NetDev', 'kind') == 'ipvlan')
        assert(ipvlan_parser.get('IPVLAN', 'Mode') == 'L2')

        ipvlan_network_parser = configparser.ConfigParser()
        ipvlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-ipvlan-98.network'))

        assert(ipvlan_network_parser.get('Match', 'Name') == 'ipvlan-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'IPVLAN') == 'ipvlan-98')

        subprocess.check_call("nmctl remove-netdev ipvlan-98 kind ipvlan" , shell = True)
        assert(unit_exist('10-ipvlan-98.netdev') == False)
        assert(unit_exist('10-ipvlan-98.network') == False)

    def test_cli_create_ipvtap(self):
        assert(link_exist('test98') == True)

        subprocess.check_call("nmctl create-ipvtap ipvtap-98 dev test98 mode l2", shell = True)
        assert(unit_exist('10-ipvtap-98.netdev') == True)
        assert(unit_exist('10-ipvtap-98.network') == True)
        assert(unit_exist('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '3'])

        assert(link_exist('ipvtap-98') == True)

        ipvtap_parser = configparser.ConfigParser()
        ipvtap_parser.read(os.path.join(networkd_unit_file_path, '10-ipvtap-98.netdev'))

        assert(ipvtap_parser.get('NetDev', 'Name') == 'ipvtap-98')
        assert(ipvtap_parser.get('NetDev', 'kind') == 'ipvtap')
        assert(ipvtap_parser.get('IPVTAP', 'Mode') == 'L2')

        ipvtap_network_parser = configparser.ConfigParser()
        ipvtap_network_parser.read(os.path.join(networkd_unit_file_path, '10-ipvtap-98.network'))

        assert(ipvtap_network_parser.get('Match', 'Name') == 'ipvtap-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'IPVTAP') == 'ipvtap-98')

        subprocess.check_call("nmctl remove-netdev ipvtap-98 kind ipvtap" , shell = True)
        assert(unit_exist('10-ipvtap-98.netdev') == False)
        assert(unit_exist('10-ipvtap-98.network') == False)

    @pytest.mark.skip(reason="skipping")
    def test_cli_create_vrf(self):
        subprocess.check_call("nmctl create-vrf vrf-98 table 11", shell = True)
        assert(unit_exist('10-vrf-98.netdev') == True)
        assert(unit_exist('10-vrf-98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '3'])

        assert(link_exist('vrf-98') == True)

        vrf_parser = configparser.ConfigParser()
        vrf_parser.read(os.path.join(networkd_unit_file_path, '10-vrf-98.netdev'))

        assert(vrf_parser.get('NetDev', 'Name') == 'vrf-98')
        assert(vrf_parser.get('NetDev', 'kind') == 'vrf')
        assert(vrf_parser.get('VRF', 'Table') == '11')

        vrf_network_parser = configparser.ConfigParser()
        vrf_network_parser.read(os.path.join(networkd_unit_file_path, '10-vrf-98.network'))

        assert(vrf_network_parser.get('Match', 'Name') == 'vrf-98')

        subprocess.check_call("nmctl remove-netdev vrf-98 kind vrf" , shell = True)
        assert(unit_exist('10-vrf-98.netdev') == False)
        assert(unit_exist('10-vrf-98.network') == False)

    def test_cli_create_veth(self):
        subprocess.check_call("nmctl create-veth veth-98 peer veth-99" , shell = True)
        assert(unit_exist('10-veth-98.netdev') == True)
        assert(unit_exist('10-veth-98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '3'])

        assert(link_exist('veth-98') == True)
        assert(link_exist('veth-99') == True)

        veth_parser = configparser.ConfigParser()
        veth_parser.read(os.path.join(networkd_unit_file_path, '10-veth-98.netdev'))

        assert(veth_parser.get('NetDev', 'Name') == 'veth-98')
        assert(veth_parser.get('NetDev', 'kind') == 'veth')
        assert(veth_parser.get('Peer', 'Name') == 'veth-99')

        veth_network_parser = configparser.ConfigParser()
        veth_network_parser.read(os.path.join(networkd_unit_file_path, '10-veth-98.network'))

        assert(veth_network_parser.get('Match', 'Name') == 'veth-98')

        subprocess.check_call("nmctl remove-netdev veth-98 kind veth" , shell = True)
        assert(unit_exist('10-veth-98.netdev') == False)
        assert(unit_exist('10-veth-98.network') == False)

    def test_cli_create_tap_no_args(self):
        subprocess.check_call("nmctl create-tap test-tap" , shell = True)
        assert(unit_exist('10-test-tap.netdev') == True)
        assert(unit_exist('10-test-tap.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '10'])

        assert(link_exist('test-tap') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test-tap.netdev'))

        assert(parser.get('NetDev', 'Name') == 'test-tap')
        assert(parser.get('NetDev', 'kind') == 'tap')

        tun_network_parser = configparser.ConfigParser()
        tun_network_parser.read(os.path.join(networkd_unit_file_path, '10-test-tap.network'))

        assert(tun_network_parser.get('Match', 'Name') == 'test-tap')

        subprocess.check_call("nmctl remove-netdev test-tap kind tap" , shell = True)
        assert(unit_exist('10-test-tap.netdev') == False)
        assert(unit_exist('10-test-tap.network') == False)


    def test_cli_create_tap(self):
        subprocess.check_call("nmctl create-tap test-tap vnet-hdr yes" , shell = True)
        assert(unit_exist('10-test-tap.netdev') == True)
        assert(unit_exist('10-test-tap.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '10'])

        assert(link_exist('test-tap') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test-tap.netdev'))

        assert(parser.get('NetDev', 'Name') == 'test-tap')
        assert(parser.get('NetDev', 'kind') == 'tap')

        tun_network_parser = configparser.ConfigParser()
        tun_network_parser.read(os.path.join(networkd_unit_file_path, '10-test-tap.network'))

        assert(tun_network_parser.get('Match', 'Name') == 'test-tap')

        subprocess.check_call("nmctl remove-netdev test-tap kind tap" , shell = True)
        assert(unit_exist('10-test-tap.netdev') == False)
        assert(unit_exist('10-test-tap.network') == False)

    def test_cli_create_tun(self):
        subprocess.check_call("nmctl create-tun test-tun vnet-hdr yes" , shell = True)
        assert(unit_exist('10-test-tun.netdev') == True)
        assert(unit_exist('10-test-tun.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '10'])

        assert(link_exist('test-tun') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test-tun.netdev'))

        assert(parser.get('NetDev', 'Name') == 'test-tun')
        assert(parser.get('NetDev', 'kind') == 'tun')

        tun_network_parser = configparser.ConfigParser()
        tun_network_parser.read(os.path.join(networkd_unit_file_path, '10-test-tun.network'))

        assert(tun_network_parser.get('Match', 'Name') == 'test-tun')

        subprocess.check_call("nmctl remove-netdev test-tun kind tun" , shell = True)
        assert(unit_exist('10-test-tun.netdev') == False)
        assert(unit_exist('10-test-tun.network') == False)

    def test_cli_create_ipip(self):
        assert(link_exist('test98') == True)

        subprocess.check_call("nmctl create-ipip ipip-98 dev test98 local 192.168.1.2 remote 192.168.1.3", shell = True)
        assert(unit_exist('10-ipip-98.netdev') == True)
        assert(unit_exist('10-ipip-98.network') == True)
        assert(unit_exist('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '3'])

        assert(link_exist('ipip-98') == True)

        ipip_parser = configparser.ConfigParser()
        ipip_parser.read(os.path.join(networkd_unit_file_path, '10-ipip-98.netdev'))

        assert(ipip_parser.get('NetDev', 'Name') == 'ipip-98')
        assert(ipip_parser.get('NetDev', 'kind') == 'ipip')
        assert(ipip_parser.get('Tunnel', 'Local') == '192.168.1.2')
        assert(ipip_parser.get('Tunnel', 'Remote') == '192.168.1.3')

        ipip_network_parser = configparser.ConfigParser()
        ipip_network_parser.read(os.path.join(networkd_unit_file_path, '10-ipip-98.network'))

        assert(ipip_network_parser.get('Match', 'Name') == 'ipip-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'Tunnel') == 'ipip-98')

        subprocess.check_call("nmctl remove-netdev ipip-98 kind ipip" , shell = True)
        assert(unit_exist('10-ipip-98.netdev') == False)
        assert(unit_exist('10-ipip-98.network') == False)

    def test_cli_create_ipip_without_master_device(self):
        subprocess.check_call("nmctl create-ipip ipip-98 local 192.168.1.2 remote 192.168.1.3 independent yes", shell = True)
        assert(unit_exist('10-ipip-98.netdev') == True)
        assert(unit_exist('10-ipip-98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '3'])

        assert(link_exist('ipip-98') == True)

        ipip_parser = configparser.ConfigParser()
        ipip_parser.read(os.path.join(networkd_unit_file_path, '10-ipip-98.netdev'))

        assert(ipip_parser.get('NetDev', 'Name') == 'ipip-98')
        assert(ipip_parser.get('NetDev', 'kind') == 'ipip')
        assert(ipip_parser.get('Tunnel', 'Local') == '192.168.1.2')
        assert(ipip_parser.get('Tunnel', 'Remote') == '192.168.1.3')

        ipip_network_parser = configparser.ConfigParser()
        ipip_network_parser.read(os.path.join(networkd_unit_file_path, '10-ipip-98.network'))

        assert(ipip_network_parser.get('Match', 'Name') == 'ipip-98')

        subprocess.check_call("nmctl remove-netdev ipip-98 kind ipip" , shell = True)
        assert(unit_exist('10-ipip-98.netdev') == False)
        assert(unit_exist('10-ipip-98.network') == False)

    def test_cli_create_gre(self):
        assert(link_exist('test98') == True)

        subprocess.check_call("nmctl create-gre gre-98 dev test98 local 192.168.1.2 remote 192.168.1.3", shell = True)
        assert(unit_exist('10-gre-98.netdev') == True)
        assert(unit_exist('10-gre-98.network') == True)
        assert(unit_exist('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '3'])

        assert(link_exist('gre-98') == True)

        gre_parser = configparser.ConfigParser()
        gre_parser.read(os.path.join(networkd_unit_file_path, '10-gre-98.netdev'))

        assert(gre_parser.get('NetDev', 'Name') == 'gre-98')
        assert(gre_parser.get('NetDev', 'kind') == 'gre')
        assert(gre_parser.get('Tunnel', 'Local') == '192.168.1.2')
        assert(gre_parser.get('Tunnel', 'Remote') == '192.168.1.3')

        gre_network_parser = configparser.ConfigParser()
        gre_network_parser.read(os.path.join(networkd_unit_file_path, '10-gre-98.network'))

        assert(gre_network_parser.get('Match', 'Name') == 'gre-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'Tunnel') == 'gre-98')

        subprocess.check_call("nmctl remove-netdev gre-98 kind gre" , shell = True)
        assert(unit_exist('10-gre-98.netdev') == False)
        assert(unit_exist('10-gre-98.network') == False)


    def test_cli_create_vti(self):
        assert(link_exist('test98') == True)

        subprocess.check_call("nmctl create-vti vti-98 dev test98 local 192.168.1.2 remote 192.168.1.3", shell = True)
        assert(unit_exist('10-vti-98.netdev') == True)
        assert(unit_exist('10-vti-98.network') == True)
        assert(unit_exist('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '3'])

        assert(link_exist('vti-98') == True)

        vti_parser = configparser.ConfigParser()
        vti_parser.read(os.path.join(networkd_unit_file_path, '10-vti-98.netdev'))

        assert(vti_parser.get('NetDev', 'Name') == 'vti-98')
        assert(vti_parser.get('NetDev', 'kind') == 'vti')
        assert(vti_parser.get('Tunnel', 'Local') == '192.168.1.2')
        assert(vti_parser.get('Tunnel', 'Remote') == '192.168.1.3')

        vti_network_parser = configparser.ConfigParser()
        vti_network_parser.read(os.path.join(networkd_unit_file_path, '10-vti-98.network'))

        assert(vti_network_parser.get('Match', 'Name') == 'vti-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'Tunnel') == 'vti-98')

        subprocess.check_call("nmctl remove-netdev vti-98 kind vti" , shell = True)
        assert(unit_exist('10-vti-98.netdev') == False)
        assert(unit_exist('10-vti-98.network') == False)

    def test_cli_create_wireguard(self):
        subprocess.check_call("nmctl create-wg wg99 private-key EEGlnEPYJV//kbvvIqxKkQwOiS+UENyPncC4bF46ong= listen-port 32 "
                              "public-key RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA endpoint 192.168.3.56:2000 allowed-ips 192.168.1.2 "
                              "private-key-file /etc/systemd/network/key.file preshared-key-file /etc/systemd/network/prekey.file", shell = True)

        assert(unit_exist('10-wg99.netdev') == True)
        assert(unit_exist('10-wg99.network') == True)

        restart_networkd()

        wg_parser = configparser.ConfigParser()
        wg_parser.read(os.path.join(networkd_unit_file_path, '10-wg99.netdev'))

        assert(wg_parser.get('NetDev', 'Name') == 'wg99')
        assert(wg_parser.get('NetDev', 'kind') == 'wireguard')

        assert(wg_parser.get('WireGuard', 'PrivateKey') == 'EEGlnEPYJV//kbvvIqxKkQwOiS+UENyPncC4bF46ong=')
        assert(wg_parser.get('WireGuard', 'PrivateKeyFile') == '/etc/systemd/network/key.file')
        assert(wg_parser.get('WireGuard', 'ListenPort') == '32')

        assert(wg_parser.get('WireGuardPeer', 'PublicKey') == 'RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA')
        assert(wg_parser.get('WireGuardPeer', 'Endpoint') == '192.168.3.56:2000')
        assert(wg_parser.get('WireGuardPeer', 'AllowedIPs') == '192.168.1.2')
        assert(wg_parser.get('WireGuardPeer', 'PresharedKeyFile') == '/etc/systemd/network/prekey.file')

        network_parser = configparser.ConfigParser()
        network_parser.read(os.path.join(networkd_unit_file_path, '10-wg99.network'))

        assert(network_parser.get('Match', 'Name') == 'wg99')

    def test_cli_create_vxlan(self):
        assert(link_exist('test98') == True)

        subprocess.check_call("nmctl create-vxlan vxlan-98 dev test98 vni 32 local 192.168.1.2 remote 192.168.1.3 dport 7777", shell = True)
        assert(unit_exist('10-test98.network') == True)
        assert(unit_exist('10-vxlan-98.network') == True)
        assert(unit_exist('10-vxlan-98.netdev') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '10'])

        assert(link_exist('vxlan-98') == True)

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

        subprocess.check_call("nmctl remove-netdev vxlan-98 kind vxlan" , shell = True)
        assert(unit_exist('10-vxlan-98.netdev') == False)
        assert(unit_exist('10-vxlan-98.network') == False)

    def test_cli_create_vxlan_without_master(self):
        subprocess.check_call("nmctl create-vxlan vxlan-98 vni 32 local 192.168.1.2 remote 192.168.1.3 dport 7777 independent yes", shell = True)
        assert(unit_exist('10-vxlan-98.network') == True)
        assert(unit_exist('10-vxlan-98.netdev') == True)

        restart_networkd()

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

        subprocess.check_call("nmctl remove-netdev vxlan-98 kind vxlan" , shell = True)
        assert(unit_exist('10-vxlan-98.netdev') == False)
        assert(unit_exist('10-vxlan-98.network') == False)

    def test_cli_create_bridge(self):
        link_add_dummy('test-99')
        assert(link_exist('test98') == True)
        assert(link_exist('test-99') == True)

        subprocess.check_call("nmctl create-bridge bridge-98 dev test98,test-99 stp yes", shell = True)
        assert(unit_exist('10-test98.network') == True)
        assert(unit_exist('10-test-99.network') == True)
        assert(unit_exist('10-bridge-98.network') == True)
        assert(unit_exist('10-bridge-98.netdev') == True)

        subprocess.check_call(['sleep', '3'])

        assert(link_exist('bridge-98') == True)

        bridge_parser = configparser.ConfigParser()
        bridge_parser.read(os.path.join(networkd_unit_file_path, '10-bridge-98.netdev'))

        assert(bridge_parser.get('NetDev', 'Name') == 'bridge-98')
        assert(bridge_parser.get('NetDev', 'kind') == 'bridge')

        assert(bridge_parser.get('Bridge', 'STP') == 'yes')

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

        subprocess.check_call("nmctl remove-netdev bridge-98 kind bridge" , shell = True)
        assert(unit_exist('10-bridge-98.netdev') == False)
        assert(unit_exist('10-bridge-98.network') == False)

        link_remove('test-99')

    def test_cli_create_bond(self):
        link_add_dummy('test-99')
        assert(link_exist('test98') == True)
        assert(link_exist('test-99') == True)

        subprocess.check_call("nmctl create-bond bond-98 mode balance-rr xmit-hash-policy layer2+3 dev test98,test-99", shell = True)
        assert(unit_exist('10-test98.network') == True)
        assert(unit_exist('10-test-99.network') == True)
        assert(unit_exist('10-bond-98.network') == True)
        assert(unit_exist('10-bond-98.netdev') == True)

        subprocess.check_call(['sleep', '3'])

        assert(link_exist('bond-98') == True)

        bond_parser = configparser.ConfigParser()
        bond_parser.read(os.path.join(networkd_unit_file_path, '10-bond-98.netdev'))

        assert(bond_parser.get('NetDev', 'Name') == 'bond-98')
        assert(bond_parser.get('NetDev', 'kind') == 'bond')

        assert(bond_parser.get('Bond', 'Mode') == 'balance-rr')
        assert(bond_parser.get('Bond', 'TransmitHashPolicy') == 'layer2+3')

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

        subprocess.check_call("nmctl remove-netdev bond-98 kind bond" , shell = True)
        assert(unit_exist('10-bond-98.netdev') == False)
        assert(unit_exist('10-bond-98.network') == False)

        link_remove('test-99')

    def test_cli_create_vlan_failure(self):
        assert(link_exist('test98') == True)

        assert(call_shell("nmctl create-vlan dev test98 id 11") != 0)
        assert(unit_exist('10-test98.network') == False)
        assert(unit_exist('10-vlan-98.netdev') == False)
        assert(unit_exist('10-vlan-98.network') == False)

    def test_cli_create_bond_failure(self):
        assert(link_exist('test98') == True)

        assert(call_shell("nmctl create-bond mode balance-rr dev") != 0)
        assert(unit_exist('10-test98.network') == False)
        assert(unit_exist('10-test-99.network') == False)
        assert(unit_exist('10-bond-98.network') == False)
        assert(unit_exist('10-bond-98.netdev') == False)

class TestCLIGlobalDNSDomain:
    @pytest.mark.skip(reason="skipping")
    def test_cli_configure_global_dns_server(self):
        subprocess.check_call("nmctl add-dns global dns 8.8.4.4 8.8.8.8 8.8.8.1", shell = True)

        parser = configparser.ConfigParser()
        parser.read('/etc/systemd/resolved.conf')

        dns = parser.get('Resolve', 'DNS')
        assert(dns.find("8.8.4.4") != -1)
        assert(dns.find("8.8.8.8") != -1)
        assert(dns.find("8.8.8.1") != -1)

    @pytest.mark.skip(reason="skipping")
    def test_cli_configure_global_domain_server(self):
        subprocess.check_call("nmctl add-domain global domains test1 test2", shell = True)

        parser = configparser.ConfigParser()
        parser.read('/etc/systemd/resolved.conf')

        d = parser.get('Resolve', 'Domains')
        assert(dns.find("test1") != -1)
        assert(dns.find("test2") != -1)

class TestCLINetworkProxy:
    def test_cli_configure_network_proxy(self):

        if not os.path.exists("/etc/sysconfig/"):
                os.mkdir("/etc/sysconfig/")

        f = open("/etc/sysconfig/proxy", "w")
        f.write("PROXY_ENABLED=\"no\"\nHTTP_PROXY=""\nHTTPS_PROXY=""\nNO_PROXY=\"localhost, 127.0.0.1\"\n")
        f.close()

        subprocess.check_call("nmctl set-proxy enable yes http http://test.com:123 https https://test.com:123", shell = True )

        dictionary = {}
        file = open("/etc/sysconfig/proxy")

        lines = file.read().split('\n')

        for line in lines:
            if line == '':
                 continue
            pair = line.split('=')
            dictionary[pair[0].strip('\'\'\"\"')] = pair[1].strip('\'\'\"\"')

        assert(dictionary["HTTP_PROXY"] == "http://test.com:123")
        assert(dictionary["HTTPS_PROXY"] == "https://test.com:123")
        assert(dictionary["PROXY_ENABLED"] == "yes")

        subprocess.check_call("nmctl set-proxy enable yes http http://test.com:123 ftp https://test.com123", shell = True)

class TestWifiWPASupplicantConf:
    yaml_configs = [
        "name-password-wifi-dhcp.yaml",
        "name-password-wifi-static.yaml",
        "wpa-eap-tls-wifi.yaml",
        "wpa-eap-ttls.yaml",
    ]

    def copy_yaml_file_to_network_config_manager_yaml_path(self, config_file):
        shutil.copy(os.path.join(network_config_manager_ci_yaml_path, config_file), network_config_manager_yaml_config_path)

    def remove_units_from_network_config_manager_yaml_path(self):
        for config_file in self.yaml_configs:
            if (os.path.exists(os.path.join(network_config_manager_yaml_config_path, config_file))):
                os.remove(os.path.join(network_config_manager_yaml_config_path, config_file))

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        self.remove_units_from_network_config_manager_yaml_path()

    @pytest.mark.skip(reason="skipping")
    def test_wifi_wpa_supplicant_name_password_dhcp(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('name-password-wifi-dhcp.yaml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-wlan1.network') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-wlan1.network'))

        assert(parser.get('Match', 'Name') == 'wlan1')
        assert(parser.get('Network', 'DHCP') == 'yes')

        assert(wifi_wpa_supplilant_conf_exits() == True)

        network = read_wpa_supplicant_conf(network_config_manager_wpa_supplilant_conf_file)
        assert(network["ssid"] == "network_ssid_name1")
        assert(network["password"] == "test123")

    @pytest.mark.skip(reason="skipping")
    def test_wifi_wpa_supplicant_name_password_static(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('name-password-wifi-static.yaml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-wlan1.network') == True)

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
        self.copy_yaml_file_to_network_config_manager_yaml_path('wpa-eap-tls-wifi.yaml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-wlan1.network') == True)

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

    @pytest.mark.skip(reason="skipping")
    def test_wifi_wpa_supplicant_eap_ttls_dhcp(self):
        self.copy_yaml_file_to_network_config_manager_yaml_path('wpa-eap-ttls.yaml')

        subprocess.check_call("nmctl apply", shell = True)
        assert(unit_exist('10-wlan0.network') == True)

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

class TestCLILink:
    def setup_method(self):
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        link_remove('test99')

    def test_cli_set_link(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link', 'test99', 'alias', 'ifalias', 'desc', 'testconf', 'mtu', '10M', 'bps', '5G', 'duplex', 'full', 'wol', 'phy,unicast,broadcast,multicast,arp,magic,secureon', 'wolp', 'cb:a9:87:65:43:21', 'port', 'mii', 'advertise', '10baset-half,10baset-full,100baset-half,100baset-full,1000baset-half,1000baset-full,10000baset-full,2500basex-full,1000basekx-full,10000basekx4-full,10000basekr-full,10000baser-fec,20000basemld2-full,20000basekr2-full'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'Alias') == 'ifalias')
        assert(parser.get('Link', 'Description') == 'testconf')
        assert(parser.get('Link', 'MTUBytes') == '10M')
        assert(parser.get('Link', 'BitsPerSecond') == '5G')
        assert(parser.get('Link', 'Duplex') == 'full')
        assert(parser.get('Link', 'WakeOnLan') == 'phy unicast broadcast multicast arp magic secureon')
        assert(parser.get('Link', 'WakeOnLanPassword') == 'cb:a9:87:65:43:21')
        assert(parser.get('Link', 'Port') == 'mii')
        assert(parser.get('Link', 'Advertise') == '10baset-half 10baset-full 100baset-half 100baset-full 1000baset-half 1000baset-full 10000baset-full 2500basex-full 1000basekx-full 10000basekx4-full 10000basekr-full 10000baser-fec 20000basemld2-full 20000basekr2-full')

    def test_cli_set_link_feature(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-feature', 'test99', 'auton', 'no', 'rxcsumo', 'yes', 'txcsumo', 'no', 'tso', 'no', 'tso6', '1', 'gso', '0', 'grxo', 'false', 'grxoh', 'no', 'lrxo', '1', 'rxvtha', 'True', 'txvtha', '0', 'rxvtf', 'no', 'txvstha', 'yes', 'ntf', 'false', 'uarxc', '1', 'uatxc', 'yes'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'AutoNegotiation') == 'no')
        assert(parser.get('Link', 'ReceiveChecksumOffload') == 'yes')
        assert(parser.get('Link', 'TransmitChecksumOffload') == 'no')
        assert(parser.get('Link', 'TCPSegmentationOffload') == 'no')
        assert(parser.get('Link', 'TCP6SegmentationOffload') == 'yes')
        assert(parser.get('Link', 'GenericSegmentationOffload') == 'no')
        assert(parser.get('Link', 'GenericReceiveOffload') == 'no')
        assert(parser.get('Link', 'GenericReceiveOffloadHardware') == 'no')
        assert(parser.get('Link', 'LargeReceiveOffload') == 'yes')
        assert(parser.get('Link', 'ReceiveVLANCTAGHardwareAcceleration') == 'yes')
        assert(parser.get('Link', 'TransmitVLANCTAGHardwareAcceleration') == 'no')
        assert(parser.get('Link', 'ReceiveVLANCTAGFilter') == 'no')
        assert(parser.get('Link', 'TransmitVLANSTAGHardwareAcceleration') == 'yes')
        assert(parser.get('Link', 'NTupleFilter') == 'no')
        assert(parser.get('Link', 'UseAdaptiveRxCoalesce') == 'yes')
        assert(parser.get('Link', 'UseAdaptiveTxCoalesce') == 'yes')

    def test_cli_set_link_mac_policy(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-mac', 'test99', 'macpolicy', 'none'])

        subprocess.check_call(['nmctl', 'set-link-mac', 'test99', 'macaddr', '00:0c:29:3a:bc:11'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'MACAddressPolicy') == 'none')
        assert(parser.get('Link', 'MACAddress') == '00:0c:29:3a:bc:11')

    def test_cli_set_link_name(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-name', 'test99', 'namepolicy', 'kernel,database,onboard,slot,path,mac,keep', 'name', 'dm1'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'NamePolicy') == 'kernel database onboard slot path mac keep')
        assert(parser.get('Link', 'Name') == 'dm1')

    def test_cli_set_link_alt_name(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-altname', 'test99', 'altnamepolicy', 'database,onboard,slot,path,mac', 'altname', 'demo1'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'AlternativeNamesPolicy') == 'database onboard slot path mac')
        assert(parser.get('Link', 'AlternativeName') == 'demo1')

    def test_cli_set_link_buff(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-buf', 'test99', 'rxbuf', 'max', 'rxminbuf', '65335', 'rxjumbobuf', '88776555', 'txbuf', 'max'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'RxBufferSize') == 'max')
        assert(parser.get('Link', 'RxMiniBufferSize') == '65335')
        assert(parser.get('Link', 'RxJumboBufferSize') == '88776555')
        assert(parser.get('Link', 'TxBufferSize') == 'max')

    def test_cli_set_link_queue(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-queue', 'test99', 'rxq', '4096', 'txq', '4096', 'txqlen', '1024'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'TransmitQueues') == '4096')
        assert(parser.get('Link', 'ReceiveQueues') == '4096')
        assert(parser.get('Link', 'TransmitQueueLength') == '1024')

    def test_cli_set_link_flow_control(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-flow-control', 'test99', 'rxflowctrl', 'yes', 'txflowctrl', 'no', 'autoflowctrl', 'yes'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'RxFlowControl') == 'yes')
        assert(parser.get('Link', 'TxFlowControl') == 'no')
        assert(parser.get('Link', 'AutoNegotiationFlowControl') == 'yes')

    def test_cli_set_link_gso(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-gso', 'test99', 'gsob', '65535', 'gsos', '1024'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'GenericSegmentOffloadMaxBytes') == '65535')
        assert(parser.get('Link', 'GenericSegmentOffloadMaxSegments') == '1024')

    def test_cli_set_link_channel(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-channel', 'test99', 'rxch', 'max', 'txch', '656756677', 'otrch', '429496729', 'combch', 'max'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'RxChannels') == 'max')
        assert(parser.get('Link', 'TxChannels') == '656756677')
        assert(parser.get('Link', 'OtherChannels') == '429496729')
        assert(parser.get('Link', 'CombinedChannels') == 'max')

    def test_cli_set_link_coalesce(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-coalesce', 'test99', 'rxcs', 'max', 'rxcsirq', '123456', 'rxcslow', '997654', 'rxcshigh', '87654322', 'txcs', 'max', 'txcsirq', '123456', 'txcslow', '997654', 'txcshigh', '87654322'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'RxCoalesceSec') == 'max')
        assert(parser.get('Link', 'RxCoalesceIrqSec') == '123456')
        assert(parser.get('Link', 'RxCoalesceLowSec') == '997654')
        assert(parser.get('Link', 'RxCoalesceHighSec') == '87654322')
        assert(parser.get('Link', 'TxCoalesceSec') == 'max')
        assert(parser.get('Link', 'TxCoalesceIrqSec') == '123456')
        assert(parser.get('Link', 'TxCoalesceLowSec') == '997654')
        assert(parser.get('Link', 'TxCoalesceHighSec') == '87654322')

    def test_cli_set_link_coald_frames(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-coald-frames', 'test99', 'rxmcf', 'max', 'rxmcfirq', '123456', 'rxmcflow', '997654', 'rxmcfhigh', '87654322', 'txmcf', '65532', 'txmcfirq', '987654', 'txmcflow', '12345', 'txmcfhigh', '98776555'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'RxMaxCoalescedFrames') == 'max')
        assert(parser.get('Link', 'RxMaxCoalescedIrqFrames') == '123456')
        assert(parser.get('Link', 'RxMaxCoalescedLowFrames') == '997654')
        assert(parser.get('Link', 'RxMaxCoalescedHighFrames') == '87654322')
        assert(parser.get('Link', 'TxMaxCoalescedFrames') == '65532')
        assert(parser.get('Link', 'TxMaxCoalescedIrqFrames') == '987654')
        assert(parser.get('Link', 'TxMaxCoalescedLowFrames') == '12345')
        assert(parser.get('Link', 'TxMaxCoalescedHighFrames') == '98776555')

    def test_cli_set_link_coal_pkt_rate(self):
        assert(link_exist('test99') == True)

        subprocess.check_call(['nmctl', 'set-link-coal-pkt', 'test99', 'cprlow', '123456789', 'cprhigh', 'max', 'cprsis', '99877761', 'sbcs', '987766555'])
        assert(unit_exist('10-test99.link') == True)

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('Link', 'CoalescePacketRateLow') == '123456789')
        assert(parser.get('Link', 'CoalescePacketRateHigh') == 'max')
        assert(parser.get('Link', 'CoalescePacketRateSampleIntervalSec') == '99877761')
        assert(parser.get('Link', 'StatisticsBlockCoalesceSec') == '987766555')

    def test_cli_set_link_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-link test99 alias ifalias desc testconf mtub 10M bps 5G duplex full wol phyunicastbroadcastmulticastarpmagicsecureon woolp port mii advertise") != 0)
        assert(unit_exist('10-test99.link') == False)

    def test_cli_set_link_feature_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-link-feature test99 auton") != 0)
        assert(unit_exist('10-test99.link') == False)

    def test_cli_set_link_mac_policy_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-link-mac test99 none") != 0)

        assert(call_shell("nmctl set-link-mac test99 macaddr") != 0)
        assert(unit_exist('10-test99.link') == False)

    def test_cli_set_link_buff_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-link-buf test99 rxbuf maximum rxminbuf notstring rxjumbobuf") != 0)
        assert(unit_exist('10-test99.link') == False)

    def test_cli_set_link_channel_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-link-channel test99 ch max 656756677 otrch") != 0)
        assert(unit_exist('10-test99.link') == False)

    def test_cli_set_link_coalesce_failure(self):
        assert(link_exist('test99') == True)

        assert(call_shell("nmctl set-link-coalesce test99 rxcs max 123456") != 0)
        assert(unit_exist('10-test99.link') == False)

class TestCLISRIOV:
    def teardown_method(self):
        remove_units_from_netword_unit_path()

    @expectedFailureIfNetdevsimWithSRIOVIsNotAvailable()
    def test_sriov(self):

        if call_shell('modprobe netdevsim') != 0:
            return

        with open('/sys/bus/netdevsim/new_device', mode='w', encoding='utf-8') as f:
            f.write('99 1')

        with open('/sys/bus/netdevsim/devices/netdevsim99/sriov_numvfs', mode='w', encoding='utf-8') as f:
            f.write('3')

        output = subprocess.call("ip link", shell=True)
        print(output)

        subprocess.check_call("nmctl add-sr-iov dev eni99np1 vf 0 vlanid 5 qos 1 vlanproto "
                               "802.1Q macspoofck yes qrss True trust yes linkstate yes "
                               "macaddr 00:11:22:33:44:55", shell = True)


        assert(unit_exist('10-eni99np1.network') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-eni99np1.network'))

        assert(parser.get('Match', 'Name') == 'eni99np1')

        assert(parser.get('SR-IOV', 'VirtualFunction') == '0')
        assert(parser.get('SR-IOV', 'VLANId') == '5')
        assert(parser.get('SR-IOV', 'QualityOfService') == '1')
        assert(parser.get('SR-IOV', 'VLANProtocol') == '802.1Q')
        assert(parser.get('SR-IOV', 'MACSpoofCheck') == 'yes')
        assert(parser.get('SR-IOV', 'QueryReceiveSideScaling') == 'yes')
        assert(parser.get('SR-IOV', 'Trust') == 'yes')
        assert(parser.get('SR-IOV', 'LinkState') == 'yes')
        assert(parser.get('SR-IOV', 'MACAddress') == '00:11:22:33:44:55')

        subprocess.check_call("nmctl add-sr-iov dev eni99np1 vf 1 vlanid 6 qos 2 vlanproto 802.1Q macspoofck yes qrss True trust yes linkstate yes "
                              "macaddr 00:11:22:33:44:56", shell = True)

        subprocess.check_call("nmctl add-sr-iov dev eni99np1 vf 2 vlanid 7 qos 3 vlanproto 802.1Q macspoofck yes qrss True trust yes linkstate yes "
                              "macaddr 00:11:22:33:44:57", shell = True)

        restart_networkd()
        subprocess.check_call(['sleep', '10'])

        output = subprocess.call('ip link', shell=True)
        print(output)
        subprocess.check_call("rmmod netdevsim", shell=True)

class TestCLISRIOLink:
    def setup_method(self):
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        link_remove('test99')

    def test_sriov(self):

        output = subprocess.call("ip link", shell=True)
        print(output)

        subprocess.check_call("nmctl add-link-sr-iov dev test99 vf 0 vlanid 5 qos 1 vlanproto "
                               "802.1Q macspoofck yes qrss True trust yes linkstate yes "
                               "macaddr 00:11:22:33:44:55", shell = True)


        assert(unit_exist('10-test99.link') == True)
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.link'))

        assert(parser.get('SR-IOV', 'VirtualFunction') == '0')
        assert(parser.get('SR-IOV', 'VLANId') == '5')
        assert(parser.get('SR-IOV', 'QualityOfService') == '1')
        assert(parser.get('SR-IOV', 'VLANProtocol') == '802.1Q')
        assert(parser.get('SR-IOV', 'MACSpoofCheck') == 'yes')
        assert(parser.get('SR-IOV', 'QueryReceiveSideScaling') == 'yes')
        assert(parser.get('SR-IOV', 'Trust') == 'yes')
        assert(parser.get('SR-IOV', 'LinkState') == 'yes')
        assert(parser.get('SR-IOV', 'MACAddress') == '00:11:22:33:44:55')

        subprocess.check_call("nmctl add-sr-iov dev test99 vf 1 vlanid 6 qos 2 vlanproto 802.1Q macspoofck yes qrss True trust yes linkstate yes "
                              "macaddr 00:11:22:33:44:56", shell = True)

        subprocess.check_call("nmctl add-sr-iov dev test99 vf 2 vlanid 7 qos 3 vlanproto 802.1Q macspoofck yes qrss True trust yes linkstate yes "
                              "macaddr 00:11:22:33:44:57", shell = True)

        output = subprocess.call('ip link', shell=True)
        print(output)

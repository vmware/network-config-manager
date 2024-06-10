:orphan:

network-config-manager manual page
====================================

Description
-----------
The network-config-manager nmctl allows to configure and introspect the state of the network links as seen by systemd-networkd. nmctl can be used to query and configure devices's for Address, Routes, Gateways, DNS, NTP, domain, hostname. nmctl also allows to create virtual NetDev (VLan, VXLan, Bridge, Bond) etc. It also allows to configure link's various configuration such as WakeOnLanPassword, Port, BitsPerSecond, Duplex and Advertise etc. nmctl uses sd-bus, sd-device APIs to interact with systemd, systemd-networkd, systemd-resolved, systemd-hostnamed, and systemd-timesyncd via dbus. nmctl uses networkd verbs to explain output. nmctl can generate configurations for required network links from YAML description. It also understands kernel command line specified in dracut's network configuration format and can generate systemd-networkd's configuration while the system boots and will persist between reboots.

Introspect system or network via nmctl
--------------------------------------
nmctl may be used to query or modify the state of the network links as seen by systemd-networkd. Please refer to systemd-networkd.service(8) for an introduction to the basic concepts, functionality, and configuration syntax.

Commands

The following commands are understood:

- ``status``

.. code-block::

  ❯ nmctl status
             Kernel: Linux (6.8.0-76060800daily20240311-generic)
    Systemd Version: 256~rc2-gfe816c2
       Architecture: x86-64
     Virtualization: vmware
   Operating System: Pop!_OS 22.04 LTS
    Hardware Vendor: VMware, Inc.
     Hardware Model: VMware Virtual Platform
   Firmware Version: 6.00
    Firmware Vendor: Phoenix Technologies LTD
      Firmware Date: Thu Nov 12 05:30:00 2020
            Boot ID: 35e5d01458ba4fcaa62e280a28010b56
         Machine ID: f0911fed670d14871b0f12cc66482080
       System State: routable
       Online State: online
      Address State: routable
 IPv4 Address State: routable
 IPv6 Address State: degraded
          Addresses: ::1/128                        on device lo
                     127.0.0.1/8                    on device lo
                     fe80::20c:29ff:fe6a:96a3/64    on device ens33
                     172.16.130.178/24              on device ens33
                     Gateway: 172.16.130.2                   on device ens33
                DNS: 172.16.130.2
       DNS Settings: MulticastDNS (yes) LLMNR (yes) DNSOverTLS (no) ResolvConfMode (stub) DNSSEC (allow-downgrade

-   ``status dev``

.. code-block::

   ❯ nmctl status ens33
                           Name: ens33
                          Index: 2
              Alternative names: enp2s1 enx000c296a96a3
                          Group: 0
                          Flags: up broadcast running multicast lowerup
                           Type: ether
                           Path: pci-0000:02:01.0
                     Parent Dev: 0000:02:01.0
                     Parent Bus: pci
                         Driver: e1000
                         Vendor: Intel Corporation
                          Model: 82545EM Gigabit Ethernet Controller (Copper) (PRO/1000 MT Single Port Adapter)
                      Link File: /usr/lib/systemd/network/99-default.link
                   Network File: /etc/systemd/network/ens33.network
                          State: routable (configured)
                  Address State: routable
             IPv4 Address State: routable
             IPv6 Address State: degraded
                   Online State: online
            Required for Online: yes
              Activation Policy: up
                     HW Address: 00:0c:29:6a:96:a3 (VMware, Inc.)
                            MTU: 1500 (min: 46 max: 16110)
                         Duplex: full
                          Speed: 1000
                          QDISC: fq_codel
                 Queues (Tx/Rx): 1/1
                Tx Queue Length: 1000
   IPv6 Address Generation Mode: eui64
                 GSO Max Size: 65536 GSO Max Segments: 65535
                 TSO Max Size: 65536 TSO Max Segments: 65535
                      Address: 172.16.130.178/24 (DHCPv4 via 172.16.130.254) lease time: 30min seconds T1: 15min seconds T2: 26min 15s seconds
                               fe80::20c:29ff:fe6a:96a3/64 (IPv6 Link Local)
                      Gateway: 172.16.130.2 (DHCPv4) via (172.16.130.254) (configuring,configured)
                          DNS: 172.16.130.2
            DHCP6 Client DUID: DUID-EN/Vendor:0000ab11d48ecc34dc43d9ff

- Display DNS mode. Allow to show how DNS servers are configured. Displays one of 'static', 'DHCP' or 'merged' (DHCP + static)

.. code-block::

   ❯ nmctl show-dns-mode dev ens33
        DNS Mode: merged

   ❯ nmctl show-dns-mode dev ens33 -j
        {
          "DNSMode": "merged"
        }

Configure Static Address and Gateway
------------------------------------
- The ``set-static`` command allows to configure static address and routes/gateway.

.. code-block::

  ❯ nmctl set-static dev [DEVICE] address|a|addr [ADDRESS] gw|gateway|g [GATEWAY ADDRESS] dns [SERVER1,SERVER2...] keep [BOOLEAN]

|
| Example

.. code-block::

  ❯ nmctl set-static dev eth0 a 192.168.10.51/24 gw 192.168.10.1

| Configure multiple address and gateways can be configured at once.

.. code-block::

  ❯ nmctl set-static dev eth0 a 192.168.10.51/24 a 192.168.10.52/24 a FE80::10 gw 192.168.10.1 gw FE80::1

| Configure address, gateway and static DNS

.. code-block:: bash

  ❯ nmctl set-static dev eth0 a 192.168.1.12/24 gw 192.168.1.1 dns 192.168.1.2,192.168.1.1

- The ``set-gw-family`` command allows to configure set IPv4 and IPv6 Gateway.

.. code-block:: bash

  ❯ set-gw-family dev [DEVICE] gw4 [IPv4 GATEWAY ADDRESS] gw6 [IPv6 GATEWAY ADDRESS]

|
| Example

.. code-block:: bash

  ❯ nmctl set-gw-family dev eth0 gw4 192.168.10.1 gw6 FE80::1

| Remove GW from device

- The ``remove-gw`` command allows to remove IPv4 and IPv6 Gateway.

.. code-block:: bash

  ❯ remove-gw dev [DEVICE] f|family [ipv4|ipv6|yes].

|
| Remove all GWs (IPv4/IPv6)

.. code-block:: bash

  ❯  nmctl remove-gw dev eth0

|
| Remove only GW of an explicit family i.e IPv4/IPv6

.. code-block:: bash

  ❯ nmctl remove-gw dev eth0 family ipv4

- The ``add-addr`` command allows to configure static address.

.. code-block:: bash

   ❯ add-addr dev [DEVICE] address|a|addr [ADDRESS] peer [ADDRESS]] label [STRING] pref-lifetime|pl [{forever|infinity|0}] scope {global|link|host|NUMBER}] dad [DAD {none|ipv4|ipv6|both}] prefix-route|pr [PREFIXROUTE BOOLEAN] prefix-route|pr [PREFIXROUTE BOOLEAN] many [ADDRESS1,ADDRESS2...]

- Add one address

.. code-block:: bash

  ❯ nmctl add-addr dev eth0 a 192.168.1.5

- The ``remove-addr`` command allows to remove static address.

.. code-block:: bash

   ❯ nmctl remove-addr dev eth0 a 192.168.1.5

- Add many addresses at once

.. code-block:: bash

  ❯ nmctl add-addr dev eth0 many 192.168.1.5/24,192.168.1.6/24,192.168.1.7/24,192.168.1.8/24

- Remove many addresses at once

.. code-block:: bash

  ❯ nmctl remove-addr dev eth0 many 192.168.1.5/24,192.168.1.6/24,192.168.1.7/24,192.168.1.8/24

- Remove many addresses at once by family

.. code-block:: bash

  ❯ nmctl remove-addr dev eth0 family ipv4

- Remove all addresses at once

.. code-block:: bash

  ❯ nmctl remove-addr dev eth0 family yes

- Replace address

   The `replace-addr` allows to replace address or addresses on a device. Takes one or many address and family ipv4, ipv6 or yes. The family specifies which family of address to be replaced with.

.. code-block:: bash

   replace-addr dev [DEVICE] address|a|addr [ADDRESS] many [ADDRESS1,ADDRESS2...] f|family [ipv4|ipv6|yes]

   Replace many address with specified family

.. code-block:: bash

   ❯ nmctl replace-addr dev eth0 many 192.168.1.7/24,192.168.1.8/24 family ipv4

.. code-block:: bash

  ❯ nmctl remove-addr dev eth0 family yes

- The ``set-gw`` command allows to configure static Gateway.

| Example:

.. code-block:: bash

   ❯ nmctl set-gw dev [DEVICE] gw [GATEWAY ADDRESS] onlink [ONLINK BOOLEAN]
   ❯ nmctl set-gw dev eth0 gw 192.168.1.1 onlink yes

- The ``remove-gw`` command allows to remove static gateway by family or all.

| Example:

.. code-block:: bash

   ❯ nmctl remove-gw dev [DEVICE] f|family [ipv4|ipv6|yes]
   ❯ nmctl remov-gw dev eth0 gw family ipv4

- Configure route

   The `add-route` allows to configure route on a device.

.. code-block:: bash

   add-route dev [DEVICE] gw [GATEWAY ADDRESS] dest [DESTINATION ADDRESS] src [SOURCE ADDRESS] pref-src [PREFFREDSOURCE ADDRESS] metric [METRIC NUMBER] scope [SCOPE {global|site|link|host|nowhere}] mtu [MTU NUMBER] table [TABLE {default|main|local|NUMBER}] proto [PROTOCOL {boot|static|ra|dhcp|NUMBER}] type [TYPE {unicast|local|broadcast|anycast|multicast|blackhole|unreachable|prohibit|throw|nat|resolve}] ipv6-pref [IPV6PREFERENCE {low|medium|high}] onlink [{ONLINK BOOLEN}]

   `gw` Takes the gateway address.

   `dest` The destination prefix of the route. Possibly followed by a slash and the prefix length. If omitted, a full-length host route is assumed.

   `src` The source prefix of the route. Possibly followed by a slash and the prefix length. If omitted, a full-length host route is assumed.

   `pref-src` The preferred source address of the route. The address must be in the format described in inet_pton(3).

   `metric` The metric of the route. Takes an unsigned integer in the range 0…4294967295. Defaults to unset, and the kernel's default will be used.

   `scope` The scope of the IPv4 route, which can be "global", "site", "link", "host", or "nowhere":

   "global" means the route can reach hosts more than one hop away.
   "site" means an interior route in the local autonomous system.
   "link" means the route can only reach hosts on the local network (one hop away).
   "host" means the route will not leave the local machine (used for internal addresses like 127.0.0.1).
   "nowhere" means the destination doesn't exist.

    `mtu` The maximum transmission unit in bytes to set for the route.

   `table` The table identifier for the route. Takes one of predefined names "default", "main", and "local", and names defined in RouteTable= in networkd.conf(5), or a number between 1 and 4294967295. The table can be retrieved using ip route show table num. If unset and Type= is "local", "broadcast", "anycast", or "nat", then "local" is used. In other cases, defaults to "main".

   `proto` The protocol identifier for the route. Takes a number between 0 and 255 or the special values "kernel", "boot", "static", "ra" and "dhcp". Defaults to "static".

    `type` Specifies the type for the route. Takes one of "unicast", "local", "broadcast", "anycast", "multicast", "blackhole", "unreachable", "prohibit", "throw", "nat", and "xresolve". If "unicast", a regular route is defined, i.e. a route indicating the path to take to a destination network address. If "blackhole", packets to the defined route are discarded silently. If "unreachable", packets to the defined route are discarded and the ICMP message "Host Unreachable" is generated. If "prohibit", packets to the defined route are discarded and the ICMP message "Communication Administratively Prohibited" is generated. If "throw", route lookup in the current routing table will fail and the route selection process will return to Routing Policy Database (RPDB). Defaults to "unicast".

    `onlink` Takes a boolean. If set to true, the kernel does not have to check if the gateway is reachable directly by the current machine (i.e., attached to the local network), so that we can insert the route in the kernel table without it being complained about. Defaults to "no".

    `ipv6-pref` Specifies the route preference as defined in RFC 4191 for Router Discovery messages. Which can be one of "low" the route has a lowest priority, "medium" the route has a default priority or "high" the route has a highest priority.

.. code-block:: bash

  ❯ nmctl add-route dev eth0 gw 192.168.1.1 dest 192.168.1.2 metric 111

- Remove route

   The `remove-route` allows to remove a route. Taken one of family ``ipv4/ipv6`` or ``yes`` .

.. code-block:: bash

  ❯ nmctl remove-route dev [DEVICE] f|family [ipv4|ipv6|yes]
  ❯ nmctl remove-route dev eth0 family yes

Configure Dynamic Address and Gateway
-------------------------------------
|

- ``nmctl`` provides ``set-dynamic`` command to configure dynamic address

.. code-block:: bash

  set-dynamic dev [DEVICE] dhcp [DHCP {BOOLEAN|ipv4|ipv6}] use-dns-ipv4 [BOOLEAN] use-dns-ipv6 [BOOLEAN] send-release-ipv4 [BOOLEAN] send-release-ipv6 [BOOLEAN] accept-ra [BOOLEAN]

- By default set-static creates a new .network file. To keep the previous configuration use "keep yes"

- DHCPv4 (IPv4 only)
  With nmctl ``set-dynamic`` we can configure DHCPv4 addresses.

.. code-block:: bash

  ❯ nmctl set-dynamic dev eth0 dhcp ipv4

.. code-block:: bash

  ❯ nmctl show-config dev eth0
  /etc/systemd/network/10-eth0.network

  [Match]
  Name=eth0

  [Network]
  LinkLocalAddressing=no # Disables IPv6
  IPv6AcceptRA=no
  DHCP=ipv4              # Enables DHCPv4 client

- DHCPv6 (IPv6 only)
- With nmctl set-dynamic we can configure DHCPv4 addresses.

.. code-block:: bash

  ❯ nmctl set-dynamic dev eth0 dhcp ipv6
  ❯ nmctl show-config dev eth0
  /etc/systemd/network/10-eth0.network

  [Match]
  Name=eth0

  [Network]
  LinkLocalAddressing=ipv6 # Enables IPv6 Link Local Address
  IPv6AcceptRA=yes         # Enables RA client
  DHCP=ipv6                # Enables IPv6 client

- Note: We need to enable ``LinkLocalAddressing=``, So that RA client and DHCPv6 client can talk to respective servers. RA ``IPv6AcceptRA=`` is requred to get the default route and It also indicates The 'M' and the 'O' bit. When M or O bit is on that implies the systemd-networkd should talk to DHCPv6 server to obtain the DHCPv6 address. See rfc4861 Section 4.2 M 1-bit "Managed address configuration" flag. When set, it indicates that addresses are available via Dynamic Host Configuration Protocol [DHCPv6]. If the M flag is set, the O flag is redundant and can be ignored because DHCPv6 will return all available configuration information. O 1-bit "Other configuration" flag. When set, it indicates that other configuration information is available via DHCPv6. Examples of such information are DNS-related information or information on other servers within the network.

- Configure DHCPv4 + DHCPv6

   With ``set-dynamic`` we can configure DHCPv4 and DHCPv6 addresses.

.. code-block:: bash

  ❯ nmctl set-dynamic dev eth0 dhcp yes
  ❯ nmctl show-config dev eth0
  /etc/systemd/network/10-eth0.network

  [Match]
  Name=eth0

  [Network]
  LinkLocalAddressing=ipv6 # Enables IPv6 Link Local Address
  IPv6AcceptRA=yes         # Enables RA client
  DHCP=yes                 # Enables IPv4 and IPv6 client


Configure Dynamic and Static Address and Gateway at once
--------------------------------------------------------

-  The ``set-network`` allows to configure both static and dynamic configuration. It is a combination of ``set-dynamic`` and ``set-static`` . Hence we can replace any command of ``set-dynamic`` or ``set-static`` with ``set-network``. We can call ``set-network`` as ``hybrid`` or ``mixed`` mode.

.. code-block:: bash

   ❯ set-network dev [DEVICE] dhcp [DHCP {BOOLEAN|ipv4|ipv6}] use-dns-ipv4 [BOOLEAN] use-dns-ipv6 [BOOLEAN] send-release-ipv4 [BOOLEAN] send-release-ipv6 [BOOLEAN] use-domains-ipv4 [BOOLEAN] use-domains-ipv6 [BOOLEAN] accept-ra [BOOLEAN] client-id-ipv4|dhcp4-client-id [DHCPv4 IDENTIFIER {mac|duid|duid-only}  iaid-ipv4|dhcpv4-iaid  [DHCPv4 IAID] iaid-ipv6|dhcp6-iaid [DHCPv6 IAID] address|a|addr [ADDRESS] gw|gateway|g [GATEWAY ADDRESS] dns [SERVER1,SERVER2...]
 keep [BOOLEAN] Configures dynamic and static configuration of the device.

- Note: By default ``set-static`` / ``set-dynamic`` / ``set-network`` creates a new .network file. To keep the previous configuration use "keep yes"

- Auto IPv6

configuring AUTOV6 for our VCSA and the vami command we would run is the following:

.. code-block:: bash

  ❯ nmctl set-network dev eth0 accept-ra yes

  ❯ sudo nmctl show-config eth0
  /etc/systemd/network/10-eth0.network

  [Match]
  Name=eth0

  [Network]
  LinkLocalAddressing=ipv6
  IPv6AcceptRA=yes


- Configure DHCPv4

- With ``set-dynamic`` we can configure DHCPv4 addresses.

.. code-block:: bash

  ❯ nmctl set-network dev eth0 dhcp ipv4
  ❯ nmctl show-config dev eth0
  /etc/systemd/network/10-eth0.network

  [Match]
  Name=eth0

  [Network]
  LinkLocalAddressing=no # Disables IPv6
  IPv6AcceptRA=no
  DHCP=ipv4              # Enables DHCPv4 client


- Configure DHCPv6 (IPv6 only)

.. code-block:: bash

  ❯ nmctl set-network dev eth0 dhcp ipv6
  ❯ nmctl show-config dev eth0
  /etc/systemd/network/10-eth0.network

  [Match]
  Name=eth0

  [Network]
  LinkLocalAddressing=ipv6 # Enables IPv6 Link Local Address
  IPv6AcceptRA=yes         # Enables RA client
  DHCP=ipv6                # Enables IPv6 client

- Configure DHCPv4 and DHCPv6 (IPv6 + IPv4)

.. code-block:: bash

  ❯ nmctl set-network dev eth0 dhcp yes
  ❯ nmctl show-config dev eth0
  /etc/systemd/network/10-eth0.network

  [Match]
  Name=eth0

  [Network]
  LinkLocalAddressing=ipv6 # Enables IPv6 Link Local Address
  IPv6AcceptRA=yes         # Enables RA client
  DHCP=yes                 # Enables IPv4 and IPv6 client

- Configure Static IPv4 Address and GW

.. code-block:: bash

   ❯ nmctl set-network dev eth0 a 192.168.10.51/24 gw 192.168.10.1
   ❯ nmctl show-config dev eth0
   /etc/systemd/network/10-eth0.network

   [Match]
   Name=eth0

   [Address]
   Address=192.168.10.51/24

   [Route]
   Gateway=192.168.10.1


- Configure Static IPv6 Address and GW

.. code-block:: bash

   ❯ nmctl set-network dev eth0 FE80::10 gw FE80::1

   ❯ nmctl show-config eth0
   /etc/systemd/network/10-eth0.network

   [Match]
   Name=eth0

   [Address]
   Address=FE80::10

   [Route]
   Gateway=FE80::1

- Configure Static IPv4 + Static IPv6

.. code-block:: bash

   ❯ nmctl set-network dev eth0 a 192.168.10.51/24 a 192.168.10.52/24 a FE80::10 gw 192.168.10.1 gw FE80::1

   ❯ nmctl show-config eth0
   /etc/systemd/network/10-eth0.network

   [Match]
   Name=eth0

   [Address]
   Address=192.168.10.51/24

   [Address]
   Address=192.168.10.52/24

   [Address]
   Address=FE80::10

   [Route]
   Gateway=192.168.10.1

   [Route]
   Gateway=FE80::1

- Configure DHCPv4 and Static v6

.. code-block:: bash

  ❯ nmctl set-network dev eth0 dhcp ipv4 a fe80::4 gw fe80::1

  ❯ nmctl show-config eth0
  /etc/systemd/network/10-eth0.network

  [Match]
  Name=eth0

  [Network]
  LinkLocalAddressing=ipv6
  IPv6AcceptRA=no
  DHCP=ipv4

  [Address]
  Address=fe80::4

  [Route]
  Gateway=fe80::1

- Configure Static v4 + DHCPv6

.. code-block:: bash

   ❯ nmctl set-network dev eth0 dhcp ipv6 a 192.168.1.41/24 gw 192.168.1.1

   ❯ nmctl show-config eth0
   /etc/systemd/network/10-eth0.network

   [Match]
   Name=eth0

   [Network]
   LinkLocalAddressing=ipv6
   IPv6AcceptRA=yes
   DHCP=ipv6

   [Address]
   Address=192.168.1.41/24

   [Route]
   Gateway=192.168.1.1

- Configure DHCPv4 and Auto v6

.. code-block:: bash

  ❯ nmctl set-network dev eth0 dhcp ipv4 accept-ra yes

  ❯ nmctl show-config eth0
  /etc/systemd/network/10-eth0.network

  [Match]
  Name=eth0

  [Network]
  LinkLocalAddressing=ipv6
  IPv6AcceptRA=yes
  DHCP=ipv4

- Configure Static v4 + Auto v6

.. code-block:: bash

   ❯ nmctl set-network dev eth0 accept-ra yes a 192.168.1.41/24 gw 192.168.1.1

   ❯ nmctl show-config eth0
   /etc/systemd/network/10-eth0.network

   [Match]
   Name=eth0

   [Network]
   LinkLocalAddressing=ipv6
   IPv6AcceptRA=yes

   [Address]
   Address=192.168.1.41/24

   [Route]
   Gateway=192.168.1.1

- Setup the MTU for device

   The `set-mtu` allows to set the device MTU.

.. code-block:: bash

   ❯ nmctl set-mtu dev eth0 mtu 1800

- Configure device MAC address

   The `set-mac` allows to set the device MAC address.

.. code-block:: bash

   ❯ nmctl set-mtu dev eth0 mac 00:0c:29:3a:bc:11

- Configure device the ARP (low-level Address Resolution Protocol)

   The `set-link-option` allows to set device ARP. Takes a boolean If set to true, the ARP (low-level Address Resolution Protocol) for this interface is enabled.

.. code-block:: bash

   ❯ nmctl set-link-option dev eth0 arp yes

- Configure device Multicast

   The `set-link-option` allows to set device multicast. Takes a boolean. If set to true, the multicast flag on the device is enabled

.. code-block:: bash

   ❯ nmctl set-link-option dev eth0 mc yes

- Configure device All Multicast

   The `set-link-option` allows to set device all multicast. Takes a boolean. If set to true, the all multicast flag on the device is enabled

.. code-block:: bash

   ❯ nmctl set-link-option dev eth0 amc yes

- Configure device Promiscuous

   The `set-link-option` allows to set device all Promiscuous. Takes a boolean. If set to true, promiscuous mode of the interface is enabled.

.. code-block:: bash

   ❯ nmctl set-link-option dev eth0 pcs yes

- Configure device group

   The `set-link-group` allows to set device group. Link groups are similar to port ranges found in managed switches. When network interfaces are added to a numbered group, operations on all the interfaces from that group can be performed at once. Takes an unsigned integer in the range 0…2147483647

.. code-block:: bash

   ❯ nmctl set-link-group dev eth0 group 2147483647

- Configure device required family for online

  Takes an address family. When specified, an IP address in the given family is deemed required when determining whether the link is online (including when running systemd-networkd-wait-online). Takes one of "ipv4", "ipv6", "both", or "any". Defaults to "any". Note that this option has no effect if "RequiredForOnline=no", or if "RequiredForOnline=" specifies a minimum operational state below "degraded".

.. code-block:: bash

   ❯ nmctl set-link-rfo dev eth0 f ipv4

- Configure DHCPv4 and/or DHCPv6 client

   The `set-dhcp` enables DHCPv4 and/or DHCPv6 client support. Accepts "yes", "no", "ipv4", or "ipv6". Defaults to "no". With `set-dhcp` ``use-dns-ipv4``, ``use-dns-ipv6``, ``use-domains-ipv4``, ``use-domains-ipv6``, ``send-release-ipv4`` and ``send-release-ipv6`` can also be applied.

.. code-block:: bash

   ❯ nmctl set-dhcp dev eth0 dhcp ipv4

- Configure DHCPv4 client identifier.

   The `set-dhcp4-cid` allows to set DHCPv4 client identifier. Takes one of mac or duid. If set to mac, the MAC address of the link is used. If set to duid, an RFC4361-compliant Client ID, which is the combination of IAID and DUID, is used. IAID can be configured by IAID=. DUID can be configured by DUIDType= and DUIDRawData=. Defaults to duid.

.. code-block:: bash

   ❯ nmctl set-dhcp dev eth0 id mac

- Configure DHCP Identity Association Identifier (IAID).

   The `set-dhcp-iaid` allows to set DHCP (IPv4 and / or IPv6) client Identity Association Identifier (IAID) for the interface, a 32-bit unsigned integer.

.. code-block:: bash

   ❯ nmctl set-dhcp dev eth0 f 6 iaid 0xb6220feb
   ❯ nmctl set-dhcp dev eth0 f 4 iaid 0xb6220f12

- Configure DHCP unique identifier (DUID)

  The `set-dhcp-duid` allow to set DHCP unique identifier (DUID).

``set-dhcp-duid dev|system [DEVICE] family|f [ipv4|ipv6|4|6] type [DUIDType {link-layer-time|vendor|link-layer|uuid|0…65535}] data [RAWDATA]``

  `family` Takes one of ipv4 or ipv6.
  `type` Takes one of link-layer-time, vendor, link-layer, uuid, 0…65535.
  `data` Takes raw data.

 .. code-block:: bash

   ❯ nmctl set-dhcp-duid dev eth0 f 6 type vendor data 00:00:ab:11:f9:2a:c2:77:29:f9:5c:00

- Configure link-local address autoconfiguration.

  The `set-lla` Controls link-local address autoconfiguration. Takes a boolean or `ipv4/ipv6`

.. code-block:: bash

   ❯ nmctl set-lla dev eth0 ipv6

- Configure Link Layer Discovery Protocol (LLDP).

  The `set-lldp` Controls support for Ethernet LLDP packet reception and LLDP packet emission.

.. code-block:: bash

   ❯ nmctl set-lldp dev eth0 receive yes emit yes


- Configures Link Local Multicast Name Resolution (LLMNR).

  The `set-llmnr` allow to configure Link Local Multicast Name Resolution (LLMNR). Takes a boolean or "resolve". When true, enables Link-Local Multicast Name Resolution on the link. When set to "resolve", only resolution is enabled, but not host registration and announcement. Defaults to true. This setting is read by systemd-resolved.service(8).

.. code-block:: bash

   ❯ nmctl set-llmnr dev eth0 yes

Generate network config from YAML file
----------------------------------------

- `nmctl` can generate configurations for required network links from YAML description. Configuration written to disk under `/etc/systemd/network` will persist between reboots. When `network-config-manager-yaml-generator.service` is enabled it reads yaml files from `/etc/network-config-manager/yaml` and generates systemd-networkd configuration files. `nmctl apply` and `nmctl apply-file` can be used to generate configuration from yml file.

- `nmctl` uses similar format as defined by [different YAML format](https://curtin.readthedocs.io/en/latest/topics/networking.html).

- Using DHCP

To set the device named ``eth1`` get an address via DHCP4 create a YAML file with the following:

.. code-block:: yml

   network:
     ethernets:
       eth1:
         dhcp4: true

- Configuring static address and routes

   To set static IP address, use the addresses key, which takes a list of (IPv4 or IPv6), addresses along with the subnet prefix length (e.g. /24). Gateway and DNS information can be provided as well:

.. code-block:: yml

  network:
    ethernets:
      eth0:
        addresses:
          - 10.10.10.2/24
          - 10.10.10.3/24
          - 10.10.10.4/24
          - 10.10.10.5/24
        nameservers:
          search: [mydomain, otherdomain]
        addresses: [10.10.10.1, 1.1.1.1]
        routes:
          - to: 192.168.1.1
           via: 10.10.10.1

   Directly connected gateway

.. code-block:: yml

   network:
     ethernets:
       ens3:
          addresses: [ "10.10.10.1/24" ]
          routes:
            - to: 0.0.0.0/0
              via: 9.9.9.9
              on-link: true

  Multiple addresses on a single device

.. code-block:: yml

 network:
   ethernets:
     ens3:
       addresses:
           - 10.100.1.37/24
           - 10.100.1.38/24:
               label: ens3:0
               lifetime: 1000
           - 10.100.1.39/24:
               label: ens3:test-label
               lifetime: 2000
       routes:
           - to: default
             via: 10.100.1.1

 Using DHCP4 and DHCP6 overrides

.. code-block:: yml

 network:
   ethernets:
     eth0:
       dhcp4: yes
       dhcp6: yes
       dhcp4-overrides:
         route-metric: 200
         send-release: no
         use-gateway: true
         use-hostname: no
         send-hostname: yes
         use-mtu: yes
         iaid: 0xb6220feb
         initial-congestion-window: 20
         initial-advertised-receive-window: 20
     eth1:
       dhcp4: yes
       dhcp4-overrides:
         route-metric: 300
         iaid: 0xb6220feb
         initial-congestion-window: 20
         initial-advertised-receive-window: 20
       dhcp6-overrides:
         use-dns: true
         use-domain: true
         use-address: true
         use-hostname: true
         use-ntp: true
         rapid-commit: false
         send-release: no
         iaid: 0xb6220feb
         without-ra: solicit

 Using IPv6 Router Advertisement (RA)

.. code-block:: yml

   network:
    ethernets:
      eth0:
        dhcp4: yes
        dhcp6: yes
        accept-ra: yes
        link-local: ipv6
        ra-overrides:
          token: eui64
          use-dns: true
          use-domain: true
          use-mtu: true
          use-gateway: true
          use-route-prefix: true
          use-autonomous-prefix: true
          use-on-link-prefix: true

 Using match as MacAddress

.. code-block:: yml

 network:
   ethernets:
       eth0:
           match:
               macaddress: "de:ad:be:ef:ca:fe"
           addresses: [ "10.3.0.5/23" ]
           nameservers:
               addresses: [ "8.8.8.8", "8.8.4.4" ]
               search: [ example.com ]
           routes:
               - to: default
                 via: 10.3.0.1

 Configure Routing Policy Rule

.. code-block:: yml

 network:
   ethernets:
     eth1:
       addresses:
           - 10.100.1.5/24
       routes:
           - to: default
             via: 10.100.1.1
       routing-policy:
             - from: 10.100.1.5/24
               to: 10.100.1.5/24
               table: 101

 Configure SR-IOV Virtual Functions

.. code-block:: yml

   network:
    ethernets:
      eni99np1:
       addresses:
           - 10.100.1.5/24
       routes:
           - to: default
             via: 10.100.1.1
       sriovs:
             - virtual-function: 0
               vlan-id: 1
               quality-of-service: 101
               vlan-protocol: 802.1Q
               link-state: yes
               macaddress: 00:11:22:33:44:55
             - virtual-function: 1
               vlan-id: 2
               quality-of-service: 102
               vlan-protocol: 802.1Q
               link-state: yes
               macaddress: 00:11:22:33:44:56

 DHCP4 Server

.. code-block:: yml

   network:
    version: 2
    renderer: networkd
      ethernets:
       ens33:
          dhcp4: no
          accept-ra: no
          addresses:
            - 10.100.1.1/24
          enable-dhcp4-server: yes
          dhcp4-server:
              pool-offset: 0
              pool-size: 200
              emit-dns: yes
              dns: 8.8.8.8
              static-leases:
                - address: 10.100.1.2/24
                  macaddress: 00:0c:29:5f:d1:41
                - address: 10.100.1.3/24
                  macaddress: 00:0c:29:5f:d1:42
                - address: 10.100.1.4/24
                  macaddress: 00:0c:29:5f:d1:43

 Generate link config from yml file

 `nmctl` can generate link configuration from YAML description.

.. code-block:: yml

   network:
    ethernets:
      eth1:
       receive-checksum-offload: true
       transmit-checksum-offload: true
       tcp-segmentation-offload: true
       tcp6-segmentation-offload: true
       generic-segmentation-offload: true
       generic-receive-offload: true
       large-receive-offload: true
       ifname: test99
       alias: ifalias
       description: testconf
       mtu: 1600
       bitspersecond: 5G
       duplex: full
       wakeonlan: phy unicast broadcast multicast arp magic secureon
       wakeonlan-password: cb:a9:87:65:43:21
       port: mii
       advertise: 10baset-half 10baset-full 100baset-half 100baset-full 1000baset-half 1000baset-full 10000baset-full 2500basex-full 1000basekx-full 10000basekx4-full 10000basekr-full 10000baser-fec 20000basemld2-full 20000basekr2-full
       auto-negotiation: no
       receive-vlan-ctag-hardware-acceleration: yes
       transmit-vlan-ctag-hardware-acceleration: no
       receive-vlan-ctag-filter: no
       transmit-vlan-stag-hardware-acceleration: yes
       ntuple-filter: no
       use-adaptive-rx-coalesce: yes
       use-adaptive-tx-coalesce: yes
       macaddress-policy: none
       macaddress: 00:0c:29:3a:bc:11
       namepolicy: kernel database onboard slot path mac keep
       name: dm1
       alternative-names-policy: database onboard slot path mac
       alternative-name: demo1
       rx-buffer-size: max
       rx-mini-buffer-size: 65335
       rx-jumbo-buffer-size: 88776555
       tx-buffer-size: max
       transmit-queues: 4096
       receive-queues: 4096
       transmit-queue-length: 1024
       tx-flow-control: no
       rx-flow-control: yes
       auto-negotiation-flow-control: yes
       generic-segment-offload-maxbytes: 65535
       generic-segment-offload-max-segments: 1024
       rx-channels: max
       tx-channels: 656756677
       other-channels: 429496729

- Generate VLAN configuration

 Configure VLan with id 10 and set it's master device to `ens33` .

.. code-block:: yml

 network:
  ethernets:
     ens33:
          addresses: [ "192.168.10.2/23" ]
          nameservers:
              addresses: [ "8.8.8.8", "8.8.4.4" ]
              search: [ example.com ]
          routes:
              - to: default
                via: 192.168.1.1
  vlans:
      vlan10:
          id: 10
          link: ens33
          addresses: [ "192.168.10.5/24" ]
          nameservers:
              addresses: [ "8.8.8.8" ]
              search: [ domain1.example.com, domain2.example.com ]

- Generate Bond configuration

 Configure bond `bond0` with mode `active-backup`  and set slave devices to `ens33` and `ens37`.

.. code-block:: yml

   network:
     bonds:
       bond0:
          dhcp4: yes
          interfaces:
              - ens33
              - ens37
          parameters:
              mode: active-backup

- Generate Bridge configuration

  Configure bridge `bridge0` and set slave master devices to `ens33` with IPv4 DHCP network.

.. code-block:: yml

 network:
  renderer: networkd
  ethernets:
      ens33:
          dhcp4: no
  bridges:
      br0:
          dhcp4: yes
          interfaces:
              - ens33

- Generate Tunnel configuration

  Configure IPv6 tunnel sit `he-ipv6` with address and routes.

.. code-block:: yml

 network:
  ethernets:
      eth0:
          addresses:
              - 1.1.1.1/24
              - "2001:cafe:face::1/64"
          routes:
              - to: default
                via: 1.1.1.254
  tunnels:
      he-ipv6:
          mode: sit
          remote: 2.2.2.2
          local: 1.1.1.1
          addresses:
              - "2001:dead:beef::2/64"
          routes:
              - to: default
                via: "2001:dead:beef::1"

- Generate VRF configuration

 Configure vrf `vrf1005` with table `1005` and interface `ens33` and `ens37`

.. code-block:: yml

 network:
  ethernets:
    ens33:
    dhcp4: true
  vrfs:
    vrf1005:
      table: 1005
      interfaces:
        - ens33
        - ens37
      routes:
      - to: default
        via: 1.2.3.4
      routing-policy:
      - from: 2.3.4.5

- Generate VXLan configuration

  Configure VXLan `vxlan1` id 1 on interface `ens33`

.. code-block:: yml

 network:
   ethernets:
     ens33:
       routes:
         - to: 10.20.30.40/32
           via: 10.20.30.1
   tunnels:
     vxlan1:
       mode: vxlan
       id: 1
       link: ens33
       local: 192.168.1.34
       remote: 192.168.1.35

- Generate WireGuard configuration

 Configure WireGuard `wg1`

.. code-block:: yml

   network:
    tunnels:
      wg1:
       mode: wireguard
       key: /etc/wireguard/laptop-private.key
       port: 51000
       addresses: [10.10.11.2/24]
       peers:
         - keys:
           public: syR+psKigVdJ+PZvpEkacU5niqg9WGYxepDZT/zLGj8=
           endpoint: 10.48.132.39:51000
           allowed-ips: [10.10.11.0/24, 10.10.10.0/24]

 - Generate network config from kernel command line

 `nmctl` understands kernel command line specified in [dracut's](https://mirrors.edge.kernel.org/pub/linux/utils/boot/dracut/dracut.html#dracutkernel7) network configuration format and can generate [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd-networkd.service.html)'s configuration while the system boots and will persist between reboots.

.. code-block:: yml

 Network
       ip={dhcp|on|any|dhcp6|auto6}
           dhcp|on|any: get ip from dhcp server from all devices. If root=dhcp, loop
           sequentially through all devices (eth0, eth1, ...) and use the first with a valid
           DHCP root-path.

           auto6: IPv6 autoconfiguration

           dhcp6: IPv6 DHCP

       ip=<device>:{dhcp|on|any|dhcp6|auto6}
           dhcp|on|any|dhcp6: get ip from dhcp server on a specific device

           auto6: do IPv6 autoconfiguration

           This parameter can be specified multiple times.

       ip=<client-IP>:[ <server-id>]:<gateway-IP>:<netmask>:<client_hostname>:<device>:{none|off}
           explicit network configuration.

       ifname=<device>:<MAC>
           Assign network device name <device> (ie eth0) to the NIC with MAC <MAC>. Note
           letters in the MAC-address must be lowercase!  Note: If you use this option you must
           specify an ifname= argument for all devices used in ip= or fcoe= arguments.  This
           parameter can be specified multiple times.

       nameserver=<IP>[nameserver=<IP> ...]
           specify nameserver(s) to use

- Generate network config from kernel command line

`nmctl` understands kernel command line specified in [dracut's](https://mirrors.edge.kernel.org/pub/linux/utils/boot/dracut/dracut.html#dracutkernel7) network configuration format and can generate [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd-networkd.service.html)'s configuration while the system boots and will persist between reboots.

.. code-block:: bash

 Network
       ip={dhcp|on|any|dhcp6|auto6}
           dhcp|on|any: get ip from dhcp server from all devices. If root=dhcp, loop
           sequentially through all devices (eth0, eth1, ...) and use the first with a valid
           DHCP root-path.

           auto6: IPv6 autoconfiguration

           dhcp6: IPv6 DHCP

       ip=<device>:{dhcp|on|any|dhcp6|auto6}
           dhcp|on|any|dhcp6: get ip from dhcp server on a specific device

           auto6: do IPv6 autoconfiguration

           This parameter can be specified multiple times.

       ip=<client-IP>:[ <server-id>]:<gateway-IP>:<netmask>:<client_hostname>:<device>:{none|off}
           explicit network configuration.

       ifname=<device>:<MAC>
           Assign network device name <device> (ie eth0) to the NIC with MAC <MAC>. Note
           letters in the MAC-address must be lowercase!  Note: If you use this option you must
           specify an ifname= argument for all devices used in ip= or fcoe= arguments.  This
           parameter can be specified multiple times.

       nameserver=<IP>[nameserver=<IP> ...]
           specify nameserver(s) to use

.. code-block:: bash

  ➜  ~ cat /proc/cmdline
      BOOT_IMAGE=/boot/vmlinuz-6.8.0-76060800daily20240311-generic root=UUID=1c01f709-ae8a-4947-88e9-3973f4c0833a ro quiet splash ip=dhcp

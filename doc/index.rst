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

  ❯ nmctl set-static dev [DEVICE] address|a|addr [ADDRESS] gw|gateway|g [GATEWAY ADDRESS] dns [SERVER1,SERVER2...] keep [BOOLEAN] Configures static configuration of the device
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

  ❯ set-gw-family dev [DEVICE] gw4 [IPv4 GATEWAY ADDRESS] gw6 [IPv6 GATEWAY ADDRESS] Configures device default IPv4/IPv6 Gateway.

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

   ❯ add-addr dev [DEVICE] address|a|addr [ADDRESS] peer [ADDRESS]] label [STRING] pref-lifetime|pl [{forever|infinity|0}] scope {global|link|host|NUMBER}] dad [DAD {none|ipv4|ipv6|both}] prefix-route|pr [PREFIXROUTE BOOLEAN] prefix-route|pr [PREFIXROUTE BOOLEAN] many [ADDRESS1,ADDRESS2...] Configures device Address.

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

- The ``set-gw`` command allows to configure static Gateway.

| Example:

.. code-block:: bash

   ❯ nmctl set-gw dev [DEVICE] gw [GATEWAY ADDRESS] onlink [ONLINK BOOLEAN] Configures device default Gateway.
   ❯ nmctl set-gw dev eth0 gw 192.168.1.1 onlink yes

Configure Dynamic Address and Gateway
-------------------------------------
|

- ``nmctl`` provides set-dynamic command to configure dynamic address

.. code-block:: bash

  set-dynamic  dev [DEVICE] dhcp [DHCP {BOOLEAN|ipv4|ipv6}] use-dns-ipv4 [BOOLEAN] use-dns-ipv6 [BOOLEAN] send-release-ipv4 [BOOLEAN] send-release-ipv6 [BOOLEAN]accept-ra [BOOLEAN] Configures dynamic configration of the device (IPv4|IPv6|RA).

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

- Note: We need to enable LinkLocalAddressing=, So that RA client and DHCPv6 client can talk to respective servers. RA IPv6AcceptRA= is requred to get the default route and It also indicates The 'M' and the 'O' bit. When M or O bit is on that implies the systemd-networkd should talk to DHCPv6 server to obtain the DHCPv6 address. See rfc4861 Section 4.2 M 1-bit "Managed address configuration" flag. When set, it indicates that addresses are available via Dynamic Host Configuration Protocol [DHCPv6]. If the M flag is set, the O flag is redundant and can be ignored because DHCPv6 will return all available configuration information. O 1-bit "Other configuration" flag. When set, it indicates that other configuration information is available via DHCPv6. Examples of such information are DNS-related information or information on other servers within the network.

- Configure DHCPv4 + DHCPv6

   With ``nmctl set-dynamic`` we can configure DHCPv4 and DHCPv6 addresses.

.. code-block:: bash

  ❯ nmctl set-dynamic dev eth0 dhcp yes
  ❯ nmctl show-config dev eth0
  /etc/systemd/network/10-eth0.network

  [Match]
  Name=eth0

  [Network``
  LinkLocalAddressing=ipv6 # Enables IPv6 Link Local Address
  IPv6AcceptRA=yes         # Enables RA client
  DHCP=yes                 # Enables IPv4 and IPv6 client


Configure Dynamic and Static Address and Gateway at once
--------------------------------------------------------
|

-  The ``set-network`` allows to configure both static and dynamic configuration. It is a combination of ``set-dynamic`` and ``set-static`` . Hence we can replace any command of ``set-dynamic`` or ``set-static`` with ``set-network``. We can call ``set-network`` as ``hybrid`` or ``mixed`` mode.

.. code-block:: bash

   ❯ set-network dev [DEVICE] dhcp [DHCP {BOOLEAN|ipv4|ipv6}] use-dns-ipv4 [BOOLEAN] use-dns-ipv6 [BOOLEAN] send-release-ipv4 [BOOLEAN] send-release-ipv6 [BOOLEAN] use-domains-ipv4 [BOOLEAN] use-domains-ipv6 [BOOLEAN] accept-ra [BOOLEAN] client-id-ipv4|dhcp4-client-id [DHCPv4 IDENTIFIER {mac|duid|duid-only}  iaid-ipv4|dhcpv4-iaid  [DHCPv4 IAID] iaid-ipv6|dhcp6-iaid [DHCPv6 IAID] address|a|addr [ADDRESS] gw|gateway|g [GATEWAY ADDRESS] dns [SERVER1,SERVER2...]
 keep [BOOLEAN] Configures dynamic and static configuration of the device.

- Note: By default set-static / set-dynamic / set-network creates a new .network file. To keep the previous configuration use "keep yes"

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

- With ``nmctl set-dynamic`` we can configure DHCPv4 addresses.

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

Generate network config from YAML file
----------------------------------------

- `nmctl` can generate configurations for required network links from YAML description. Configuration written to disk under `/etc/systemd/network` will persist between reboots. When `network-config-manager-yaml-generator.service` is enabled it reads yaml files from `/etc/network-config-manager/yaml` and generates systemd-networkd configuration files. `nmctl apply` and `nmctl apply-file` can be used to generate configuration from yml file.

- `nmctl` uses similar format as defined by [different YAML format](https://curtin.readthedocs.io/en/latest/topics/networking.html).

- Using DHCP

To set the device named `eth1` get an address via DHCP4 create a YAML file with the following:

.. code-block:: yml

   network:
     ethernets:
       eth1:
         dhcp4: true

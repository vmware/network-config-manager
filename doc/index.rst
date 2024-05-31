:orphan:

network-config-manager manual page
====================================

Description
-----------
The network-config-manager nmctl allows to configure and introspect the state of the network links as seen by systemd-networkd. nmctl can be used to query and configure devices's for Address, Routes, Gateways, DNS, NTP, domain, hostname. nmctl also allows to create virtual NetDev (VLan, VXLan, Bridge, Bond) etc. It also allows to configure link's various configuration such as WakeOnLanPassword, Port, BitsPerSecond, Duplex and Advertise etc. nmctl uses sd-bus, sd-device APIs to interact with systemd, systemd-networkd, systemd-resolved, systemd-hostnamed, and systemd-timesyncd via dbus. nmctl uses networkd verbs to explain output. nmctl can generate configurations for required network links from YAML description. It also understands kernel command line specified in dracut's network configuration format and can generate systemd-networkd's configuration while the system boots and will persist between reboots.

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

- Note: We need to enable LinkLocalAddressing=, So that RA client and DHCPv6 client can talk to respective servers. RA IPv6AcceptRA= is requred to get the default route and It also indicates The 'M' and the 'O' bit. When M or O bit is on that implies the systemd-networkd should talk to DHCPv6 server to obtain the DHCPv6 address.
See rfc4861 Section 4.2
M 1-bit "Managed address configuration" flag. When set, it indicates that addresses are available via Dynamic Host Configuration Protocol [DHCPv6]. If the M flag is set, the O flag is redundant and can be ignored because DHCPv6 will return all available configuration information.
O 1-bit "Other configuration" flag. When set, it indicates that other configuration information is available via DHCPv6. Examples of such information are DNS-related information or information on other servers within the network.

- DHCPv4 + DHCPv6 (IPv6 + IPv4)
- With nmctl set-dynamic we can configure DHCPv4 and DHCPv6 addresses.

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

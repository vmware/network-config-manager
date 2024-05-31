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

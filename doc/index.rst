:orphan:

network-config-manager manual page
====================================

Description
-----------
The network-config-manager nmctl allows to configure and introspect the state of the network links as seen by systemd-networkd. nmctl can be used to query and configure devices's for Address, Routes, Gateways, DNS, NTP, domain, hostname. nmctl also allows to create virtual NetDev (VLan, VXLan, Bridge, Bond) etc. It also allows to configure link's various configuration such as WakeOnLanPassword, Port, BitsPerSecond, Duplex and Advertise etc. nmctl uses sd-bus, sd-device APIs to interact with systemd, systemd-networkd, systemd-resolved, systemd-hostnamed, and systemd-timesyncd via dbus. nmctl uses networkd verbs to explain output. nmctl can generate configurations for required network links from YAML description. It also understands kernel command line specified in dracut's network configuration format and can generate systemd-networkd's configuration while the system boots and will persist between reboots.

Configure Static Address and Gateway
------------------------------------
The ``set-static`` command allows to configure static address and routes/gateway.

.. code-block::

  ❯ nmctl set-static dev [DEVICE] address|a|addr [ADDRESS] gw|gateway|g [GATEWAY ADDRESS] dns [SERVER1,SERVER2...] keep [BOOLEAN] Configures static configuration of the device

- Example

.. code-block::

  ❯ nmctl set-static dev eth0 a 192.168.10.51/24 gw 192.168.10.1

- Configure multiple address and gateways can be configured at once.

.. code-block::

  ❯ nmctl set-static dev eth0 a 192.168.10.51/24 a 192.168.10.52/24 a FE80::10 gw 192.168.10.1 gw FE80::1

- Configure address, gateway and static DNS

.. code-block:: bash

  ❯ nmctl set-static dev eth0 a 192.168.1.12/24 gw 192.168.1.1 dns 192.168.1.2,192.168.1.1

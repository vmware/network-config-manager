# network-config-manager
[![network config manager CI](https://github.com/vmware/network-config-manager/actions/workflows/network-config-manager.yml/badge.svg?branch=main)](https://github.com/vmware/network-config-manager/actions/workflows/network-config-manager.yml)

### What is nmctl

The network-config-manager `nmctl` allows to configure and introspect the state of the network links as seen by [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd-networkd.service.html). nmctl can be used to query and configure devices's for Address, Routes, Gateways, DNS,  NTP,  domain, hostname. nmctl also allows to create virtual NetDev (VLan, VXLan, Bridge, Bond) etc. It also allows to configure link's various configuration such as WakeOnLanPassword, Port, BitsPerSecond, Duplex and Advertise etc. nmctl uses [sd-bus](http://0pointer.net/blog/the-new-sd-bus-api-of-systemd.html), [sd-device](https://www.freedesktop.org/software/systemd/man/sd-device.html) APIs to interact with [systemd](https://www.freedesktop.org/wiki/Software/systemd), [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd-networkd.service.html), [systemd-resolved](https://www.freedesktop.org/software/systemd/man/systemd-resolved.service.html), [systemd-hostnamed](https://www.freedesktop.org/software/systemd/man/systemd-hostnamed.service.html), and [systemd-timesyncd](https://www.freedesktop.org/software/systemd/man/systemd-timesyncd.service.html) via dbus. nmctl uses networkd verbs to explain output. nmctl can generate configurations for required network links from YAML description. It also understands kernel command line specified in [dracut](http://man7.org/linux/man-pages/man7/dracut.cmdline.7.html)'s network configuration format and can generate systemd-networkd's configuration while the system boots and will persist between reboots.

### Features

Configure
  - Static IPv4 and IPv6 Address, Routes, Gateway.
  - DHCPv4/DHCPv6 Client (DHCP4 Client Identifier, UseMTU/UseDNS/UseDomains/UseNTP/UseRoutes).
  - LLDP, Link Local Addressing, IPv4LLRoute, LLMNR.
  - Per Link and global DNS, Domains
  - NTP
  - Routing Policy Rule
  - Multiple default gateway with routing policy rules.
  - Link's MAC, MTU, ARP, Multicast, AllMulticast, Promiscuous, Unmanaged, Group, RequiredForOnline, RequiredFamilyForOnline, and ActivationPolicy.
  - Create netdevs, vlan, vxlan, bridge, bond, veth, macvlan/macvtap, ipvlap/ipvtap, veth, tunnels(ipip, sit, gre, sit, vti), wireguard.
  - Hostname.
  - DHCPv4 Server.
  - DHCPv4 Server Static Lease.
  - IPv6 Router Advertisements.
  - Network and Link SRIOV
  - Add delete and view nftables table, chains and rules.
  - Edit network / link configuration via vim/vi.

  Please see [systemd.network](https://www.freedesktop.org/software/systemd/man/systemd.network.html) for more information.

  Device's
  - Alias, Description, MTUBytes, WakeOnLan, WakeOnLanPassword, Port, BitsPerSecond, Duplex and Advertise.
  - Offload parameters and other features.
  - MACAddressPolicy or MACAddress.
  - NamePolicy or Name.
  - AlternativeNamesPolicy or AlternativeName.
  - Pending packets receive buffer.
  - Queue size.
  - Flow control.
  - GSO.
  - Channels.
  - Coalesce.
  - Coalesced frames.
  - Coalesce packet rate.

Please see [systemd.link](https://www.freedesktop.org/software/systemd/man/systemd.link.html) for more information.

 Allow to generates systemd-networkd's configuration
 - Flexible [netplan](https://netplan.readthedocs.io/en/stable/) like network configuration from [YML](https://yaml.org) file.
 - [Dracut](https://mirrors.edge.kernel.org/pub/linux/utils/boot/dracut/dracut.html#dracutkernel7) kernel command line network config.

Introspect
 - Links.
 - DNS and Domains.
 - Hostname.
 - nftable
 - Allows to export in JSON format.

### Building from source.

```bash
➜  ~ meson build
➜  ~ ninja -C build
➜  ~ sudo ninja -C build install
```

Or by simply doing
```
❯ make
❯ sudo make install
```

### Building in photon OS.

```bash
❯ git clone git@github.com:vmware/network-config-manager.git
❯ cd network-config-manager
❯ wget https://raw.githubusercontent.com/vmware/photon/master/SPECS/network-config-manager/network-config-manager.spec
❯ sudo rpmspec -q --srpm --requires network-config-manager.spec | sudo xargs -d '\n' tdnf -y install
❯ make
❯ sudo make install

```
### Use cases

```bash
➜  ~ nmctl --help
```

- For a comprehensive list of YAML examples, see [YAML example configurations](https://github.com/vmware/network-config-manager/blob/main/example-yaml-configurations.md)
- Introspect system or network via ```nmctl```  [nmctl display](https://github.com/vmware/network-config-manager/blob/main/example-nmctl-display.md)

### Howto get started with nmctl
- [Configure static address and route GW](https://www.linkedin.com/pulse/configure-static-address-route-gw-susant-sahani-dljdf)
- [Configure dynamic address and routes (DHCPv4/DHCPv6/RA)](https://www.linkedin.com/pulse/configure-dynamic-addrss-routes-dhcpv4dhcpv6ra-susant-sahani-krz5f)
- [How to Configure Networking on Photon OS](https://www.linkedin.com/pulse/how-configure-networking-photon-os-network-config-manager-sahani)
- [Generate systemd-networkd's configuration from yaml](https://www.linkedin.com/pulse/generate-systemd-networkds-configuration-from-yml-file-susant-sahani)
- [VCSA Photon OS Network Configurations via network-config-manager](https://www.linkedin.com/pulse/vcsa-network-configurations-via-nmctl-susant-sahani-5xh8f)
- [Configure ipv6 address via network-config-manager](https://www.linkedin.com/pulse/photon-os-ipv6-network-configuration-via-nitesh-kumar-xvgac)
- [Configure ipv4 address via network-config-manager](https://www.linkedin.com/pulse/photon-os-ipv4-network-configuration-via-nitesh-kumar-ejemc)
- [Configure DNSMode via network-config-manager](https://www.linkedin.com/pulse/configure-dnsmode-using-network-config-manager-nitesh-kumar-di3kf)

### Contributing

The network-config-manager project team welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).

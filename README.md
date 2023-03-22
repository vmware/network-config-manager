# network-config-manager

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

Generates networkd unit configs from
 - [YML](https://yaml.org) file.
 - [Dracut](https://mirrors.edge.kernel.org/pub/linux/utils/boot/dracut/dracut.html#dracutkernel7) kernel command line network config.

Introspect
 - Links.
 - DNS and Domains.
 - Hostname.
 - nftable
 - Supports JSON format.

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

### Use cases

```bash
➜  ~ nmctl --help
```
### Generate network config from yml file:

`nmctl` can generate configurations for required network links from YAML description. Configuration written to disk under `/etc/systemd/network` will persist between reboots. When `network-config-manager-yaml-generator.service` is enabled it reads yaml files from `/etc/network-config-manager/yaml` and generates systemd-networkd configuration files. `nmctl apply` and `nmctl apply-file` can be used to generate configuration from yml file.

`nmctl` uses similar format as defined by [different YAML format](https://curtin.readthedocs.io/en/latest/topics/networking.html).

#### Using DHCP:

To set the device named `eth1` get an address via DHCP4 create a YAML file with the following:

```yml
 network:
  ethernets:
    eth1:
      dhcp4: true
 ```

#### Static configuration
To set a static IP address, use the addresses key, which takes a list of (IPv4 or IPv6), addresses along with the subnet prefix length (e.g. /24). Gateway and DNS information can be provided as well:

```yml
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
```

#### Directly connected gateway
```yml
 network:
  ethernets:
      ens3:
          addresses: [ "10.10.10.1/24" ]
          routes:
            - to: 0.0.0.0/0
              via: 9.9.9.9
              on-link: true
 ```

#### Multiple addresses on a single device

```yml
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
 ```
#### Using DHCP4 overrides
```yml
network:
  ethernets:
    dummy95:
      dhcp4: yes
      dhcp4-overrides:
        route-metric: 200
    test99:
      dhcp4: yes
      dhcp4-overrides:
        route-metric: 300
      dhcp6-overrides:
        use-dns: true
```
#### Using match as MacAddress
```yml
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
```

#### Routing Policy Rule
```yml
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
```

#### Generate link config from yml file:

`nmctl` can generate link configuration from YAML description.

```yml
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
      mtu: 10M
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
 ```

#### Generate VLAN configuration
 Configue VLan with id 10 and set it's master device to `ens33` .
 ```yml
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

 ```
 #### Generate Bond configuration
 Configue bond `bond0` with mode `active-backup`  and set slave devices to `ens33` and `ens37`.
 ```yml
 network:
  bonds:
      bond0:
          dhcp4: yes
          interfaces:
              - ens33
              - ens37
          parameters:
              mode: active-backup

 ```
 #### Generate Bridge configuration
 Configue bridge `bridge0` and set slave master devices to `ens33` with IPv4 DHCP network.
 ```yml
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
 ```
 
 #### Generate Tunnel configuration
 Configue IPv6 tunnel sit `he-ipv6` with address and routes.
 
 ```yml
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
 ```
 #### Generate VRF configuration
 Configue vrf `vrf1005` with table `1005` and interface `ens33` and `ens37`
 
 ```yml
 network:
  ethernets:
    ens33: 
    dhcp4: true
  vrfs:
    vrf1005:
      table: 1005
      interfaces:
        - ens33
        - test37
      routes:
      - to: default
        via: 1.2.3.4
      routing-policy:
      - from: 2.3.4.5

 ```

### Generate network config from kernel command line

`nmctl` understands kernel command line specified in [dracut's](https://mirrors.edge.kernel.org/pub/linux/utils/boot/dracut/dracut.html#dracutkernel7) network configuration format and can generate [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd-networkd.service.html)'s configuration while the system boots and will persist between reboots.

```bash
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
```

```bash
➜  ~ cat /proc/cmdline
   BOOT_IMAGE=/boot/vmlinuz-4.19.52-2.ph3-esx root=PARTUUID=ebf01b6d-7e9c-4345-93f4-122f44eb2726
   init=/lib/systemd/systemd rcupdate.rcu_expedited=1 rw systemd.show_status=0 quiet noreplace-smp
   cpu_init_udelay=0 net.ifnames=0 plymouth.enable=0 systemd.legacy_systemd_cgroup_controller=yes
   ip=dhcp
```

`network-config-manager-generator.service` is a [oneshot](https://www.freedesktop.org/software/systemd/man/systemd.service.html#Type=) type systemd service unit which runs while system boots. It parses the kernel command line and generates networkd config in ```/etc/systemd/network```.

```bash
➜  ~ sudo systemctl enable network-config-manager-generator.service
Created symlink /etc/systemd/system/network.target.wants/network-config-manager-generator.service → /usr/lib/systemd/system/network-config-manager-generator.service.

```

### Contributing

The network-config-manager project team welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).

### Generate network config from YAML file:


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

#### Configuring static address and routes
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
#### Using DHCP4 and DHCP6 overrides
```yml
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
```

#### Using IPv6 Router Advertisement (RA)
```yml
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

#### Configuring Routing Policy Rule
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

#### Configuring SR-IOV Virtual Functions
```yml
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
```


#### DHCP4 Server
```yml
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
 ```

#### Generate VLAN configuration
 Configure VLan with id 10 and set it's master device to `ens33` .
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
 Configure bond `bond0` with mode `active-backup`  and set slave devices to `ens33` and `ens37`.
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
 Configure bridge `bridge0` and set slave master devices to `ens33` with IPv4 DHCP network.
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
 Configure IPv6 tunnel sit `he-ipv6` with address and routes.

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
 Configure vrf `vrf1005` with table `1005` and interface `ens33` and `ens37`

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
        - ens37
      routes:
      - to: default
        via: 1.2.3.4
      routing-policy:
      - from: 2.3.4.5

 ```

 #### Generate VXLan configuration
 Configure VXLan `vxlan1` id 1 on interface `ens33`

 ```yml
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

 ```
 #### Generate WireGuard configuration
 Configure WIreGuard `wg1`

 ```yml
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

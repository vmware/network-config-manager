### nmctl output in text and JSON format


```bash
❯ nmctl
         System Name: Zeus1
              Kernel: Linux (6.7.0-0.rc0.20231110git89cdf9d55601.13.fc40.x86_64)
     Systemd Version: 255~rc3-1.fc40
        Architecture: x86-64
      Virtualization: vmware
    Operating System: Fedora Linux 40 (Workstation Edition Prerelease)
     Hardware Vendor: VMware, Inc.
      Hardware Model: VMware Virtual Platform
    Firmware Version: 6.00
     Firmware Vendor: Phoenix Technologies LTD
          Machine ID: d4f740d7e70d423cb46c8b1def547701
        System State: routable
        Online State: partial
       Address State: routable
  IPv4 Address State: routable
  IPv6 Address State: degraded
           Addresses: fe80::20c:29ff:fe5f:d139/64    on device ens33
                      127.0.0.1/8                    on device lo
                      172.16.130.131/24              on device ens33
                      ::1/128                        on device lo
                      fe80::20c:29ff:fe5f:d143/64    on device ens37
             Gateway: 172.16.130.2                   on device ens33
                 DNS: 8.8.4.4 8.8.8.8 172.16.130.2
  Current DNS Server: 8.8.8.8
        DNS Settings: MulticastDNS (no) LLMNR (resolve) DNSOverTLS (no) ResolvConfMode (stub) DNSSEC (no)
      Search Domains: test1 test2
                 NTP: test3 test4

 ```
JSON output:
```bash

❯ nmctl status ens33 -j
{
  "Index": 2,
  "Name": "ens33",
  "AlternativeNames": [
    "enp2s1"
  ],
  "SetupState": "configured",
  "Speed": "1000",
  "Duplex": "full",
  "HardwareAddress": "00:0c:29:5f:d1:39",
  "PermanentHardwareAddress": "00:0c:29:5f:d1:39",
  "MTU": "1500",
  "QDisc": "fq_codel",
  "Path": "pci-0000:02:01.0",
  "Driver": "e1000",
  "Vendor": "Intel Corporation",
  "Model": "pci-0000:02:01.0",
  "HardwareDescription": "VMware, Inc.",
  "LinkFile": "/usr/lib/systemd/network/99-default.link",
  "NetworkFile": "/etc/systemd/network/10-ens33.network",
  "KernelOperStateString": "up",
  "KernelOperState": 6,
  "AddressState": "routable",
  "IPv4AddressState": "routable",
  "IPv6AddressState": "degraded",
  "OnlineState": "online",
  "RequiredforOnline": "yes",
  "ActivationPolicy": "up",
  "Flags": [
    "up",
    "broadcast",
    "running",
    "multicast",
    "lowerup"
  ],
  "Alias": "",
  "LinkEvent": "none",
  "IPv6AddressGenerationMode": "eui64",
  "NetNSId": 0,
  "NewNetNSId": 0,
  "NewIfIndex": 0,
  "MinMTU": 46,
  "MaxMTU": 16110,
  "NTXQueues": 1,
  "NRXQueues": 1,
  "GSOMaxSize": 65536,
  "GSOMaxSegments": 65535,
  "TSOMaxSize": 65536,
  "TSOMaxSegments": 65535,
  "GROMaxSize": 65536,
  "GROIPv4MaxSize": 65536,
  "ParentDev": "0000:02:01.0",
  "ParentBus": "pci",
  "GSOIPv4MaxSize": 65536,
  "RXBytes": 2038133190,
  "TXBytes": 44031040,
  "RXPackets": 1489738,
  "TXPackets": 472059,
  "TXErrors": 0,
  "RXErrors": 0,
  "TXDropped": 0,
  "RXDropped": 0,
  "RXOverErrors": 0,
  "MulticastPackets": 0,
  "Collisions": 0,
  "RXLengthErrors": 0,
  "RXCRCErrors": 0,
  "RXFrameErrors": 0,
  "RXFIFOErrors": 0,
  "RXMissedErrors": 0,
  "TXAbortedErrors": 0,
  "TXCarrierErrors": 0,
  "TXFIFOErrors": 0,
  "TXHeartBeatErrors": 0,
  "TXWindowErrors": 0,
  "RXCompressed": 0,
  "TXCompressed": 0,
  "RXNoHandler": 0,
  "IPv6LinkLocalAddress": "fe80::20c:29ff:fe5f:d139",
  "Addresses": [
    {
      "Address": "fe80::20c:29ff:fe5f:d139",
      "PrefixLength": 64,
      "BroadcastAddress": "::",
      "Scope": 253,
      "ScopeString": "link",
      "Flags": 128,
      "FlagsString": [
        "permanent"
      ],
      "PreferedLifetime": "forever",
      "ValidLifetime": "forever",
      "Label": "",
      "Protocol": "kernel-link-local",
      "ConfigSource": "foreign"
    },
    {
      "Address": "172.16.130.131",
      "PrefixLength": 24,
      "BroadcastAddress": "172.16.130.255",
      "Scope": 0,
      "ScopeString": "global",
      "Flags": 0,
      "FlagsString": [
        "dynamic"
      ],
      "PreferedLifetime": 1747,
      "ValidLifetime": 1747,
      "Label": "ens33",
      "Protocol": "",
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254"
    }
  ],
  "Routes": [
    {
      "Type": 1,
      "TypeString": "unicast",
      "Scope": 0,
      "ScopeString": "global",
      "Table": 254,
      "TableString": "main(254)",
      "Protocol": 16,
      "Preference": 0,
      "Destination": "",
      "DestinationPrefixLength": 0,
      "Priority": 1024,
      "OutgoingInterface": 2,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "172.16.130.131",
      "Gateway": "172.16.130.2",
      "FlagsString": [],
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254"
    },
    {
      "Type": 1,
      "TypeString": "unicast",
      "Scope": 0,
      "ScopeString": "global",
      "Table": 10001,
      "TableString": "10001",
      "Protocol": 3,
      "Preference": 0,
      "Destination": "",
      "DestinationPrefixLength": 0,
      "Priority": 0,
      "OutgoingInterface": 2,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "",
      "Gateway": "172.16.130.2",
      "FlagsString": [],
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254"
    }
  ],
  "DNS": [
    {
      "Address": "8.8.4.4",
      "ConfigProvider": "static"
    },
    {
      "Address": "8.8.8.8",
      "ConfigProvider": "static"
    },
    {
      "Address": "172.16.130.2",
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254"
    }
  ],
  "SearchDomains": [
    {
      "Domain": "test1",
      "ConfigProvider": "static"
    },
    {
      "Domain": "test2",
      "ConfigProvider": "static"
    }
  ],
  "DNSSettings": {
    "MDNS": "no",
    "LLMNR": "yes"
  },
  "NTP": [
    {
      "Address": "test3",
      "ConfigSource": "runtime"
    },
    {
      "Address": "test4",
      "ConfigSource": "runtime"
    }
  ]
}

```

Display DNS
```bash
❯ nmctl show-dns dev ens33 -j
{
  "DNS": [
    {
      "Address": "8.8.4.4",
      "ConfigSource": "static"
    },
    {
      "Address": "8.8.8.8",
      "ConfigSource": "static"
    },
    {
      "Address": "8.8.4.4",
      "ConfigSource": "static"
    },
    {
      "Address": "8.8.8.8",
      "ConfigSource": "static"
    },
    {
      "Address": "172.16.130.2",
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254"
    }
  ],
  "CurrentDNSServer": "8.8.8.8"
}
```

Display DNS mode. Allow to show how DNS servers are configured. Displays one of 'static', 'DHCP' or 'merged' (DHCP + static)

```bash
❯ nmctl show-dns-mode dev ens33
DNS Mode: merged
```

```bash
❯ nmctl show-dns-mode dev ens33 -j
{
  "DNSMode": "merged"
}
```

Display Search domains
```bash
❯ nmctl show-domains dev ens33
DNS Domain: test1
INDEX LINK                 Domain
    2 ens33                test1
```

JSON format
```bash
❯ nmctl show-domains dev ens33 -j | jq
{
  "SearchDomains": [
    "test1"
  ],
  "ens33": [
    "test1"
  ]
}

```

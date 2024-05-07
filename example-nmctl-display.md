### nmctl output in text and JSON format


```bash
❯ nmctl         
         System Name: Zeus1
              Kernel: Linux (6.9.0-0.rc6.20240503gitf03359bca01b.56.fc41.x86_64)
     Systemd Version: 255.5-1.fc41
        Architecture: x86-64
      Virtualization: vmware
    Operating System: Fedora Linux 41 (Workstation Edition Prerelease)
     Hardware Vendor: VMware, Inc.
      Hardware Model: VMware Virtual Platform
    Firmware Version: 6.00
     Firmware Vendor: Phoenix Technologies LTD
       Firmware Date: Thu Nov 12 05:30:00 2020
             Boot ID: 8ec8f1a083854762a97bc9a62701d490
          Machine ID: d4f740d7e70d423cb46c8b1def547701
        System State: routable
        Online State: partial
       Address State: routable
  IPv4 Address State: routable
  IPv6 Address State: degraded
           Addresses: 127.0.0.1/8                    on device lo
                      ::1/128                        on device lo
                      fe80::20c:29ff:fe5f:d139/64    on device ens33
                      172.16.130.169/24              on device ens33
             Gateway: 172.16.130.2                   on device ens33
                 DNS: 172.16.130.2 
  Current DNS Server: 8.8.8.8
        DNS Settings: MulticastDNS (no) LLMNR (resolve) DNSOverTLS (no) ResolvConfMode (stub) DNSSEC (no)
                                                                                                             

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
  "RXBytes": 229303570,
  "TXBytes": 7166820,
  "RXPackets": 167649,
  "TXPackets": 54573,
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
      "Family": 10,
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
      "Address": "172.16.130.169",
      "Family": 2,
      "PrefixLength": 24,
      "BroadcastAddress": "172.16.130.255",
      "Scope": 0,
      "ScopeString": "global",
      "Flags": 0,
      "FlagsString": [
        "dynamic"
      ],
      "PreferedLifetime": 1048,
      "ValidLifetime": 1048,
      "Label": "ens33",
      "Protocol": "",
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254",
      "ConfigState": "configured"
    }
  ],
  "Routes": [
    {
      "Type": 3,
      "TypeString": "broadcast",
      "Scope": 253,
      "ScopeString": "link",
      "Table": 255,
      "TableString": "local(255)",
      "Family": 2,
      "Protocol": 2,
      "Preference": 0,
      "Destination": "172.16.130.255",
      "DestinationPrefixLength": 32,
      "Priority": 0,
      "OutgoingInterface": 2,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "172.16.130.169",
      "Gateway": "",
      "FlagsString": [],
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254",
      "ConfigState": "configuring,configured"
    },
    {
      "Type": 1,
      "TypeString": "unicast",
      "Scope": 253,
      "ScopeString": "link",
      "Table": 254,
      "TableString": "main(254)",
      "Family": 2,
      "Protocol": 2,
      "Preference": 0,
      "Destination": "172.16.130.0",
      "DestinationPrefixLength": 24,
      "Priority": 1024,
      "OutgoingInterface": 2,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "172.16.130.169",
      "Gateway": "",
      "FlagsString": [],
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254",
      "ConfigState": "configuring,configured"
    },
    {
      "Type": 2,
      "TypeString": "local",
      "Scope": 0,
      "ScopeString": "global",
      "Table": 255,
      "TableString": "local(255)",
      "Family": 10,
      "Protocol": 2,
      "Preference": 0,
      "Destination": "::1",
      "DestinationPrefixLength": 128,
      "Priority": 0,
      "OutgoingInterface": 1,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "",
      "Gateway": "",
      "FlagsString": []
    },
    {
      "Type": 1,
      "TypeString": "unicast",
      "Scope": 0,
      "ScopeString": "global",
      "Table": 254,
      "TableString": "main(254)",
      "Family": 2,
      "Protocol": 16,
      "Preference": 0,
      "Destination": "",
      "DestinationPrefixLength": 0,
      "Priority": 1024,
      "OutgoingInterface": 2,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "172.16.130.169",
      "Gateway": "172.16.130.2",
      "FlagsString": [],
      "ConfigSource": "foreign",
      "ConfigProvider": "172.16.130.254",
      "ConfigState": "configured"
    },
    {
      "Type": 5,
      "TypeString": "multicast",
      "Scope": 0,
      "ScopeString": "global",
      "Table": 255,
      "TableString": "local(255)",
      "Family": 10,
      "Protocol": 2,
      "Preference": 0,
      "Destination": "ff00::",
      "DestinationPrefixLength": 8,
      "Priority": 256,
      "OutgoingInterface": 2,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "",
      "Gateway": "",
      "FlagsString": [],
      "ConfigSource": "foreign",
      "ConfigProvider": "172.16.130.254",
      "ConfigState": "configured"
    },
    {
      "Type": 1,
      "TypeString": "unicast",
      "Scope": 0,
      "ScopeString": "global",
      "Table": 10001,
      "TableString": "10001",
      "Family": 2,
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
      "ConfigSource": "foreign",
      "ConfigProvider": "172.16.130.254",
      "ConfigState": "configured"
    },
    {
      "Type": 1,
      "TypeString": "unicast",
      "Scope": 253,
      "ScopeString": "link",
      "Table": 254,
      "TableString": "main(254)",
      "Family": 2,
      "Protocol": 16,
      "Preference": 0,
      "Destination": "172.16.130.2",
      "DestinationPrefixLength": 32,
      "Priority": 1024,
      "OutgoingInterface": 2,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "172.16.130.169",
      "Gateway": "",
      "FlagsString": [],
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254",
      "ConfigState": "configuring,configured"
    },
    {
      "Type": 2,
      "TypeString": "local",
      "Scope": 254,
      "ScopeString": "host",
      "Table": 255,
      "TableString": "local(255)",
      "Family": 2,
      "Protocol": 2,
      "Preference": 0,
      "Destination": "172.16.130.169",
      "DestinationPrefixLength": 32,
      "Priority": 0,
      "OutgoingInterface": 2,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "172.16.130.169",
      "Gateway": "",
      "FlagsString": [],
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254",
      "ConfigState": "configuring,configured"
    },
    {
      "Type": 2,
      "TypeString": "local",
      "Scope": 0,
      "ScopeString": "global",
      "Table": 255,
      "TableString": "local(255)",
      "Family": 10,
      "Protocol": 2,
      "Preference": 0,
      "Destination": "fe80::20c:29ff:fe5f:d139",
      "DestinationPrefixLength": 128,
      "Priority": 0,
      "OutgoingInterface": 2,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "",
      "Gateway": "",
      "FlagsString": [],
      "ConfigSource": "foreign",
      "ConfigProvider": "172.16.130.254",
      "ConfigState": "configured"
    },
    {
      "Type": 1,
      "TypeString": "unicast",
      "Scope": 0,
      "ScopeString": "global",
      "Table": 254,
      "TableString": "main(254)",
      "Family": 10,
      "Protocol": 2,
      "Preference": 0,
      "Destination": "fe80::",
      "DestinationPrefixLength": 64,
      "Priority": 256,
      "OutgoingInterface": 2,
      "IncomingInterface": 0,
      "TTLPropogate": 0,
      "PreferredSource": "",
      "Gateway": "",
      "FlagsString": [],
      "ConfigSource": "foreign",
      "ConfigProvider": "172.16.130.254",
      "ConfigState": "configured"
    }
  ],
  "DNS": [
    {
      "Address": "172.16.130.2",
      "Family": 2,
      "ConfigSource": "DHCPv4",
      "ConfigProvider": "172.16.130.254"
    }
  ],
  "DNSSettings": [
    {
      "LLMNR": "yes",
      "ConfigSource": "static"
    },
    {
      "MDNS": "no",
      "ConfigSource": "static"
    }
  ]
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

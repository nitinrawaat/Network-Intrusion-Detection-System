# 🌐 Lab Topology & Addressing Scheme

```text
                           LOCAL PHYSICAL LAN (e.g. 192.168.1.0/24)
                                             │
               ┌─────────────────────────────┴─────────────────────────────┐
               │                                                           │
     [MAIN HOST: Windows]                                        [SECOND MACHINE: Attacker]
     Host OS: Windows 11/10                                      OS: Kali Linux / Linux / Windows
     Physical IP: 192.168.1.10                                   IP: 192.168.1.20 (Example)
               │
          [VMware Workstation]
          (Bridged Network: VMnet0)
               │
               ▼
     [IDS SENSOR: Kali Linux VM]
     VM IP: 192.168.1.50 (Example)
     Interface: eth0 / ens33
     Role: Passive Sniffing & IDS Engine
```

## IP Assignments (Example Reference)

| Node | OS / Role | Interface | Example IP | Notes |
|---|---|---|---|---|
| **Attacker Machine** | Linux / Physical Machine | eth0 / wlan0 | `192.168.1.20` | Generates attack and benchmark traffic |
| **IDS Sensor** | Kali Linux VM | eth0 / ens33 | `192.168.1.50` | Runs Python IDS; inspects packets |
| **Gateway / Router**| Router | LAN | `192.168.1.1` | Local DHCP & default gateway |

> [!NOTE]
> Update the IPs above with the actual addresses obtained via `ip addr` or `ipconfig` on your specific devices.

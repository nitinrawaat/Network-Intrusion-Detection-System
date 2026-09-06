# 🛠️ Lab Setup Guide: Kali Linux VM in VMware

This guide explains how to prepare your Kali Linux Virtual Machine inside VMware Workstation / Player to act as the **Network IDS Sensor**.

---

## 1. VMware Network Adapter Configuration

For your Kali VM to capture traffic from a separate physical attacker machine, the VM must receive its own IP address on your local network.

1. In VMware, select your **Kali Linux VM** (ensure it is powered off or restart network after changing).
2. Open **VM Settings** (`Ctrl + D` or right-click VM -> *Settings*).
3. Select **Network Adapter**.
4. Set Network Connection to **Bridged: Connected directly to the physical network**.
   - *(Optional Check)*: In VMware's *Virtual Network Editor*, verify `VMnet0 (Bridged)` is bridged to your active physical network adapter (Wi-Fi or Ethernet adapter on your Windows host).
5. Ensure **Replicate physical network connection state** is checked.
6. Click **OK** and boot the Kali Linux VM.

---

## 2. Verify Kali Network Configuration

Open a terminal inside Kali Linux and run:

```bash
# Check assigned IP and interface names
ip addr

# Check default gateway
ip route
```

Identify your active interface name (commonly `eth0` or `ens33`). Note down its IP address (e.g. `192.168.1.50`).

Verify external network connectivity:
```bash
ping -c 3 8.8.8.8
```

---

## 3. Install System Prerequisites on Kali

Run the following in Kali's terminal:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git tcpdump libpcap-dev
```

---

## 4. Get the IDS Code onto Kali

### Option A: Clone from GitHub (Recommended)
Once your GitHub repository is updated:
```bash
cd ~
git clone https://github.com/NiTinRaWaTtt/Network-Intrusion-Detection-System.git python-network-ids
cd python-network-ids
```

### Option B: VMware Shared Folders / SCP / Local Transfer
If transferring directly from Windows:
```bash
# Via SCP from Windows (in PowerShell):
# scp -r D:\Project\Project-1 kali@<KALI_IP>:~/python-network-ids
```

---

## 5. Set Up Python Virtual Environment on Kali

Inside the project directory on Kali:

```bash
cd ~/python-network-ids

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

Verify Scapy is installed:
```bash
python3 -c "import scapy; print('Scapy version:', scapy.__version__)"
```

---

## 6. Running Packet Capture on Kali

Raw packet sniffing requires superuser privileges (`cap_net_raw` / root). Run the IDS using `sudo` with the virtual environment's Python binary:

```bash
# 1. List available interfaces
sudo .venv/bin/python3 -m ids.main --list-interfaces

# 2. Start capturing on your active interface (e.g., eth0 or ens33)
sudo .venv/bin/python3 -m ids.main --interface eth0

# Or capture a fixed number of packets (e.g., 20 packets)
sudo .venv/bin/python3 -m ids.main --interface eth0 --count 20
```

### Stopping Capture Gracefully
Press `Ctrl + C` in the terminal. The IDS will trap the interrupt signal, stop sniffing, and display the total count of captured packets.

---

## 7. Verifying from Attacker Machine / External Host

From your second physical machine or host:
```bash
# Send 4 ICMP pings to the Kali VM
ping <KALI_IP>
```

You should immediately see the ICMP packets logged in real-time on your Kali terminal:
```text
[00001] 192.168.1.20 -> 192.168.1.50 ICMP type=8 code=0 (ttl=64)
[00002] 192.168.1.50 -> 192.168.1.20 ICMP type=0 code=0 (ttl=64)
```

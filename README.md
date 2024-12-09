# ARP Spoofing Detection Tool

This script detects ARP spoofing attacks on a given network interface.

**Features:**

* Monitors ARP traffic on the specified interface.
* Compares the source MAC address of ARP responses with the actual MAC address of the source IP.
* Detects and alerts the user if an ARP spoofing attack is detected.

**Usage:**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Gaurav909565/arp_spoof_detector.git
   ```

2. **Navigate to the repository:**
   ```bash
   cd arp_spoof_detector/
   ```

3. **Run the script:**
   ```bash
   python arp_spoofing_detector.py -i <interface_name>
   ```
   * Replace `<interface_name>` with the name of the network interface you want to monitor (e.g., `eth0`, `wlan0`).

**Example:**

```bash
python arp_spoofing_detector.py -i eth0
```
* This script provides basic ARP spoofing detection capabilities. 
* It may not detect all types of ARP spoofing attacks.

**Disclaimer:**

* This script is for educational purposes only. 
* It may not detect all types of ARP spoofing attacks. 
* The developer is not responsible for any misuse of this tool.

**Note:**

* This script requires the Scapy library. Install it using:
   ```bash
   pip install scapy
   ```

**Disclaimer:**

* This script is for educational and ethical purposes only. 
* It may not detect all types of ARP spoofing attacks. 
* The developer is not responsible for any misuse of this tool. 
* Always use this script responsibly and ethically.

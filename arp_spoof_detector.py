import scapy.all as scapy
import argparse

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="To add an interface to scan")
    option = parser.parse_args()

    if not option.interface:
        parser.error("[-] Interface not found, Please specify an interface")
    else:
        return option

def process_packet(interface):
    scapy.sniff(iface= interface, store=False, prn=check_mac)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_req_broadcast, timeout=4, verbose=False) [0]

    return answered_list[0][1].hwsrc

def check_mac(packet):
    try:
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2 :
            real_mac = get_mac(packet[scapy.ARP].psrc)
            returned_mac = packet[scapy.ARP].hwsrc
            if real_mac != returned_mac:
                print("[-] You are under ARP Spoofing attack")
    except IndexError:
        pass

if __name__ == '__main__':
    options = get_argument()
    try:
        process_packet(options.interface)
    except KeyboardInterrupt:
        print("[-] Exiting the program")


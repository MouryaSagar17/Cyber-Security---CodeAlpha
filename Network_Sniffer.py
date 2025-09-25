# Importing the required packages.
import scapy.all
import psutil
from prettytable import PrettyTable
import time
from colorama import Fore, Style
from scapy.layers.inet import IP, TCP, UDP, ICMP


def get_current_ip(interface):
    addrs = psutil.net_if_addrs().get(interface)
    if addrs:
        for addr in addrs:
            if addr.family == 2:  # AF_INET (IPv4)
                return addr.address
    return None


def get_current_mac(interface):
    addrs = psutil.net_if_addrs().get(interface)
    if addrs:
        for addr in addrs:
            # On Windows, use psutil.AF_LINK; on Linux, use 17 for MAC addresses
            if getattr(addr, "family", None) in [17, psutil.AF_LINK]:
                return addr.address
    return None


def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable(
        [f"{Fore.GREEN}Interface", "Mac Address", f"IP Address{Style.RESET_ALL}"]
    )
    for k in addrs:
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)


def sniff(interface):
    scapy.all.sniff(iface=interface, prn=packet_callback, store=False)


def packet_callback(packet):
    packet_details = f"{Fore.CYAN}Packet Details:{Style.RESET_ALL}\n"

    if IP in packet:
        packet_details += f"{Fore.GREEN}IP Layer:{Style.RESET_ALL}\n"
        packet_details += (
            f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}\n"
        )
        packet_details += f"ID: {packet[IP].id} ; Version: {packet[IP].version} ; Length: {packet[IP].len} ; Flags: {packet[IP].flags}\n"
        packet_details += f"Protocol: {packet[IP].proto} ; TTL: {packet[IP].ttl} ; Checksum: {packet[IP].chksum}\n"

    if TCP in packet:
        packet_details += f"{Fore.YELLOW}TCP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}\n"
        packet_details += f"Sequence Number: {packet[TCP].seq} ; Acknowledgment Number: {packet[TCP].ack}\n"
        packet_details += (
            f"Window: {packet[TCP].window} ; Checksum: {packet[TCP].chksum}\n"
        )
        packet_details += (
            f"Flags: {packet[TCP].flags} ; Options: {packet[TCP].options}\n"
        )

    if UDP in packet:
        packet_details += f"{Fore.YELLOW}UDP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[UDP].sport}\n"
        packet_details += f"Destination Port: {packet[UDP].dport}\n"

    if ICMP in packet:
        packet_details += f"{Fore.YELLOW}ICMP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Type: {packet[ICMP].type}\n"
        packet_details += f"Code: {packet[ICMP].code}\n"

    print(packet_details)


def main():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(
        f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***]{Style.RESET_ALL}"
    )
    try:
        ip_table()
        interface = input("[*] Please enter the interface name: ")
        print(f"{Fore.GREEN}Selected Interface: {interface}{Style.RESET_ALL}")
        ip = get_current_ip(interface)
        mac = get_current_mac(interface)
        print(f"IP Address: {ip}")
        print(f"MAC Address: {mac}")
        print("[*] Sniffing Packets...")
        sniff(interface)
        print(f"{Fore.YELLOW}\n[*] Interrupt...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Stopping the Sniffer...{Style.RESET_ALL}")
        time.sleep(3)


if __name__ == "__main__":
    main()

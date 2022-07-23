#!usr/bin/env python
import subprocess
import optparse
import re


def change_mac(inter, mac):
    """
    Calling linux command using subprocess module to change the mac address.
    The interface is turned off then the mac address is changed and then it is turned back on.
    :param inter: interface name
    :param mac: new mac address
    :return: None
    """
    subprocess.call(["ifconfig", inter, "down"])
    subprocess.call(["ifconfig", inter, "hw", "ether", mac])
    subprocess.call(["ifconfig", inter, "up"])
    print()


def get_arguments():
    """
    This function asks the user for the interface name and the new mac address.
    Both the interface and mac address are required to be passed on through the terminal.
    :return: A tuple containing the interface name and the mac address
    """
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC")
    parser.add_option("-m", "--mac", dest="mac_add", help="New MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify the interface name. Use --help for details.")
    elif not options.mac_add:
        parser.error("[-] Please specify the mac address. Use --help for details.")
    return options


def get_mac(inter):
    """
    Returns the current mac address of the device of the given interface
    :param inter: interface name
    :return: current mac address of the device
    """
    ifconfig_result = subprocess.check_output(["ifconfig", inter])
    mac_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result.decode("utf-8"))
    return mac_search_result.group(0)


def main():
    options = get_arguments()
    og_mac = get_mac(options.interface)
    change_mac(options.interface, options.mac_add)

    new_mac = get_mac(options.interface)
    if new_mac == options.mac_add:
        print("[+] MAC address changed successfully.")
        print("[+] MAC address changed from", og_mac, "to", new_mac)
    else:
        print("[-] Task failed. Could not read MAC address.")


if __name__ == '__main__':
    main()

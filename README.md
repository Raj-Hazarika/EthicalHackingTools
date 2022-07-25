# Ethical Hacking Tools
- All the tools are programmed using python.
- The tools are fully functional and are meant to be used using the kali linux terminal.
- ***FOR EDUCATIONAL PURPOSES ONLY***


## How to use?


 - ### MAC_changer.py

    This python script can be used to change the mac address of our current device to any desired mac address.

    The interface name and the new mac address is required as input to change the mac address.
    In the linux terminal, enter the following line:
```
    python3 MAC_changer.py -i <interface name> -m <mac address>
```
    For more help, the help command can be used in the linux terminal:
```
    python3 MAC_changer.py --help
```    


 - ### NetworkScanner.py

    This python scripts scans the provided ip range to search all the devices connected to it. Only devices connected to the same subnet are identified with this script. 

    The ip range needs to be entered and all the devices connected to the same subnet will be detected along with their mac addresses, ip addresses and vendor information.
    Enter the following line in the linux terminal:
```
    python3 NetworkScanner.py -i <ip range>
```
    For more help, the help command can be used in the linux terminal:
```
    python3 NetworkScanner.py --help
```    


 - ### VendorInfo.py

    This python script is used in NetworkScanner.py to gather the vendor information about the devices. The script uses the mac address to gather information regarding the vendor of the device.
    This script is not meant to be used solely in the linux terminal and is used as a helper script in NetworkScanner.py.



 - ### ARP_Spoof.py

    ARP spoofing is one way of performing the man in the middle (MITM) attacks. ARP sppofing is done to intercept data of the target device. This is done by tricking the target device to send data to the hacker device instead of sending it to the recipient.

    For this script, the ip address of the target device and the ip address of the source (router ip address) is needed. The following line should be entered in the terminal:
```
    python3 ARP_Spoof.py -t <target ip address> -s <source ip address>
```
    After entering the above line in the terminal, the target ip will start sending network packets via our device but our device will stop the request from going  
    through the internet. As a result of which, it will seem as if the target device has lost connection to the internet. To grant access and forward the packets to 
    the internet and maintain the access of the target device, the following line is also required to be entered in a different terminal:
```
    echo 1 > /proc/sys/net/ipv4/ip_forward
```

    For more help, the help command can be used in the linux terminal:
```
    python3 ARP_Spoof.py --help
``` 


 - ### PacketSniffer.py

    This script enables the hacker to read the packets sent by the target. For reading the packet, the hacker has to be the man in the middle which could be done by 
    ARP_Spoof.py. Data of sites loaded over HTTP can be read. For this to work with HTTPS, the HTTPS site has to be downgraded to HTTP.

    The hacker needs to specify the interface over which the data is to be read. Enter the following line in the script for this to work:
```
    python3 PacketSniffer.py -i <interface name>
```

    For more help, the help command can be used in the linux terminal:
```
    python3 PacketSniffer.py --help
``` 

# NetSniffer
Netsniffer is a packet sniffer aimed at helping begginer/intermediate computer science and cybersecurity learners. It uses the open source libpcap library, and is written in c++. Net sniffer can be ran on linux to capture traffic which can help debug potential issues and helps you to understand what network activity goes to and from your linux based machines. I am working on this project to showcase my cybersecurity skills and to demonstrate my low level network programming skills using libpcap.


# Capabilities
- live capture of packets
- NetSniffer captures all Ipv4 based packets only.
- Session summary at the end (shows total packets captured + total network data in bytes)
  
Protocols Parsed:
Ethernet II (Ethertype, mac adresses)
IPv4 (source/destination ip, protocols used)
TCP (port type)
UDP (port type)

# DEPENDANCIES
Install libpcap on your target system (where you plan to run this.) 'Linux only!'
```bash
 sudo apt install libpcap0.8 libpcap0.8-dev 
```
If you do not have it already, install a compiler of your choice (ex g++)
```bash
 sudo apt install build-essential
```
You can install CMAKE to compile files.


# How it works
This project uses libpcap, an open source library that can capture network traffic on network interfaces. The packet sniffer is a cybersecurity based project, based on the OSI model. It uses layers 2 through 4 on it.

<img width="541" height="423" alt="image" src="https://github.com/user-attachments/assets/14294c04-8e1a-48a3-962b-3c1fb457933b" />

`Layer 2: Data Link Layer`: This layer in Netsniffer allows to get the MAC adress (hardware adresses of devices) for the source and destination devices. 

`Layer 3: Network Layer`: This layer controls the flow/routing of traffic. There are different protocols that route traffic and forward packets, such as `IPV4`, and `IPV6`. This packet sniffer works with the `IPv4` protocol, as other protocols have different protocol headers. `Ipv4` is the most common type of internet protocol used in most devices today. To ensure traffic is IPv4 and not any other protocol, we can parse ethernet frame (layer 2) (0->13 bytes). If the 12th and 13th byte, which shows the ether type (or what protocol it uses, such as IPv4, Ipv6, ARP etc) is `0x0800`, it is Ipv4. Otherwise the packet sniffer will not take capture packets.

`Layer 4: Transport Layer`: This layer has many protocols that transport packet data accordingly. For example the UDP protocol is used in video games, to access servers fast by sending a lot of packets sequentially. 






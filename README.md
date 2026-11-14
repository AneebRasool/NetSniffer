# NetSniffer
This repository will house a packet sniffer I will be working on. It will be written in c++ with thanks to the libpcap library, intended to run on linux based systems to capture packets. This packet sniffer is aimed towards begginer/intermediate skill levels for networking. 

This packet sniffer uses the library 'libpcap', a very foundational library used for packet sniffing/networking purposes (used in tcpdump, a popular open source packet sniffer). 

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

`Layer 3: Network Layer`: This layer controls the flow/routing of traffic. There are different protocols that route traffic and forward packets, such as `IPV4`, and `IPV6`. This packet sniffer works with the `IPv4` protocol, as other protocols have different protocol headers. `Ipv4` is the most common type of internet protocol used in most devices today.

`Layer 3: Transport Layer`: This layer has many protocols that transport packet data accordingly. For example the UDP protocol is used in video games, to access servers fast by sending a lot of packets sequentially. 






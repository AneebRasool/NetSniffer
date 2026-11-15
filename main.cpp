#include<iostream>
#include<pcap.h>
#include<vector>
#include<ctime>
#include<iomanip>
#include<cstdlib>
using namespace std;

string protocol_identifier(uint8_t protraw)
{

string protocol;

switch(protraw)
{
    case 1:  protocol = "ICMP"; break;
    case 6:  protocol = "TCP"; break;
    case 17: protocol = "UDP"; break;
    case 41: protocol = "IPv6"; break;
    default: protocol = "Protocol unknown:" + to_string(protraw); // fallback shows the raw protocol number
    break; 
}

return protocol;
}


string port_identifier(uint16_t srcport, uint16_t dstport)
{

string port_type;

if(srcport == 20 || dstport == 20) port_type = "FTP data";
else if(srcport == 21 || dstport == 21) port_type = "FTP";
else if(srcport == 22 || dstport == 22) port_type = "SSH";
else if(srcport == 23 || dstport == 23) port_type = "TELNET";
else if(srcport == 25 || dstport == 25) port_type = "SMTP";
else if(srcport == 53 || dstport == 53) port_type = "DNS";
else if(srcport == 69 || dstport == 69) port_type = "TFTP";
else if(srcport == 80 || dstport == 80) port_type = "HTTP";
else if(srcport == 443 || dstport == 443) port_type = "HTTPS";
else if(srcport == 445 || dstport == 445) port_type = "SMB";
else if(srcport == 8096 || dstport == 8096) port_type = "Jellyfin HTTP";
else if(srcport == 8920 || dstport == 8920) port_type = "Jellyfin HTTPS";

else port_type = "NA";

return port_type;
}


void packet_handler(u_char *user_args, const struct pcap_pkthdr *header, const u_char *packet)
{

cout << left;

uint16_t ethertype = (packet[12] << 8) | packet[13]; //finds ethertype (12th and 13th byte of ethernet layer!)

//Outputs only if ethertype is ipv4 (to avoid outputting other garbled data thats not ipv4)
if (ethertype == 0x0800){


//convert unix time to readable date/time.
char timebuf[16];
time_t secs = header->ts.tv_sec;
tm *t = localtime(&secs);
strftime(timebuf, sizeof(timebuf), "%I:%M:%S %p", t);
    cout << setw(18) << timebuf;


    //find protocols
    uint8_t protocol = (int)packet[23];
    cout << setw(11) << protocol_identifier(protocol);


    string ipflow = "";

//source ip adress (based on ether type).
string srcip = "";
    for(int i=26; i<30; i++){ // ethernet layer (2) ends at byte 13, and +12 bytes to 14bytes leads to 26th byte (source ip)
        srcip += to_string((int)packet[i]);
        if(i==29) break;
        srcip += ".";
    }


//source port
uint16_t srcport = (packet[34] << 8) | packet[35];


string dstip = "";
    //Destination ip adress (based on ether type).
    for(int i=30; i<34; i++){ // After byte 29, +4 is 33th byte. so 30th, 31st, 32nd and 33rd byte is destination ip adress in ipv4 model.
        dstip += to_string((int)packet[i]);
        if(i==33) break;
        dstip += ".";
    }

//destination port
uint16_t dstport = (packet[36] << 8) | packet[37];


ipflow += srcip; ipflow += ":"; ipflow += to_string(srcport);
    ipflow += " -> "; 
    ipflow += dstip; ipflow += ":"; ipflow += to_string(dstport);
    cout << setw(50) << ipflow;


//make sure port types only display for TCP and UDP (no port types for other ports!)
if(protocol == 6 || protocol == 17) cout << setw(16) << port_identifier(srcport, dstport);

//if no port type, display no type.
else cout << setw(10) << "No type";


//packet length
cout << header->len << "B";
}

else{cout << "[NON-ipv4 packet captured]";}
cout << endl;
}


int main()
{

pcap_if_t *alldevs = nullptr;
char errorbuffer[PCAP_ERRBUF_SIZE]; // stores any errors/issues.
int interfacesuccess = pcap_findalldevs(&alldevs, errorbuffer); //Lists all network interfaces.


if (interfacesuccess == -1){
    cout << "error found: " << errorbuffer;
}


else{

int x;
vector<pcap_if_t*> interfaces;

cout << "Found interfaces: " << endl;
for (pcap_if_t *i = alldevs; i != nullptr; i = i->next) { //all devs = # of interfaces from linked list.
     cout << i->name << endl;
     interfaces.push_back(i);
}


cout << "What interface would you like to choose, ";
cout << "enter number from #0 (first interface) to #-1? (last interface) going up by 1's: ";
cin >> x;

if(x < 0 || x >= interfaces.size()){
    cout << "error, invalid interface chosen. Please pick again." << endl;
}

cout << "\nYou picked interface: " << interfaces[x]->name << endl;


pcap_t *handle = pcap_open_live(interfaces[x]->name, 65535, 1, 75, errorbuffer); // (interface, byte limit, promiscious mode?, time out (ms), err buf) - paramaters.

if (handle == nullptr){
    cout << "could not open network interface " << interfaces[x]->name << errorbuffer;
}

cout << "Timestamp" << setw(15) << "Protocol" << setw(42) << "Source IP:port -> Destination IP:port" << setw(18) << "port type" << setw(17) <<"Total size" << endl;
for(int i=0;i<110;i++) cout << "-";
cout << endl;


pcap_loop(handle, -1, packet_handler, nullptr);


//ending processes
pcap_freealldevs(alldevs);
pcap_close(handle);
}

return 0;


}

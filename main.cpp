#include<iostream>
#include<pcap.h>
#include<vector>
#include<ctime>
#include<iomanip>
using namespace std;


void packet_handler(u_char *user_args, const struct pcap_pkthdr *header, const u_char *packet){


//convert unix time to readable date/time.
cout << left;

cout << setw(15) << (header->ts.tv_sec);

//packet length
cout <<  header->len << setw(10)  << "B";

uint16_t ethertype = (packet[12] << 8) | packet[13]; //move 12th ethertype 1byte left, and combine with 13th etherbyte (to combine ethertype instead of 2 values)
                                                     // ethertype is 2 bytes or 16bits, and unsigned so uint16_t is an exact size instead of regular int (4 bytes)

cout << hex;
cout << "Ether type: 0x" << setw(15) << ethertype;

cout << dec;

if (ethertype == 0x0800){

    //source ip adress (based on ether type).
    
    for(int i=26; i<30; i++){ // ethernet layer (2) ends at byte 13, and +12 bytes to 14bytes leads to 26th byte (source ip)
        cout << (int)packet[i];
        if(i==29){
            break;
        }
        cout << ".";
    }

    cout << " -> ";

    //Destination ip adress (based on ether type).
    for(int i=30; i<34; i++){ // After byte 29, +4 is 33th byte. so 30th, 31st, 32nd and 33rd byte is destination ip adress in ipv4 model.
        cout << (int)packet[i];
        if(i==33){
            break;
        }
        cout << ".";
    }

}

cout << dec;
cout << endl << endl;
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


pcap_t *handle = pcap_open_live(interfaces[x]->name, 65535, 1, 1, errorbuffer); // (interface, byte limit, promiscious mode?, time out (ms), err buf) - paramaters.

if (handle == nullptr){
    cout << "could not open network interface " << interfaces[x]->name << errorbuffer;
}

cout << "Timestamp" << setw(15) << "Total size" << setw(15) << "type" << setw(10) << "Flow" << endl;

pcap_loop(handle, 5, packet_handler, nullptr);


//ending processes
pcap_freealldevs(alldevs);
pcap_close(handle);
}

return 0;


}

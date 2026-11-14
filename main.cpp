#include<iostream>
#include<pcap.h>
#include<vector>
#include<ctime>
using namespace std;


void packet_handler(u_char *user_args, const struct pcap_pkthdr *header, const u_char *packet){

cout << "Packet captured. Length: "<< header->len << endl;
//convert unix time to readable date/time.
cout << "time stamp: " << ctime(&header->ts.tv_sec) << endl;


//destination MAC adress:

cout << "Mac adress: " << endl;
for(int i=0;i<6;i++){
       cout << hex << (int)packet[i] << " "; //print hexadecimal forma
}
cout << dec;
}


int main()
{

pcap_if_t *alldevs = nullptr;
char errorbuffer[PCAP_ERRBUF_SIZE];
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
cout << "enter number from #0 (first interface) to #? (last interface) going up by 1's: ";
cin >> x;


cout << "\nYou picked interface: " << interfaces[x]->name;

pcap_t *handle = pcap_open_live(interfaces[x]->name, 65535, 1, 1, errorbuffer); // (interface, byte limit, promiscious mode, time out ms, err buf) - paramaters.

if (handle == nullptr){
    cout << "could not open network interface " << interfaces[x]->name << errorbuffer;
}


pcap_loop(handle, 5, packet_handler, nullptr);


//ending processes
pcap_freealldevs(alldevs);
pcap_close(handle);
}

return 0;


}






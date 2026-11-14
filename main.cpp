#include<iostream>
#include<pcap.h>
#include<vector>
#include<ctime>
#include<iomanip>
using namespace std;


void packet_handler(u_char *user_args, const struct pcap_pkthdr *header, const u_char *packet){

//packet length
cout << "Length: "<< header->len << endl;

//convert unix time to readable date/time.
cout << "time stamp: " << ctime(&header->ts.tv_sec);


cout << "Ether type: 0x";
for(int i = 12; i <= 13; i++){
    // setw(2) ensures it takes up 2 spaces, setfill('0') puts a '0' in front if it's single-digit
    cout << hex << setw(2) << setfill('0') << (int)packet[i];
}
cout << endl;

cout << dec;



if ((int)packet[12] == 8 && (int)packet[13]==0){

    //source ip adress (based on ether type).
    cout << "Source ip adress: ";
    for(int i=26; i<30; i++){ // ethernet layer (2) ends at byte 13, and +12 bytes to 14bytes leads to 26th byte (source ip)
        cout << (int)packet[i];
        if(i==29){
            break;
        }
        cout << ".";
    }

    cout << " -> Destination ip adress: ";

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


cout << "\nYou picked interface: " << interfaces[x]->name << endl;

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






#include "header.h"

/*---------------------------------------
           summary variables
---------------------------------------*/

long long int total_bytes = 0;
long long int total_packets = 0;

ofstream file;

pcap_t *global = nullptr;

void signalHandler(int)
{	//needed function for closing packet handler loop gracefully

	if(global != nullptr)
	{
		pcap_breakloop(global);
	}

}

string protocol_identifier(uint8_t protraw)
{

	string protocol;

	switch(protraw)
	{
	case 1:
		protocol = "ICMP";
		break;
	case 6:
		protocol = "TCP";
		break;
	case 17:
		protocol = "UDP";
		break;
	case 41:
		protocol = "IPv6";
		break;
	default:
		protocol = "unknown:" + to_string(protraw); // fallback shows the raw protocol number
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

	total_packets++;
	total_bytes += header->len;

	cout << left;
	uint16_t ethertype = (packet[12] << 8) | packet[13]; //finds ethertype (ex ipv4 vs ipv6.)

	//Outputs only if ethertype is ipv4.
	if (ethertype == 0x0800) {

		/*---------------------------------------
		   convert unix time to readable time
		---------------------------------------*/

		char timebuf[16];
		time_t secs = header->ts.tv_sec;
		tm *t = localtime(&secs);
		strftime(timebuf, sizeof(timebuf), "%I:%M:%S %p", t);
		cout << setw(18) << timebuf;
		

		/*---------------------------------------
		            find protocols
		---------------------------------------*/

		uint8_t protocol = (int)packet[23];
		cout << setw(11) << protocol_identifier(protocol);
		

		string ipflow = "";

		/*---------------------------------------
		            Find source ip adress
		---------------------------------------*/

		string srcip = "";
		for(int i=26; i<30; i++) { // ethernet layer (2) ends at byte 13, and +12 bytes to 14bytes leads to 26th byte (source ip) of ipv4 model
			srcip += to_string((int)packet[i]);
			if(i==29) break;
			srcip += ".";
		}

		/*---------------------------------------
		            Find source port #
		---------------------------------------*/
		uint16_t srcport = (packet[34] << 8) | packet[35];


		string dstip = "";
		//Destination ip adress (based on ether type).
		for(int i=30; i<34; i++) { // After byte 29, +4 is 33th byte. so 30th, 31st, 32nd and 33rd byte is destination ip adress in ipv4 model.
			dstip += to_string((int)packet[i]);
			if(i==33) break;
			dstip += ".";
		}

		/*---------------------------------------
		            destination port
		---------------------------------------*/
		uint16_t dstport = (packet[36] << 8) | packet[37];


		/*---------------------------------------
		            Ip adress + ports
		---------------------------------------*/
		ipflow += srcip;
		ipflow += ":";
		ipflow += to_string(srcport);
		ipflow += " -> ";
		ipflow += dstip;
		ipflow += ":";
		ipflow += to_string(dstport);
		cout << setw(50) << ipflow;
		

		//make sure port types only display for TCP and UDP (no port types exist for other ports!)
		if(protocol == 6 || protocol == 17){
			cout << setw(16) << port_identifier(srcport, dstport);
			
		}
		//if no port type, display no type.
		else {cout << setw(10) << "No type";
		      file << setw(10) << "No type";
		}

		/*---------------------------------------
		            Packet size (Bytes)
		---------------------------------------*/
		cout << header->len << "B";
		
		cout << endl;


	 if(file.is_open() == 1){
		file << setw(18) << timebuf;
		file << setw(11) << protocol_identifier(protocol);
		file << setw(50) << ipflow;
		file << setw(16) << port_identifier(srcport, dstport);
		file << header->len << "B" << endl;
	 }

		
	}
}

/*---------------------------------------
              Int main
---------------------------------------*/
int main(int argc, char *argv[])
{

	char *interface = nullptr;
	int count = -1;
	string save;
	string filter;

	for(int i=0; i<argc; i++) {

		string arg = argv[i];
		if(i+1 > argc) break;

		if     (arg == "-i") { if(i+1<argc) interface = argv[i+1];}
		else if(arg == "-c") { if(i+1<argc) count =     stoi(argv[i+1]);}
		else if(arg == "-s") { if(i+1<argc) save =      argv[i+1]; }
		else if(arg == "-f") { if(i+1<argc) filter =    argv[i+1]; }

		else if(arg == "-help" || arg == "-h") {
			cerr << "Options:" << endl << "Choose an interface (mandatory): ./Netsniffer -i [interface_name] ex ./Netsniffer -i eno1" << endl;
			cerr << "Set packet # limit: ./Netsniffer -i [interface_name] -c [count]" << endl;
			cerr << "Save file (.txt or .csv): ./Netsniffer -i [interface_name] -s [name_of_file.csv]" << endl;
			cerr << "Set filters (via BPF): ./Netsniffer -i [interface_name] -f [filter] ex a filter can be \"udp\", or \"tcp port 443\" in quotes only!" << endl;
			return 1;
		}
	}

	pcap_if_t *alldevs = nullptr;
	char errorbuffer[PCAP_ERRBUF_SIZE]; // stores any errors/issues.
	int interfacesuccess = pcap_findalldevs(&alldevs, errorbuffer); //Lists all network interfaces



	vector<pcap_if_t*> interfaces; //vector stores all network interfaces

	for (pcap_if_t *i = alldevs; i != nullptr; i = i->next) { //all devs = # of interfaces from linked list.
		interfaces.push_back(i);
	}

    if(interface == nullptr){
        cout << "INTERFACE NOT CHOSEN! please choose an interface with -i [interface] or run -h for help.";
		return 1;
    }


	// (interface, byte limit, promiscious mode, time out (ms), err buf) - paramaters.
	pcap_t *handle = pcap_open_live(interface, 65535, 1, 50, errorbuffer);
	global = handle;

	if (handle == nullptr) {
		cout << "Could not open network interface " << interface << errorbuffer;
		return 1;
	}

	// FILTERS
	struct bpf_program fp; //needed to get filled by pcap_compile and used by pcap_setfilter!



	if (pcap_compile(handle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
		cerr << "\nCompile error: " << pcap_geterr(handle) << endl;
		pcap_freecode(&fp);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		cerr << "\nfilter error: " << pcap_geterr(handle) << endl;
		pcap_freecode(&fp);
	}



	if(save.empty() == 0) {
		file.open(save, ios::app);


		string dash = "";
		for(int i=0; i<110; i++) dash += "-";


		file << "Timestamp"  << setw(15)
		        << "Protocol"   <<  setw(42)
		        << "Source IP:port -> Destination IP:port" << setw(18)
		        << "port type"  << setw(17)
		        << "Total size" << endl;

		file << dash << endl;

	}


	cout << "Timestamp"  << setw(15)
	     << "Protocol"   <<  setw(42)
	     << "Source IP:port -> Destination IP:port" << setw(18)
	     << "port type"  << setw(17)
	     << "Total size" << endl;

	for(int i=0; i<110; i++) cout << "-";
	cout << endl;

	signal(SIGINT, signalHandler); //gracefully closes the loop when ctrl c. (if packets are indefinetely running).

	pcap_loop(handle, count, packet_handler, nullptr); // loop handler

	/*---------------------------------------
	              Summary
	---------------------------------------*/


	cout << "---------------------------";
	cout << "\nSession summary: " << endl;
	cout << "Total packets captured: " << total_packets << endl;
	cout << "Total network data: " << total_bytes << "B" << endl;

	if(file.is_open() == 1){
		file.close();
	}



	//ending processes
	pcap_freealldevs(alldevs);
	pcap_close(handle);
	return 0;

}



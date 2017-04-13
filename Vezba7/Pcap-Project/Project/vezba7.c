// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2016/2017
// Datoteka: vezba7.c
// ================================================================

// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <pcap.h>
#include "protocol_headers.h"
#define PCAP_ERRBUFF_SIZE 1000


int packet_counter = 0;

// Function declarations
void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);
pcap_if_t* select_device(pcap_if_t* devices);

//Print data
void print_raw_data(unsigned char* data, int data_length);
// Print packet headers
void print_winpcap_header(const struct pcap_pkthdr *packet_header, int packet_counter);
void print_ethernet_header(ethernet_header* eh);
void print_ip_header(ip_header * ih);
void print_udp_header(udp_header * uh);
void print_application_data(unsigned char* data, long data_length);
void packet_handler(unsigned char *param, const struct pcap_pkthdr*
packet_header, const unsigned char* packet_data);

int main()
{
    pcap_if_t* devices;
    pcap_if_t* device;
    pcap_t* device_handle;
    char error_buffer[PCAP_ERRBUFF_SIZE];
    unsigned int netmask;
    struct bpf_program fcode;
    char filter_exp[] = "ether src b9:27:eb:e4:ce:db and ip or udp or tcp";

    int result;
    struct pcap_pkthdr* packet_header;
    const unsigned char* packet_data;

    /*List all devs -> first assignement*/
    if(pcap_findalldevs(&devices, error_buffer)==1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return -1;
    }

    device = select_device(devices);

    if(device == NULL)
    {
        pcap_freealldevs(devices);
        return -1;
    }

    /*Second assignment*/
    if((device_handle = pcap_open_live(device->name, 65536, 0, 2000, error_buffer))==NULL)
    {
        printf("\nUnable to open the adapter, %s is not supported!\n", device->name);
        pcap_freealldevs(devices);
        return -1;
    }

    /*Third assignment*/
    /*Check link layer ethernet*/
    if(pcap_datalink(device_handle) != DLT_EN10MB)
    {
        printf("\nThis program works only on Ethernet networks!\n");
        return -1;
    }

#ifdef _WIN32
	if(device->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff;
#else
    if (!device->addresses->netmask)
        netmask = 0;
    else
        netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;
#endif

    /*Fifth assignement*/
    if(pcap_compile(device_handle, &fcode, filter_exp, 1, netmask)<0)
    {
        printf("\n Unable to compile packet filter. Check the syntax!\n");
        return -1;
    }

    if(pcap_setfilter(device_handle, &fcode) < 0)
    {
        printf("\nError setting the filter!\n");
        return -1;
    }

    printf("\nListening on %s...\n", device->description);
    pcap_freealldevs(devices);
    /*Fourth assignment*/
    /*Start packet capture*/
    pcap_loop(device_handle, 5, packet_handler, NULL);

 while((result = pcap_next_ex(device_handle, &packet_header, &packet_data)) >= 0){
        ethernet_header * eh;
        ip_header* ih;
        int ip_len;
        udp_header* uh;
        unsigned char * app_data;
        int app_length;

		 // Check if timeout has elapsed
        if(result == 0)
            continue;

		// Print libpcap/WinPcap pseudo header
		print_winpcap_header(packet_header, ++packet_counter);

		/* DATA LINK LAYER - Ethernet */
		// Retrive the position of the ethernet header
        eh = (ethernet_header *)packet_data;
		// Print ethernet header
		print_ethernet_header(eh);
        // Print udp header
        print_udp_header(uh);
		/* NETWORK LAYER - IPv4 */
		// Retrieve the position of the ip header
		ih = (ip_header*) (packet_data + sizeof(ethernet_header));
		// Print ip header
		print_ip_header(ih);
		// Print udp data
		
		app_data = (unsigned char*)uh + sizeof(udp_header);//3
		app_length = ntohs(uh->datagram_length) - sizeof(uh);//4
		print_application_data(app_data, app_length);
		/* TRANSPORT LAYER - UDP */
		// Retrieve the position of the udp header
		ip_len = ih->header_length * 4; // header length is calculated using words (1 word = 4 bytes)
		uh = (udp_header*) ((unsigned char*)ih + ip_len);
		
		// For demonstration purpose
		printf("\n\nPress enter to receive new packet\n");
		getchar();
    }

    if(result == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(device_handle));
        return -1;
    }


    return 0;
}


/*Choose one of devices from which you want to read data*/
pcap_if_t* select_device(pcap_if_t* devices)
{
    int device_number;
    int i = 0; //count device num nad provide jump to selected device
    pcap_if_t* device; //iterator through device list

    for(device = devices; device; device = device->next)
    {
        printf("%.d %s", ++i, device->name); //print devices in a list
        if(device->description)
        {
            printf(" (%s)\n", device->description);
        }
        else
        {
            printf(" (No device description available!)\n");
        }
    }

    if(i == 0)
    {
        printf("\n No interfaces found!\n");
        return NULL;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &device_number);

    if(device_number <1 || device_number > i)
    {
        printf("\nInterface number out of range!\n");
        return NULL;
    }

    for(device = devices, i = 0; i < device_number - 1; device = device->next, i++);

    return device;
}


/*callback func for every incoming package*/
void packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
    time_t timestamp;
    struct tm* local_time;
    char time_string[16];
    int i, k;

    timestamp = packet_header->ts.tv_sec;
    local_time = localtime(&timestamp);
    strftime(time_string, sizeof time_string, "%H:%M:%S", local_time);

    printf("\n-----------------------------------------");
    printf("\nPacket (%d): %s, %d byte\n", ++packet_counter, time_string, packet_header->len);
    for(i = 0; i < packet_header->len; i++)
    {
        printf("%.2x ", ++packet_counter, packet_data[i]);
        k++;
        if(k % 16 == 0)
        {
            printf("\n");
       }
    }
}

void print_raw_data(unsigned char* data, int data_length)
{
    int i, k;
    printf("\n-------------------------------------------------\n\t");
    for(i = 0; i < data_length; i++)
    {
        printf("%.2x", ((unsigned char*)data)[i]);
        k++;
        if(k % 16 == 0)
        {
           printf("\n");
        }
    }
    printf("\n-------------------------------------------------\n\t");

}

// Print pseudo header which is generated by libpcap/WinPcap driver
void print_winpcap_header(const struct pcap_pkthdr* packet_header, int packet_counter)
{
    time_t timestamp;			// Raw time (bits) when packet is received 
	struct tm* local_time;		// Local time when packet is received
	char time_string[16];		// Local time converted to string

	printf("\n\n=============================================================");
	printf("\n\tlibpcap/WinPcap PSEUDO LAYER");
	printf("\n-------------------------------------------------------------");

	// Convert the timestamp to readable format
	timestamp = packet_header->ts.tv_sec;
	local_time = localtime(&timestamp);
	strftime( time_string, sizeof time_string, "%H:%M:%S", local_time);

	// Print timestamp and length of the packet
	printf("\n\tPacket number:\t\t%u", packet_counter);
	printf("\n\tTimestamp:\t\t%s.", time_string);
	printf("\n\tPacket length:\t\t%u ", packet_header->len);
	printf("\n=============================================================");
	return;
}

//Print content of Ethernet header
void print_ethernet_header(ethernet_header * eh)
{
	printf("\n=============================================================");
	printf("\n\tDATA LINK LAYER  -  Ethernet");

	print_raw_data((unsigned char*)eh, 14);

	printf("\n\tDestination address:\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eh->dest_address[0], eh->dest_address[1], eh->dest_address[2], eh->dest_address[3], eh->dest_address[4], eh->dest_address[5]);
	printf("\n\tSource address:\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eh->src_address[0], eh->src_address[1], eh->src_address[2], eh->src_address[3], eh->src_address[4], eh->src_address[5]);
	printf("\n\tNext protocol:\t\t0x%.4x", ntohs(eh->type));

	printf("\n=============================================================");

	return;
}

// Print content of ip header
void print_ip_header(ip_header * ih)
{
	printf("\n=============================================================");
	printf("\n\tNETWORK LAYER  -  Internet Protocol (IP)");

	print_raw_data((unsigned char*)ih, ih->header_length * 4);

	printf("\n\tVersion:\t\t%u", ih->version);
	printf("\n\tHeader Length:\t\t%u", ih->header_length*4);
	printf("\n\tType of Service:\t%u", ih->tos);
	printf("\n\tTotal length:\t\t%u", ntohs(ih->length));
	printf("\n\tIdentification:\t\t%u", ntohs(ih->identification));
	printf("\n\tFlags:\t\t\t%u", ntohs(ih->fragm_flags));
	printf("\n\tFragment offset:\t%u", ntohs(ih->fragm_offset));
	printf("\n\tTime-To-Live:\t\t%u", ih->ttl);
	printf("\n\tNext protocol:\t\t%u", ih->next_protocol);
	printf("\n\tHeader checkSum:\t%u", ntohs(ih->checksum));
	printf("\n\tSource:\t\t\t%u.%u.%u.%u", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);
	printf("\n\tDestination:\t\t%u.%u.%u.%u", ih->dst_addr[0], ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);

	printf("\n=============================================================");

	return;
}


void print_udp_header(udp_header * uh)
{
	printf("\n=============================================================");
	printf("\n\tNETWORK LAYER  -  UDP (UDP)");

	print_raw_data((unsigned char*)uh, 8);

    printf("\n\tSource port:\t\t%u", ntohs(uh->src_port));
    printf("\n\tDestination port:\t\t%u", ntohs(uh->dest_port));
    printf("\n\tDatagram length:\t\t%u", uh->datagram_length);
   	printf("\n=============================================================");
}

void print_application_data(unsigned char* data, long data_length)
{
	printf("\n=============================================================");
	printf("\n\tApp data:\t\t");
	print_raw_data(data, data_length);
   	printf("\n=============================================================");
}

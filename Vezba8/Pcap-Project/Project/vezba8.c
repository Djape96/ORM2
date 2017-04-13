// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2016/2017
// Datoteka: vezba8.c
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

// Function declarations
void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);

pcap_dumper_t* arp_dumper;
pcap_dumper_t* udp_dumper;
pcap_dumper_t* tcp_dumper;
pcap_dumper_t* icmp_dumper;

int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;
    char fName[] = "example.pcap";

	// Open the capture file 
	if ((device_handle = pcap_open_offline(fName, // Name of the device
								error_buffer	  // Error buffer
							)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", fName);
		return -1;
	}

	// Open the dump file 
	arp_dumper = pcap_dump_open(device_handle, "arp_packets.pcap");
	udp_dumper = pcap_dump_open(device_handle,"udp_packets.pcap");
	tcp_dumper = pcap_dump_open(device_handle,"tcp_packets.pcap");
	icmp_dumper = pcap_dump_open(device_handle,"icmp_packets.pcap");

	if (arp_dumper == NULL || udp_dumper == NULL || tcp_dumper == NULL || icmp_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity.
	if(pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	// Compile the filter
	if (pcap_compile(device_handle, &fcode, "", 1, 0xffffff) < 0)
	{
		 printf("\n Unable to compile the packet filter. Check the syntax.\n");
		 return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

	// Read and dispatch packets until EOF is reached
	pcap_loop(device_handle, 0, packet_handler, NULL);

	// Close the file associated with device_handle and deallocates resources
	pcap_close(device_handle);

	printf("\nFile: %s is successfully processed.\n", fName);

	return 0;
}

// Callback function invoked by WinPcap for every incoming packet
void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
    ethernet_header * eh;
	ip_header * ih;
	/* DATA LINK LAYER - Ethernet */
	// Retrive the position of the ethernet header
    eh = (ethernet_header *)packet_data;

	ih = (ip_header*) (packet_data + sizeof(ethernet_header));
	// ARP (Address Resolution Protocol) packets
	if (ntohs(eh->type) == 0x806)
	{
		pcap_dump((unsigned char*) arp_dumper, packet_header, packet_data);
		return;
	}
	else if(ih->next_protocol == 6)
	{
		pcap_dump((unsigned char*) tcp_dumper, packet_header, packet_data);
		return;
	}
	else if(ih->next_protocol == 17)
	{
		pcap_dump((unsigned char*) udp_dumper, packet_header, packet_data);
		return;
	}
	else if(ih->next_protocol == 1)
	{
		pcap_dump((unsigned char*) icmp_dumper, packet_header, packet_data);
		return;
	}

}
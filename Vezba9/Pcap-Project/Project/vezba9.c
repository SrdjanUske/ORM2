// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2017/2018
// Datoteka: vezba9.c
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

void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, unsigned char* packet_data);

pcap_t* device_handle_in, *device_handle_out;
pcap_send_queue* queue_udp;
pcap_send_queue* queue_tcp;

int main()
{
    int i=0;
    int device_number;
    int sentBytes;
	pcap_if_t* devices;
	pcap_if_t* device;
	char error_buffer [PCAP_ERRBUF_SIZE];
	
	/**************************************************************/
	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}
	// Count devices and provide jumping to the selected device 
	// Print the list
	for(device=devices; device; device=device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	// Check if list is empty
	if (i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	// Pick one device from the list
	printf("Enter the output interface number (1-%d):",i);
	scanf("%d", &device_number);

	if(device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return -1;
	}

	// Select the first device...
	device=devices;
	// ...and then jump to chosen devices
	for (i=0; i<device_number-1; i++)
	{
		device=device->next;
	}

	/**************************************************************/
	// Open the capture file 
	if ((device_handle_in = pcap_open_offline("example.pcap",	// File name 
								error_buffer					// Error buffer
	   )) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "example.pcap");
		return -1;
	}
	/**************************************************************/

	/**************************************************************/
	// Open the output adapter 
	if ((device_handle_out = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device->name);
		return -1;
	}
	
	// Check the link layer. We support only Ethernet for simplicity.
	if(pcap_datalink(device_handle_in) != DLT_EN10MB || pcap_datalink(device_handle_out) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}
	
	/**************************************************************/
	// Allocate a send queue 
	queue_udp = pcap_sendqueue_alloc(256*1024);	// 256 kB
	queue_tcp = pcap_sendqueue_alloc(512*1024);	// 512 kB

	/**************************************************************/
	// Fill the queue with the packets from the network
	pcap_loop(device_handle_in, 0, packet_handler, NULL);

	/**************************************************************/
	// Transmit the queue 
	// ...parameter “sync” tells if the timestamps must be respected (sync=1 (true) or sync=0 (false))

	Sleep(2000);

	if ((sentBytes = pcap_sendqueue_transmit(device_handle_out, queue_udp, 0)) < queue_udp->len)
	{
		printf("An error occurred sending the packets: %s. Only %d bytes were sent\n", pcap_geterr(device_handle_out), sentBytes);
	}

	if ((sentBytes = pcap_sendqueue_transmit(device_handle_out, queue_tcp, 1)) < queue_tcp->len)
	{
		printf("An error occurred sending the packets: %s. Only %d bytes were sent\n", pcap_geterr(device_handle_out), sentBytes);
	}

	/**************************************************************/
	// Free queues 
 	pcap_sendqueue_destroy(queue_udp);
	pcap_sendqueue_destroy(queue_tcp);
	/**************************************************************/

	/**************************************************************/
	// !!! IMPORTANT: remember to close the output adapter, otherwise there will be no guarantee that all the packets will be sent!
	pcap_close(device_handle_out);
	printf("All the packets are sent!\n");

	return 0;
}

// Callback function invoked by libpcap/WinPcap for every incoming packet
void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, unsigned char* packet_data)
{
	// Retrieve position of ethernet_header
	ethernet_header* eh;
    eh = (ethernet_header*)packet_data;

	// Check the type of next protocol in packet
	if (ntohs(eh->type) == 0x800)	// Ipv4
	{
		ip_header* ih;
        ih = (ip_header*)(packet_data + sizeof(ethernet_header));

		if(ih->next_protocol == 17) // UDP
		{
			/**************************************************************/
			// Add packet in the queue
			if (pcap_sendqueue_queue(/*(pcap_send_queue*)*/queue_udp, packet_header, packet_data) == -1)
			{
				printf("Warning: udp packet buffer too small, not all the packets will be sent.\n");
			}
			/**************************************************************/
		}
		else if(ih->next_protocol == 6) // TCP
		{
			/**************************************************************/
			// Add packet in the queue
			if (pcap_sendqueue_queue(/*(pcap_send_queue*)*/queue_tcp, packet_header, packet_data) == -1)
			{
				printf("Warning: tcp packet buffer too small, not all the packets will be sent.\n");
			}
			/**************************************************************/
		}
	}
	else if (ntohs(eh->type) == 0x806) { // ARP
		
		int i;
		for (i = 6; i < 12; i++) {
			packet_data[i] = 0x2;
		}
		
		//Send down the packet
		if (pcap_sendpacket(device_handle_out, packet_data, packet_header->len) != 0)
		{
			printf("\n Error sending the packet: %s\n", pcap_geterr(device_handle_out));
		}
	}
}
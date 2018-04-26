// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2017/2018
// Datoteka: vezba10.c
// ================================================================

// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
#endif

// Include libraries
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "conio.h"
#include "pcap.h"
#include "protocol_headers.h"

// Function declarations
void statistics_handler(unsigned char* param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);
void packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, unsigned char* packet_data);

long long bits_sec;
long long packets_sec;
long bajts;
struct timeval t_first_packet;
struct timeval t_last_packet;
int counter;

int main()
{
	pcap_if_t* devices;
	pcap_if_t* device;
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	int i=0;			// Count devices and provide jumping to the selected device 
    int device_number;
    struct bpf_program fcode;
    struct tm ltime;
	char timestr[16];
    struct timeval start_time;
    time_t t;
	int k;

	bajts = 0;
	counter = 0;
	bits_sec = 0;
	packets_sec = 0;

	printf("Odaberite zeljeni saobracaj:\n");
	printf("1. IP\n");
	printf("2. UDP\n");
	printf("3. TCP\n");
	printf("4. ARP\n");
	printf("-> ");
	scanf("%d", &k);


    // Retrieve the device list on the local machine
    if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

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
        return NULL;
    }
    
	// Pick one device from the list
    printf("Enter the interface number (1-%d):",i);
    scanf_s("%d", &device_number);
    
    if(device_number < 1 || device_number > i)
    {
        printf("\nInterface number out of range.\n");
        return NULL;
    }
    
	// Select first device...
	device = devices;

    // ...and then jump to chosen devices
    for (i=0; i<device_number-1; i++)
	{
		device = device->next;
	}


    // Open the capture device
    if ((device_handle = pcap_open_live( device->name,		// Name of the device
                              65536,						// Portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
                              1,							// Promiscuous  mode
                              2000,							// Read timeout
							  error_buffer					// Buffer where error message is stored
							) ) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
        pcap_freealldevs(devices);
        return -1;
    }
	
	// Check the link layer. We support only Ethernet for simplicity.
	if(pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	switch(k) {
		
		case 1:
			// Compile the filter
	if (pcap_compile(device_handle, &fcode, "ip", 1, 0xffffff) < 0)
	{
		 printf("\n Unable to compile the packet filter. Check the syntax.\n");
		 return -1;
	}

	printf("\nIP traffic summary:\n");
			break;
		
		case 2:
			// Compile the filter
	if (pcap_compile(device_handle, &fcode, "udp", 1, 0xffffff) < 0)
	{
		 printf("\n Unable to compile the packet filter. Check the syntax.\n");
		 return -1;
	}
	printf("\nUDP traffic summary:\n");
			break;
		
		case 3:
			// Compile the filter
	if (pcap_compile(device_handle, &fcode, "tcp", 1, 0xffffff) < 0)
	{
		 printf("\n Unable to compile the packet filter. Check the syntax.\n");
		 return -1;
	}
	printf("\nTCP traffic summary:\n");
			break;
		
		case 4:
			// Compile the filter
	if (pcap_compile(device_handle, &fcode, "arp", 1, 0xffffff) < 0)
	{
		 printf("\n Unable to compile the packet filter. Check the syntax.\n");
		 return -1;
	}
	printf("\nARP traffic summary:\n");
			break;
		
		default:
			break;
		
	}

	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

	// Set device (NIC) in statistical mode
	if (pcap_setmode(device_handle, MODE_STAT) < 0)
	{
		printf("\nError setting the mode.\n");
		 pcap_close(device_handle);
		// Free the device list 
		return 0;
	}

	
	
	// Get current time in which statistical analysis starts
	t = time(0);
	localtime_s(&ltime, &t);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
	
	// Print start time
    printf("Statistical analysis starts at: %s \n", timestr);

	start_time.tv_sec=t;
	start_time.tv_usec=0;

	// Start statistical analysis
	pcap_loop(device_handle, 15, statistics_handler, (unsigned char*)&start_time);
	
	// 3)
	printf("%I64u packets/sec, ", packets_sec / 15);
	printf("%I64u bits/sec, ", bits_sec / 15);

	// Set device (NIC) in capture mode
	if (pcap_setmode(device_handle, MODE_CAPT) < 0)
	{
		printf("\nError setting the mode.\n");
		 pcap_close(device_handle);
		// Free the device list 
		return 0;
	}

	// Start capture
	pcap_loop(device_handle, 20, packet_handler, NULL);

	// Close the device
	pcap_close(device_handle);

	return 0;
}

/* Calculates statistics */
void statistics_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	struct tm ltime;
    char timestr[16];
    unsigned int delay;
    long long packets_per_second;
    long long bits_per_second;
    time_t local_tv_sec;

	// Get last timestamp from the function argument
    struct timeval* old_ts = (struct timeval *)param;
    
    // Calculate the delay in microseconds from the last sample. 
    // This value is obtained from the timestamp that is associated with the sample. 
    delay = (packet_header->ts.tv_sec - old_ts->tv_sec) * 1000000 + packet_header->ts.tv_usec - old_ts->tv_usec;
    
	// Get the number of Packets per second 
    packets_per_second=(((*(long long*)(packet_data)) * 1000000) / (delay));

	// Get the number of bits per second 
    bits_per_second = (((*(long long*)(packet_data + 8)) * 8 * 1000000) / (delay));
    /*												       ^        ^
													       |        |
								   Converts bytes in bits --		|
							    Delay is expressed in microseconds --           
    */

	bits_sec += bits_per_second;
	packets_sec += packets_per_second;

    // Convert the timestamp to readable format 
    local_tv_sec = packet_header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

    // Print timestamp
    printf("\n%s  \n", timestr);

	// Print packets and bajts
	printf("%I64u packets, ", *(long long*)(packet_data));
	printf("%I64u bajts, ", *(long long*)(packet_data + 8));

    // Print results (bps and pps)
    //printf("%I64u bits/s, ", bits_per_second);
    //printf("%I64u packets/s\n", packets_per_second);

    // Store current timestamp
    old_ts->tv_sec=packet_header->ts.tv_sec;
    old_ts->tv_usec=packet_header->ts.tv_usec;
}

void packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, unsigned char* packet_data) {
	
	
	unsigned int delay;
	counter++;

	if (counter == 1) {
		t_first_packet = packet_header->ts;
		
	}
	else if (counter = 20) {
		t_last_packet = packet_header->ts;
		bajts += packet_header->len;

		delay = (t_last_packet.tv_sec - t_first_packet.tv_sec) * 1000000 + t_last_packet.tv_usec - t_first_packet.tv_usec;
		printf("Bytes/ sec = %d", bajts / delay);
	}

	bajts += packet_header->len;
}
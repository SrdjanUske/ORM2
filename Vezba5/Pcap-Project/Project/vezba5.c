// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2017/2018
// Datoteka: vezba5.c
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

int packet_counter = 0;	// numerates each packet

// Function declarations
pcap_if_t* select_device(pcap_if_t* devices);
void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);

int main()
{
	pcap_if_t *devices;						// List of network interface controllers
	pcap_if_t *device;						// Network interface controller
	pcap_t* device_handle;					// Descriptor of capture device
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer
	unsigned int netmask;
	
	char filter_exp[] = "dst host 10.81.31.69 and tcp";
	struct bpf_program fcode;

    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}
    
	// Chose one device from the list
	device = select_device(devices);
	
	// Check if device is valid
	if (device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}

    // Open the capture device
    if ((device_handle = pcap_open_live( device->name,		// name of the device
                              65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
                              1,							// promiscuous mode
                              500,							// read timeout
							  error_buffer					// buffer where error message is stored
							) ) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
        printf("Error: %s", error_buffer);
        pcap_freealldevs(devices);
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

	// Compile the filter
	if (pcap_compile(device_handle, &fcode, filter_exp, 1, netmask) < 0)
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

    printf("\nListening on %s...\n", device->description);
    
    // At this point, we don't need any more the device list. Free it 
    pcap_freealldevs(devices);

    // Start the capture
    pcap_loop(device_handle, 0, packet_handler, NULL);
    
    return 0;
}



// This function provide possibility to chose device from the list of available devices
pcap_if_t* select_device(pcap_if_t* devices)
{
    int device_number;
	int i=0;	// Count devices and provide jumping to the selected device 
	pcap_if_t* device;

    // Print the list
    for(device=devices; device; device=device->next)
    {
        printf("%d. %s", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No description available)\n");
    }
    
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return NULL;
    }
    
	// Pick one device from the list
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &device_number);
    
    if(device_number < 1 || device_number > i)
    {
        printf("\nInterface number out of range.\n");
        return NULL;
    }
    
     // Jump to the selected device
    for(device=devices, i=0; i< device_number-1 ;device=device->next, i++);

	return device;  
}

// Callback function invoked by WinPcap for every incoming packet
void packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	// Print timestamp and length of the packet
	time_t timestamp;			// Raw time (bits) when packet is received 
	struct tm* local_time;		// Local time when packet is received
	char time_string[16];		// Local time converted to string

	// Convert the timestamp to readable format
	timestamp = packet_header->ts.tv_sec;
	local_time = localtime(&timestamp);
	strftime( time_string, sizeof time_string, "%H:%M:%S", local_time);
	
	printf("\n-------------------------------------------");
	printf("\nPacket (%d): %s, %d byte\n", ++packet_counter, time_string, packet_header->len);
	
	int i;
	for (i = 0; i < packet_header->len; i++) {
		printf("%.2x ", packet_data[i]);
			if ((i+1) % 16 == 0) {
				printf("\n");
			}
	}
}
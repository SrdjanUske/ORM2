// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2017/2018
// Projekat: Pouzdan prenos UDP datagrama korištenjem više paralelnih tokova
// Studenti: Savo Dragovic, RA117-2015
//			 Srdjan Usorac, RA60-2015
// ================================================================

// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
	#define HAVE_STRUCT_TIMESPEC
#else
	#include <netinet/in.h>
	#include <time.h>
#endif

#define PTW32_STATIC_LIB

// Include libraries
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <time.h>
#include <pthread.h>
#include <math.h>

#include "conio.h"
#include "pcap.h"
#include "protocol_headers.h"
#include "preparing_file.h"

/* Flags */
unsigned int ethernet_stopped_at;
unsigned int wifi_stopped_at;

/* Counters for ack_handlers */
unsigned int ethernet_counter;
unsigned int wifi_counter;

/* handlers */
pcap_t* eth_handle;
pcap_t* wifi_handle;

/* all of the packets that need to be sent */
char** packets;
char** receiver;

/* received file extention name */
unsigned char received_ext[RECEIVED_FILE_EXT_LENGTH];
/* received number of packets */
unsigned char* received_num_of_packets;

FILE* file;
FILE* received_file;

unsigned char* packet_data;
unsigned char* packet_data_ethernet;
unsigned char* packet_data_wifi;
unsigned int fileSize;
unsigned int sizeOfLast;

struct timeval t_first_packet_ethernet;
struct timeval t_last_packet_ethernet;
struct timeval t_first_packet_wifi;
struct timeval t_last_packet_wifi;

unsigned int packet_count = 0;			// number of packets
unsigned long id_ext_name = 0;			// id for first two packets
unsigned long ethernet_order_num = 0;	// id for packet that is currently being sent via ethernet
unsigned long wifi_order_num = 0;		// id for packet that is currently being sent via wifi

// Function declarations
pcap_if_t* select_device(pcap_if_t* devices);
unsigned char* convert_to_char(int number, int* num_size);
void sendExtAndNum(unsigned char* data_buffer, unsigned char* packet_data, unsigned char* number_of_elements, int packet_count, char* header_name);
void ack_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data, unsigned int orderID);
void* sendEthernet(void* params);
void ack_handler_ethernet(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
void* sendWifi(void* params);
void ack_handler_wifi(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
void write_to_file();

int main()
{
	int i;
	pcap_if_t* devices;
	pcap_if_t* device_ethernet;
	pcap_if_t* device_wifi;
	unsigned char* number_of_elements;
	int number_of_digits;

	pthread_t wifiThread;
	pthread_t ethThread;

	double delay;
	unsigned int sec_first;
	unsigned int usec_first;
	unsigned int sec_last;
	unsigned int usec_last;

	char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned char data_extention[RECEIVED_FILE_EXT_LENGTH] = RECEIVED_FILE_NAME;

	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	/* Selecting ethernet interface */
	printf("Choose ETHERNET interface...\n");
	printf("----------------------------\n");
	device_ethernet = select_device(devices);
	if (device_ethernet == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}

	/* Selecting wifi interface */
	printf("\nChoose WIFI interface...\n");
	printf("----------------------------\n");
	device_wifi = select_device(devices);
	if (device_wifi == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}

	/* Open ethernet adapter (10ms timeout) */
	if ((eth_handle = pcap_open_live(device_ethernet->name, 65536, 0, 10, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device_ethernet->name);
		return -1;
	}

	/* Open wifi adapter (10ms timeout) */
	if ((wifi_handle = pcap_open_live(device_wifi->name, 65536, 0, 10, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device_wifi->name);
		return -1;
	}

	/* Check the protocol type of link layer. We only support Ethernet for simplicity */
	if (pcap_datalink(eth_handle) != DLT_EN10MB || pcap_datalink(wifi_handle) != DLT_EN10MB) // DLT_EN10MB -> Ethernet
	{ 
		printf("\nThis program works only on Ethernet networks...\n");
		pcap_freealldevs(devices);
		return -1; 
	}

	/* Reading from file FILE_NAME */
	printf("\nReading data from file...\n");
	packets = file_read(file, packets, &packet_count, &sizeOfLast);
	printf("\nSuccessfully read from file -> (%s)\n", FILE_NAME);
	fileSize = (packet_count - 1) * DEFAULT_BUFLEN + sizeOfLast;
	printf("File size is -> (%dKB)\n", fileSize / 1024 + 1);
	printf("Number of packets is -> (%d)\n", packet_count);
	
	printf("\nSending data extension and number of packets...\n");
	number_of_elements = convert_to_char(packet_count, &number_of_digits);
	printf("Total number of packets (unsigned char*): %s\n", number_of_elements);
	sendExtAndNum(data_extention, packet_data, number_of_elements, packet_count, ETHERNET_HEADER);
	printf("\nFirst 2 packets: file_extention and number_of_packets are sent via Ethernet...\n");
	printf("File extention name is -> (%s)\n", received_ext);
	printf("Number of packets is -> (%s)\n", received_num_of_packets);
	printf("Number of packets is -> (%d)\n", atoi(received_num_of_packets));

	received_file = fopen(received_ext, "wb");	
	receiver = (char**)malloc(atoi(received_num_of_packets) * sizeof(char*));

	printf("\n\nSending file via ethernet and wifi...\n");
	
	/* For conditions later in programs */
	t_first_packet_ethernet.tv_sec = 0;
	t_last_packet_ethernet.tv_sec = 0;
	t_first_packet_wifi.tv_sec = 0;
	t_last_packet_wifi.tv_sec = 0;

	ethernet_stopped_at = packet_count / 2;
	wifi_stopped_at = packet_count;

	ethernet_counter = 0;
	wifi_counter = 0;

	/* Wifi */
	pthread_create(&wifiThread, NULL, sendWifi, NULL);
	/* Ethernet */
	pthread_create(&ethThread, NULL, sendEthernet, NULL);
	
	pthread_join(ethThread, NULL);
	pthread_join(wifiThread, NULL);

	printf("\nFile is sent...\n\n");
	if (t_first_packet_wifi.tv_sec == 0 || t_last_packet_wifi.tv_sec == 0) /* Only Ethernet works */
	{
		delay = (t_last_packet_ethernet.tv_sec - t_first_packet_ethernet.tv_sec) * 1000000 + (t_last_packet_ethernet.tv_usec - t_first_packet_ethernet.tv_usec);
		printf("\nSending speed just for Ethernet is %.2lf kB / sec...\n", packet_count * DEFAULT_BUFLEN / delay / 1024 * 1000000);
	}
	else if (t_first_packet_ethernet.tv_sec == 0 || t_last_packet_ethernet.tv_sec == 0) /* Only WiFi works */
	{
		delay = (t_last_packet_wifi.tv_sec - t_first_packet_wifi.tv_sec) * 1000000 + (t_last_packet_wifi.tv_usec - t_first_packet_wifi.tv_usec);
		printf("\nSending speed just for Wifi is %.2lf kB / sec...\n", packet_count * DEFAULT_BUFLEN / delay / 1024 * 1000000);
	}
	else /* Both Wifi and Ethernet are in function */
	{
		sec_first = (t_first_packet_ethernet.tv_sec < t_first_packet_wifi.tv_sec) ? t_first_packet_ethernet.tv_sec : t_first_packet_wifi.tv_sec;
		usec_first = (t_first_packet_ethernet.tv_usec < t_first_packet_wifi.tv_usec) ? t_first_packet_ethernet.tv_usec : t_first_packet_wifi.tv_usec;
		sec_last = (t_last_packet_ethernet.tv_sec > t_last_packet_wifi.tv_sec) ? t_last_packet_ethernet.tv_sec : t_last_packet_wifi.tv_sec;
		usec_last = (t_last_packet_ethernet.tv_usec > t_last_packet_wifi.tv_usec) ? t_last_packet_ethernet.tv_usec : t_last_packet_wifi.tv_usec;
		delay = (sec_last - sec_first) * 1000000 + (usec_last - usec_first);
		printf("\nSending speed is %.2lf kB / sec...\n", packet_count * DEFAULT_BUFLEN / delay / 1024 * 1000000);
	}

	printf("Writing received information to file...\n\n");
	write_to_file();
	
	printf("THE END...\n\n");

	/* memory deallocation */
	
	for (i = 0; i < packet_count; i++) {
		free(packets[i]);
	}
	free(packets);
	
	for (i = 0; i < packet_count; i++) {
		free(receiver[i]);
	}
	free(receiver);
	fclose(received_file);
	
	/* closing adapters */
	pcap_close(eth_handle);
	pcap_close(wifi_handle);

	return 0;
}

pcap_if_t* select_device(pcap_if_t* devices)
{
	int device_number;
	int i = 0;			// Count devices and provide jumping to the selected device 
	pcap_if_t* device;

	// Print the list
	for (device = devices; device; device = device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return NULL;
	}

	// Pick one device from the list
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &device_number);

	if (device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return NULL;
	}

	// Jump to the selected device
	for (device = devices, i = 0; i< device_number - 1; device = device->next, i++);

	return device;
}

unsigned char* convert_to_char(int number, int* num_size)
{
	int i;
	unsigned char* number_of_elements;
	int malloc_size = 0;
	if (number >= 1000000)
	{
		malloc_size = 7;
	}
	else if (number >= 100000)
	{
		malloc_size = 6;
	}
	else if (number >= 10000)
	{
		malloc_size = 5;
	}
	else if (number >= 1000)
	{
		malloc_size = 4;
	}
	else if (number >= 100)
	{
		malloc_size = 3;
	}
	else if (number >= 10)
	{
		malloc_size = 2;
	}
	else
	{
		malloc_size = 1;
	}
	number_of_elements = (unsigned char*)malloc(malloc_size+1);
	for (i = 0; i < malloc_size; i++)
	{
		if (number >= 1000000 && number <= 9999999)
		{
			number_of_elements[i] = (number / 1000000 + '0');
			number %= 1000000;
		}
		else if (number >= 100000 && number < 999999)
		{
			number_of_elements[i] = (number / 100000 + '0');
			number %= 100000;
		}
		else if (number >= 10000 && number < 99999)
		{
			number_of_elements[i] = (number / 10000 + '0');
			number %= 10000;
		}
		else if (number >= 1000 && number < 10000)
		{
			number_of_elements[i] = (number / 1000 + '0');
			number %= 1000;
		}
		else if (number >= 100 && number < 1000)
		{
			number_of_elements[i] = (number / 100 + '0');
			number %= 100;
		}
		else if (number >= 10 && number < 99)
		{
			number_of_elements[i] = (number / 10 + '0');
			number %= 10;
		}
		else
		{
			number_of_elements[i] = number + '0';
		}
	}
	number_of_elements[malloc_size] = 0;
	*num_size = malloc_size + 1;
	return number_of_elements;
}

void sendExtAndNum(unsigned char* data_buffer, unsigned char* packet_data, unsigned char* number_of_elements, int packet_count, char* header_name)
{
	//Send data extention
	id_ext_name = 1;
	packet_data = setup_header(data_buffer, packet_data, strlen((const char*)data_buffer) + 1, id_ext_name, header_name);
	
	if (pcap_sendpacket(eth_handle, packet_data, strlen((const char*)data_buffer) + 1 + TOTAL_HEADER_SIZE) == -1)
	{
		printf("Packet %d not sent!\n", id_ext_name);
		return;
	}

	/* Receive ACK for current packet */
	while (pcap_loop(eth_handle, 0, ack_handler, NULL) != -2)
	{
		if (pcap_sendpacket(eth_handle, packet_data, strlen((const char*)data_buffer) + 1 + TOTAL_HEADER_SIZE) == -1)
		{
			printf("Packet %d not sent!\n", id_ext_name);
			return;
		}
	}

	//Send number of packets
	id_ext_name = 2;
	packet_data = setup_header(number_of_elements, packet_data, strlen((const char*)data_buffer) + 1, id_ext_name, header_name);

	if (pcap_sendpacket(eth_handle, packet_data, strlen((const char*)data_buffer) + 1 + TOTAL_HEADER_SIZE) == -1)
	{
		printf("Packet %d not sent!\n", id_ext_name);
		return;
	}

	/* Receive ACK for current packet */
	while (pcap_loop(eth_handle, 0, ack_handler, NULL) != -2)
	{
		if (pcap_sendpacket(eth_handle, packet_data, strlen((const char*)data_buffer) + 1 + TOTAL_HEADER_SIZE) == -1)
		{
			printf("Packet %d not sent!\n", id_ext_name);
			return;
		}
	}
}

void ack_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	int i, j;
	ethernet_header * eh;
	ip_header * ih;
	unsigned char* custom_made_header;
	unsigned long num;

	eh = (ethernet_header *)packet_data;
	if (ntohs(eh->type) != 0x800) return;

	ih = (ip_header *)(packet_data + sizeof(ethernet_header));

	if (ih->next_protocol != 17) return;
	
	custom_made_header = (unsigned char*)(packet_data + ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE);	//string
	num = (*(custom_made_header + 0) << 24) + (*(custom_made_header + 1) << 16) + (*(custom_made_header + 2) << 8) + *(custom_made_header + 3);

	if (num == 1)
	{
		for (i = 0; i < RECEIVED_FILE_EXT_LENGTH; i++)
		{
			received_ext[i] = *(custom_made_header + ORDER_NUM_CHECK + i);
		}
		pcap_breakloop(eth_handle);
	}
	else if (num == 2)
	{
		received_num_of_packets = (unsigned char*)malloc((packet_header->len - TOTAL_HEADER_SIZE)*sizeof(char));
		for (i = TOTAL_HEADER_SIZE, j = 0; i < packet_header->len; i++, j++)
		{
			received_num_of_packets[j] = packet_data[i];
		}
		pcap_breakloop(eth_handle);
	}
}

void* sendEthernet(void* params)
{
	int i,j;
	for (i = 0; i < packet_count / 2; i++)
	{
		ethernet_order_num = i + 1;

		packet_data_ethernet = setup_header((unsigned char*)packets[i], packet_data_ethernet, DEFAULT_BUFLEN, ethernet_order_num, ETHERNET_HEADER);

		if (pcap_sendpacket(eth_handle, packet_data_ethernet, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
		{
			printf("Packet %d not sent!\n", ethernet_order_num);
			printf("\n...ETHERNET KAPUT...\n\n");
			ethernet_stopped_at = ethernet_order_num - 1;
			return;
		}

		/* Receive ACK for current packet */
		while (pcap_loop(eth_handle, 0, ack_handler_ethernet, NULL) != -2 || ethernet_stopped_at != packet_count / 2)
		{
			if (pcap_sendpacket(eth_handle, packet_data_ethernet, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", ethernet_order_num);
				printf("\n...ETHERNET KAPUT...\n\n");
				ethernet_stopped_at = ethernet_order_num - 1;
				return;
			}

			ethernet_stopped_at = packet_count / 2;
		}

		if (ethernet_stopped_at != packet_count / 2)
		{
			printf("\n...ETHERNET KAPUT...\n\n");
			return;
		}
	}

	for (j = wifi_stopped_at; j < packet_count; j++)
	{
		ethernet_order_num = j + 1;

		packet_data_ethernet = setup_header((unsigned char*)packets[j], packet_data_ethernet, DEFAULT_BUFLEN, ethernet_order_num, ETHERNET_HEADER);

		if (pcap_sendpacket(eth_handle, packet_data_ethernet, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
		{
			printf("Packet %d not sent!\n", ethernet_order_num);
			printf("\n...ETHERNET KAPUT...\n\n");
			ethernet_stopped_at = ethernet_order_num - 1;
			return;	
		}

		/* Receive ACK for current packet */
		while (pcap_loop(eth_handle, 0, ack_handler_ethernet, NULL) != -2 || ethernet_stopped_at != packet_count / 2)
		{
			if (pcap_sendpacket(eth_handle, packet_data_ethernet, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", ethernet_order_num);
				printf("\n...ETHERNET KAPUT...\n\n");
				ethernet_stopped_at = ethernet_order_num - 1;
				return;	
			}

			ethernet_stopped_at = packet_count / 2;
		}

		if (ethernet_stopped_at != packet_count / 2)
		{
			printf("\n...ETHERNET KAPUT...\n\n");
			return;
		}
	}
}
void ack_handler_ethernet(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	int i, j;
	ethernet_header * eh;
	ip_header * ih;
	unsigned char* custom_made_header;
	unsigned long num;

	ethernet_counter++;

	if (ethernet_counter == 10) 
	{
		ethernet_counter = 0;

		ethernet_stopped_at = ethernet_order_num - 1;
		pcap_breakloop(eth_handle);
	}

	eh = (ethernet_header *)packet_data;
	if (ntohs(eh->type) != 0x800)
	{
		printf("ETHERNET: Not an ip packet!\n");
		return;
	}

	ih = (ip_header *)(packet_data + sizeof(ethernet_header));

	if (ih->next_protocol != 17)
	{
		printf("ETHERNET: Not an udp packet!\n");
		return;
	}

	custom_made_header = (unsigned char*)(packet_data + ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE);	//string
	num = (*(custom_made_header + 0) << 24) + (*(custom_made_header + 1) << 16) + (*(custom_made_header + 2) << 8) + *(custom_made_header + 3);

	if (num == ethernet_order_num)
	{
		ethernet_counter = 0;

		if (ethernet_order_num == 1) t_first_packet_ethernet = packet_header->ts; 
		if (ethernet_order_num == packet_count / 2)	t_last_packet_ethernet = packet_header->ts;

		receiver[num - 1] = (char*) malloc(DEFAULT_BUFLEN * sizeof(char));
		for (i = TOTAL_HEADER_SIZE, j = 0; j < (packet_header->len - TOTAL_HEADER_SIZE); i++, j++)
		{
			receiver[num - 1][j] = packet_data[i];
		}
		printf("Packet (Ethernet) number %d\n", num);
		pcap_breakloop(eth_handle);
	}
}

void* sendWifi(void* params)
{
	int i, j;
	unsigned int ack;
	for (i = packet_count / 2; i < packet_count; i++)
	{
		wifi_order_num = i + 1;

		packet_data_wifi = setup_header((unsigned char*)packets[i], packet_data_wifi, DEFAULT_BUFLEN, wifi_order_num, WIFI_HEADER);

		if (pcap_sendpacket(wifi_handle, packet_data_wifi, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
		{
			printf("Packet %d not sent!\n", wifi_order_num);				
			printf("\n...WIFI KAPUT...\n\n");
			wifi_stopped_at = wifi_order_num - 1;
			return;
		}

		/* Receive ACK for current packet */
		while (pcap_loop(wifi_handle, 0, ack_handler_wifi, NULL) != -2 || wifi_stopped_at != packet_count)
		{
			if (pcap_sendpacket(wifi_handle, packet_data_wifi, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", wifi_order_num);				
				printf("\n...WIFI KAPUT...\n\n");
				wifi_stopped_at = wifi_order_num - 1;
				return;
			}

			wifi_stopped_at = packet_count;
		}

		if (wifi_stopped_at != packet_count)
		{
			printf("\n...WIFI KAPUT...\n\n");
			return;
		}
	}

	for (j = ethernet_stopped_at; j < packet_count / 2; j++)
	{
		wifi_order_num = j + 1;

		packet_data_wifi = setup_header((unsigned char*)packets[j], packet_data_wifi, DEFAULT_BUFLEN, wifi_order_num, WIFI_HEADER);

		if (pcap_sendpacket(wifi_handle, packet_data_wifi, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
		{
			printf("Packet %d not sent!\n", wifi_order_num);				
			printf("\n...WIFI KAPUT...\n\n");
			wifi_stopped_at = wifi_order_num - 1;
			return;
		}

		/* Receive ACK for current packet */
		while (pcap_loop(wifi_handle, 0, ack_handler_wifi, NULL) != -2 || wifi_stopped_at != packet_count)
		{
			if (pcap_sendpacket(wifi_handle, packet_data_wifi, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", wifi_order_num);
				printf("\n...WIFI KAPUT...\n\n");
				wifi_stopped_at = wifi_order_num - 1;				
				return;
			}

			wifi_stopped_at = packet_count;
		}

		if (wifi_stopped_at != packet_count)
		{
			printf("\n...WIFI KAPUT...\n\n");
			return;
		}
	}
}

void ack_handler_wifi(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	int i, j;
	ethernet_header * eh;
	ip_header * ih;
	unsigned char* custom_made_header;
	unsigned long num;

	wifi_counter++;

	if (wifi_counter == 10) {
		wifi_counter = 0;
		wifi_stopped_at = wifi_order_num - 1;
		pcap_breakloop(wifi_handle);
	}

	eh = (ethernet_header *)packet_data;
	if (ntohs(eh->type) != 0x800)//ipv4 protokol-sifra
	{
		//printf("eh %x\n", ntohs(eh->type));
		//printf("WIFI: Not an ip packet!\n");
		return;
	}

	ih = (ip_header *)(packet_data + sizeof(ethernet_header));

	if (ih->next_protocol != 17)//UDP protocol
	{
		//printf("ip %d\n", ih->next_protocol);
		//printf("WIFI: Not an udp packet!\n");
		return;
	}

	custom_made_header = (unsigned char*)(packet_data + ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE);	//string
	num = (*(custom_made_header + 0) << 24) + (*(custom_made_header + 1) << 16) + (*(custom_made_header + 2) << 8) + *(custom_made_header + 3);
	
	/*if (num == 400) 
	{
		wifi_stopped_at = num - 1;
		pcap_breakloop(wifi_handle);
	}*/

	if (num == wifi_order_num)
	{
		wifi_counter = 0;

		if (wifi_order_num == packet_count / 2) t_first_packet_wifi = packet_header->ts; 
		if (wifi_order_num == packet_count)	t_last_packet_wifi = packet_header->ts;

		receiver[num - 1] = (char*) malloc(DEFAULT_BUFLEN * sizeof(char));
		for (i = TOTAL_HEADER_SIZE, j = 0; j < (packet_header->len - TOTAL_HEADER_SIZE); i++, j++)
		{
			receiver[num - 1][j] = packet_data[i];
		}
		printf("Packet (Wifi) number %d\n", num);
		pcap_breakloop(wifi_handle);
	}
}

void write_to_file()
{
	int i;
	for (i = 0; i < packet_count - 1; i++)
	{
		fwrite(receiver[i], sizeof(unsigned char), DEFAULT_BUFLEN, received_file);
	}
	fwrite(receiver[packet_count - 1], sizeof(unsigned char), sizeOfLast, received_file);
}

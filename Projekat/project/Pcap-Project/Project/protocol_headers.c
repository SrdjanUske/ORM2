#include "preparing_file.h"
#include "protocol_headers.h"

/* Srdjan adresses */
unsigned char src_ip_ethernet[] = { 169, 254, 35, 126 };
unsigned char src_mac_ethernet[] = { 0x80, 0xce, 0x62, 0x51, 0x3c, 0x40 };
/* USB Wifi address src */
unsigned char src_ip_wifi[] = { 192, 168, 43, 104 };
unsigned char src_mac_wifi[] = { 0x00, 0x0f, 0x60, 0x04, 0x5c, 0xe5 };

/* Savo adresses */
unsigned char dst_ip_ethernet[] = { 169, 254, 4, 62 };
unsigned char dst_mac_ethernet[] = { 0xac, 0xe2, 0xd3, 0xce, 0x48, 0xeb };
/* USB Wifi address dst */
unsigned char dst_ip_wifi[] = { 192, 168, 43, 141 };
unsigned char dst_mac_wifi[] = { 0x00, 0x0f, 0x60, 0x05, 0xce, 0x27 };


unsigned char next_protocol_header_ipv4[2] = { 0x08, 0x00 };
unsigned int next_protocol_header_udp = 17;

/* Function for calculating checksum */
unsigned short calculate_checksum(unsigned char* header)
{
	int i;
	unsigned int header_checksum_calc = 0;

	for (i = ETHERNET_HEADER_SIZE; i < ETHERNET_HEADER_SIZE + IP_SIZE; i += 2)
	{
		header_checksum_calc += (header[i] << 8) + header[i + 1];
	}


	while (header_checksum_calc & 0xF0000)
	{
		unsigned int temp = (header_checksum_calc >> 16) + (header_checksum_calc & 0xFFFF);
		header_checksum_calc = temp;
	}

	header_checksum_calc = ~(header_checksum_calc);

	return (unsigned short)header_checksum_calc;
}

/* Function for setting up the header:
	-> data_buffer - current packet for sending
	-> passed_header - last packet sent
	-> size_of_current_package - DEFAULT_BUFLEN or less (last packet)
	-> orderNumber - postition of the packet in file
	-> header_name - Ethernet or WiFi
*/
unsigned char* setup_header(unsigned char* data_buffer, unsigned char* passed_header, int size_of_current_package, int orderNumber, char* header_name)
{
	int i, j;
	unsigned int len;
	unsigned char* header;
	unsigned short ret_ip_checksum;
	
	if (size_of_current_package != DEFAULT_BUFLEN)
	{
		len = TOTAL_HEADER_SIZE + size_of_current_package;
	}
	else
	{
		len = TOTAL_HEADER_SIZE + DEFAULT_BUFLEN;
	}

	header = (unsigned char*)realloc(passed_header, len);
	ret_ip_checksum = 0;


	/* SETUP ETHERNET HEADER */
	if (!strcmp(header_name, ETHERNET_HEADER))
	{
		for (i = 0; i < 6; i++)
		{
			header[i] = dst_mac_ethernet[i];		// Destination address
			header[i + 6] = src_mac_ethernet[i];	// Source address
		}
	}
	else if (!strcmp(header_name, WIFI_HEADER))
	{
		for (i = 0; i < 6; i++)
		{
			header[i] = dst_mac_wifi[i];		// Destination address
			header[i + 6] = src_mac_wifi[i];	// Source address
		}
	}
	else
	{
		printf("Wrong header! Ethernet or WiFi!\n");
		return NULL;
	}
	

	/* Type of the next layer (IPv4) */
	header[12] = (unsigned char)next_protocol_header_ipv4[0];
	header[13] = (unsigned char)next_protocol_header_ipv4[1];

	/* SETUP IP HEADER */
	header[ETHERNET_HEADER_SIZE] = (unsigned char)0x45; // Version & Internet header length
	header[ETHERNET_HEADER_SIZE + 1] = (unsigned char)0x00; // Type of service
	header[ETHERNET_HEADER_SIZE + 2] = (unsigned char)(len-ETHERNET_HEADER_SIZE >> 8); // Total len in hex, first part
	header[ETHERNET_HEADER_SIZE + 3] = (unsigned char)(len - ETHERNET_HEADER_SIZE & 0xff); // Total len in hex, second part
	header[ETHERNET_HEADER_SIZE + 4] = (unsigned char)0x00; // Identification first part
	header[ETHERNET_HEADER_SIZE + 5] = (unsigned char)0x00; // Identification second part
	header[ETHERNET_HEADER_SIZE + 6] = (unsigned char)0x40; // Flags
	header[ETHERNET_HEADER_SIZE + 7] = (unsigned char)0x00; // Offset
	header[ETHERNET_HEADER_SIZE + 8] = (unsigned char)0x1e; // Time to live
	header[ETHERNET_HEADER_SIZE + 9] = (unsigned char)next_protocol_header_udp; // Protocol of the next layer (UDP)
	/* Header checksum (initial) */
	header[ETHERNET_HEADER_SIZE + 10] = 0;
	header[ETHERNET_HEADER_SIZE + 11] = 0;

	if (!strcmp(header_name, ETHERNET_HEADER))
	{
		/* Source IP address */
		header[ETHERNET_HEADER_SIZE + 12] = (unsigned char)src_ip_ethernet[0];
		header[ETHERNET_HEADER_SIZE + 13] = (unsigned char)src_ip_ethernet[1];
		header[ETHERNET_HEADER_SIZE + 14] = (unsigned char)src_ip_ethernet[2];
		header[ETHERNET_HEADER_SIZE + 15] = (unsigned char)src_ip_ethernet[3];
		/* Destination IP address */
		header[ETHERNET_HEADER_SIZE + 16] = (unsigned char)dst_ip_ethernet[0];
		header[ETHERNET_HEADER_SIZE + 17] = (unsigned char)dst_ip_ethernet[1];
		header[ETHERNET_HEADER_SIZE + 18] = (unsigned char)dst_ip_ethernet[2];
		header[ETHERNET_HEADER_SIZE + 19] = (unsigned char)dst_ip_ethernet[3];
	}
	else if (!strcmp(header_name, WIFI_HEADER))
	{
		/* Source IP address */
		header[ETHERNET_HEADER_SIZE + 12] = (unsigned char)src_ip_wifi[0];
		header[ETHERNET_HEADER_SIZE + 13] = (unsigned char)src_ip_wifi[1];
		header[ETHERNET_HEADER_SIZE + 14] = (unsigned char)src_ip_wifi[2];
		header[ETHERNET_HEADER_SIZE + 15] = (unsigned char)src_ip_wifi[3];
		/* Destination IP address */
		header[ETHERNET_HEADER_SIZE + 16] = (unsigned char)dst_ip_wifi[0];
		header[ETHERNET_HEADER_SIZE + 17] = (unsigned char)dst_ip_wifi[1];
		header[ETHERNET_HEADER_SIZE + 18] = (unsigned char)dst_ip_wifi[2];
		header[ETHERNET_HEADER_SIZE + 19] = (unsigned char)dst_ip_wifi[3];
	}
	else
	{
		printf("Wrong header! Ethernet or WiFi!\n");
		return NULL;
	}
	
	ret_ip_checksum = calculate_checksum(header);

	/* Header checksum */
	header[ETHERNET_HEADER_SIZE + 10] = (unsigned char)(ret_ip_checksum >> 8);
	header[ETHERNET_HEADER_SIZE + 11] = (unsigned char)(ret_ip_checksum & 0x00ff);

	/*SETUP UDP HEADER*/
	
	/* Source port */
	header[ETHERNET_HEADER_SIZE + IP_SIZE] = (unsigned char)(SOURCE_PORT >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 1] = (unsigned char)(SOURCE_PORT & 0x00ff);
	/* Destination port */
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 2] = (unsigned char)(DESTINATION_PORT >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 3] = (unsigned char)(DESTINATION_PORT & 0x00ff);
	/* Length of datagram including UDP header and data */
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 4] = (unsigned char)((len - IP_SIZE - ETHERNET_HEADER_SIZE) >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 5] = (unsigned char)((len - IP_SIZE - ETHERNET_HEADER_SIZE) & 0x00ff);
	/* Header checksum */
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 6] = (unsigned char) 0x00;
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 7] = (unsigned char) 0x00;


	// SETUP DATA (FIRST THE ORDER NUM, THEN THE PACKET_DATA)
	//**************************************************************************************

	for (i = (ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE); i < TOTAL_HEADER_SIZE; i++)	//len is 564
	{
		header[i] = 0;
	}
	//header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 0] = (unsigned char)((orderNumber & 0xFF00000000) >> 32);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 0] = (unsigned char)((orderNumber & 0xFF000000) >> 24);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 1] = (unsigned char)((orderNumber & 0xFF0000) >> 16);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 2] = (unsigned char)((orderNumber & 0xFF00) >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE + 3] = (unsigned char)(orderNumber & 0xFF);

	for (i = TOTAL_HEADER_SIZE, j = 0; i < len; i++, j++)
	{
		header[i] = data_buffer[j];
	}

	//**************************************************************************************

	return header;
}

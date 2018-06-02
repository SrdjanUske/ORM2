/* PROTOCOL HEADERS */
#include <stdlib.h>
#include <stdio.h>

#define ETHERNET_HEADER "Ethernet"
#define WIFI_HEADER "WiFi"
#define DESTINATION_PORT 8080
#define SOURCE_PORT 8080
#define ETHERNET_HEADER_SIZE 14
#define IP_SIZE 20
#define UDP_SIZE 8
#define ORDER_NUM_CHECK 4
#define TOTAL_HEADER_SIZE 46
 

// Ethernet header (14 bytes)
typedef struct ethernet_header{
	unsigned char dest_address[6];		// Destination address
	unsigned char src_address[6];		// Source address
	unsigned short type;				// Type of the next layer
}ethernet_header;

// IPv4 header (20 bytes)
typedef struct ip_header{
	unsigned char header_length :4;	// Internet header length (4 bits)
	unsigned char version :4;		// Version (4 bits)
	unsigned char tos;				// Type of service 
	unsigned short length;			// Total length 
	unsigned short identification;	// Identification
	unsigned short fragm_flags :3;  // Flags (3 bits) & Fragment offset (13 bits)
    unsigned short fragm_offset :13;// Flags (3 bits) & Fragment offset (13 bits)
	unsigned char ttl;				// Time to live
	unsigned char next_protocol;	// Protocol of the next layer
	unsigned short checksum;		// Header checksum
	unsigned char src_addr[4];		// Source address
	unsigned char dst_addr[4];		// Destination address
	unsigned int options_padding;	// Option + Padding
		// + variable part of the header
}ip_header;

//UDP header (8 bytes)
typedef struct udp_header{
	unsigned short src_port;		// Source port
	unsigned short dest_port;		// Destination port
	unsigned short datagram_length;	// Length of datagram including UDP header and data
	unsigned short checksum;		// Header checksum
}udp_header;

// TCP header
typedef struct tcp_header {
	unsigned short src_port;			// Source port
	unsigned short dest_port;			// Destination port
	unsigned int sequence_num;			// Sequence Number
	unsigned int ack_num;				// Acknowledgement number
	unsigned char reserved :4;			// Reserved for future use (4 bits) 
	unsigned char header_length :4;		// Header length (4 bits)
	unsigned char flags;				// Packet flags
	unsigned short windows_size;		// Window size
	unsigned short checksum;			// Header Checksum
	unsigned short urgent_pointer;		// Urgent pointer
	// + variable part of the header
} tcp_header;

/*Functions*/
unsigned short calculate_checksum(unsigned char* header);
unsigned char* setup_header(unsigned char* data_buffer, unsigned char* passed_header, int size_of_current_package, int orderNumber, char* header_name);
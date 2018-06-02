#include "preparing_file.h"

char** file_read(FILE* file, char** packets, unsigned int* packets_num, unsigned int* size_of_last_packet)
{
		int i;
        long length = 0;            /* length of file in bytes */
        int remain = 0;             /* length of the last packet in bytes */
        int num_of_packets = 0;     /* number of packets for sending */

        // opening file in mode "rb" because it's not a text file */
		file = fopen(FILE_NAME, "rb");
		if (file == NULL)
		{
			printf("Can't open file: %s!\n", FILE_NAME);
			return NULL;
		}

		/* searching for end of file */
		fseek(file, 0, SEEK_END);

		/* get the current value of the position indicator (file length in bytes) */
		length = ftell(file);
        num_of_packets = (length / DEFAULT_BUFLEN) + 1;
        remain = length % DEFAULT_BUFLEN;

        /* memory allocation for packets */
        packets = (char**)malloc(num_of_packets * sizeof(char*));
        *packets_num = num_of_packets;
        *size_of_last_packet = remain;

        /* set the position of file at begin, to read packet for packet */
        rewind(file);

        /* reading packet info */
        for (i = 0; i < num_of_packets; i++)
        {
            packets[i] = (char*)malloc(DEFAULT_BUFLEN * sizeof(char));
            fread(packets[i], 1, DEFAULT_BUFLEN, file);
        }

        fclose(file);
        return packets;
}

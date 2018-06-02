#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// default size of packet (in bytes)
#define DEFAULT_BUFLEN 994
#define FILE_NAME "lena_noise.bmp"
#define RECEIVED_FILE_NAME "output.bmp"
#define RECEIVED_FILE_EXT_LENGTH 11

// function for opening a file and preparing packets for sending
char ** file_read(FILE*, char**, unsigned int*, unsigned int*);
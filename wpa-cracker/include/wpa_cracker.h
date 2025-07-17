#ifndef WPA_CRACKER_H
#define WPA_CRACKER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// Function prototypes from handshake.c
int parse_handshake(const char *filename);

// Function prototypes from wordlist.c
int read_wordlist(const char *filename);

// Function prototypes from crypto.c
void crack_handshake(void);

// Function prototypes from utils.c
void print_hex(const unsigned char *data, size_t len);

#endif // WPA_CRACKER_H

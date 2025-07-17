#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../include/wpa_cracker.h"

void print_usage() {
    printf("Usage: ./wpa-cracker -f <handshake.cap> -w <wordlist.txt> [-t <threads>] [--gpu]\n");
}

int main(int argc, char *argv[]) {
    char *handshake_file = NULL;
    char *wordlist_file = NULL;
    int threads = 1;
    int use_gpu = 0;
    int opt;

    while ((opt = getopt(argc, argv, "f:w:t:")) != -1) {
        switch (opt) {
            case 'f':
                handshake_file = optarg;
                break;
            case 'w':
                wordlist_file = optarg;
                break;
            case 't':
                threads = atoi(optarg);
                break;
            case '?':
                print_usage();
                return 1;
            default:
                print_usage();
                return 1;
        }
    }

    if (handshake_file == NULL || wordlist_file == NULL) {
        print_usage();
        return 1;
    }

    printf("Handshake file: %s\n", handshake_file);
    printf("Wordlist file: %s\n", wordlist_file);
    printf("Threads: %d\n", threads);
    printf("GPU: %s\n", use_gpu ? "Enabled" : "Disabled");

    // Main logic will go here

    return 0;
}

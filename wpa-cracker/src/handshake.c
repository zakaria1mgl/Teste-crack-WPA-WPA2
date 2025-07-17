#include "../include/wpa_cracker.h"

int parse_handshake(const char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_offline() failed: %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) {
            // Timeout elapsed
            continue;
        }
        printf("Packet captured with length: %d\n", header->len);
    }

    if (res == -1) {
        fprintf(stderr, "pcap_next_ex() failed: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);
    return 0;
}

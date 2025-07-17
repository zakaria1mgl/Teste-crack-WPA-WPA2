/**
 * handshake.c
 * Functions for reading and parsing WPA/WPA2 handshakes from pcap files
 */

#include "../include/wpa_cracker.h"

/* EAPOL frame offset constants */
#define RADIOTAP_HEADER_MIN_LENGTH 8
#define DOT11_HEADER_LENGTH 24
#define LLC_HEADER_LENGTH 8
#define EAPOL_HEADER_LENGTH 4

/* 802.11 frame types */
#define DOT11_TYPE_DATA 0x08

/* LLC SNAP header for EAPOL */
static const uint8_t EAPOL_LLC_HEADER[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};

/**
 * Extract MAC addresses from an 802.11 data frame
 */
static void extract_mac_addresses(const uint8_t *frame, uint8_t *mac_ap, uint8_t *mac_client) {
    uint8_t frame_control = frame[0];
    uint8_t direction = (frame_control & 0x03);
    
    /* MAC addresses are at different positions depending on the direction */
    switch (direction) {
        case 0: /* ToDS=0, FromDS=0 (Ad Hoc) */
            memcpy(mac_ap, frame + 16, MAC_ADDR_LENGTH);      /* BSSID */
            memcpy(mac_client, frame + 10, MAC_ADDR_LENGTH);  /* Source */
            break;
        case 1: /* ToDS=1, FromDS=0 (To AP) */
            memcpy(mac_ap, frame + 4, MAC_ADDR_LENGTH);       /* Destination */
            memcpy(mac_client, frame + 10, MAC_ADDR_LENGTH);  /* Source */
            break;
        case 2: /* ToDS=0, FromDS=1 (From AP) */
            memcpy(mac_ap, frame + 10, MAC_ADDR_LENGTH);      /* Source */
            memcpy(mac_client, frame + 4, MAC_ADDR_LENGTH);   /* Destination */
            break;
        case 3: /* ToDS=1, FromDS=1 (WDS) */
            /* Not typically used in WPA handshakes */
            memcpy(mac_ap, frame + 10, MAC_ADDR_LENGTH);      /* Transmitter */
            memcpy(mac_client, frame + 16, MAC_ADDR_LENGTH);  /* Receiver */
            break;
    }
}

/**
 * Extract the EAPOL frame from a packet
 */
static bool extract_eapol(const uint8_t *packet, size_t packet_length, 
                         uint8_t *eapol, size_t *eapol_length, 
                         uint8_t *mac_ap, uint8_t *mac_client) {
    
    /* Skip past the radiotap header */
    if (packet_length < RADIOTAP_HEADER_MIN_LENGTH) {
        return false;
    }
    
    uint16_t radiotap_length = packet[2] | (packet[3] << 8);
    if (packet_length < radiotap_length + DOT11_HEADER_LENGTH + LLC_HEADER_LENGTH) {
        return false;
    }
    
    const uint8_t *dot11_frame = packet + radiotap_length;
    
    /* Check if it's a data frame */
    if ((dot11_frame[0] & 0x0C) != DOT11_TYPE_DATA) {
        return false;
    }
    
    /* Extract MAC addresses */
    extract_mac_addresses(dot11_frame, mac_ap, mac_client);
    
    /* Check for LLC SNAP header for EAPOL */
    const uint8_t *llc = dot11_frame + DOT11_HEADER_LENGTH;
    if (memcmp(llc, EAPOL_LLC_HEADER, LLC_HEADER_LENGTH) != 0) {
        return false;
    }
    
    /* Extract EAPOL frame */
    const uint8_t *eapol_start = llc + LLC_HEADER_LENGTH;
    *eapol_length = packet_length - (eapol_start - packet);
    
    if (*eapol_length > EAPOL_MAX_LENGTH) {
        *eapol_length = EAPOL_MAX_LENGTH;
    }
    
    memcpy(eapol, eapol_start, *eapol_length);
    
    return true;
}

/**
 * Extract the key nonce from an EAPOL frame
 */
static bool extract_nonce(const uint8_t *eapol, size_t eapol_length, uint8_t *nonce) {
    /* Check minimum EAPOL length for a key frame */
    if (eapol_length < 95) {
        return false;
    }
    
    /* Check if it's a key frame */
    if (eapol[0] != 0x01 || eapol[1] != 0x03) {
        return false;
    }
    
    /* Extract the nonce (located at offset 17 in the key data) */
    memcpy(nonce, eapol + 17, NONCE_LENGTH);
    return true;
}

/**
 * Extract the MIC from an EAPOL frame
 */
static bool extract_mic(const uint8_t *eapol, size_t eapol_length, uint8_t *mic) {
    /* Check minimum EAPOL length for a key frame with MIC */
    if (eapol_length < 95) {
        return false;
    }
    
    /* Check if it's a key frame */
    if (eapol[0] != 0x01 || eapol[1] != 0x03) {
        return false;
    }
    
    /* Check if MIC is set (bit 0x80 in key info) */
    uint16_t key_info = (eapol[5] << 8) | eapol[6];
    if (!(key_info & 0x0100)) {
        return false;
    }
    
    /* Extract the MIC (located at offset 81 in the key data) */
    memcpy(mic, eapol + 81, MIC_LENGTH);
    return true;
}

/**
 * Extract the SSID from a beacon frame
 */
static bool extract_ssid(const uint8_t *packet, size_t packet_length, 
                        uint8_t *ssid, size_t *ssid_length) {
    /* Skip past the radiotap header */
    if (packet_length < RADIOTAP_HEADER_MIN_LENGTH) {
        return false;
    }
    
    uint16_t radiotap_length = packet[2] | (packet[3] << 8);
    if (packet_length < radiotap_length + 24) { /* 24 = minimum beacon frame size */
        return false;
    }
    
    const uint8_t *dot11_frame = packet + radiotap_length;
    
    /* Check if it's a beacon frame (type=0, subtype=8) */
    if (dot11_frame[0] != 0x80) {
        return false;
    }
    
    /* Skip fixed beacon frame parameters (12 bytes after the 24-byte header) */
    const uint8_t *tags = dot11_frame + 24 + 12;
    size_t tags_length = packet_length - (tags - packet);
    
    /* Look for the SSID tag (tag number 0) */
    size_t i = 0;
    while (i < tags_length - 2) {
        uint8_t tag_number = tags[i];
        uint8_t tag_length = tags[i + 1];
        
        if (tag_number == 0 && tag_length <= MAX_SSID_LENGTH) {
            *ssid_length = tag_length;
            memcpy(ssid, tags + i + 2, tag_length);
            return true;
        }
        
        i += tag_length + 2;
    }
    
    return false;
}

/**
 * Process a packet and update the handshake information if relevant
 */
static void process_packet(const uint8_t *packet, size_t packet_length, wpa_handshake_t *handshake) {
    uint8_t eapol[EAPOL_MAX_LENGTH];
    size_t eapol_length;
    uint8_t mac_ap[MAC_ADDR_LENGTH];
    uint8_t mac_client[MAC_ADDR_LENGTH];
    uint8_t nonce[NONCE_LENGTH];
    uint8_t mic[MIC_LENGTH];
    uint8_t ssid[MAX_SSID_LENGTH];
    size_t ssid_length;
    
    /* Try to extract SSID from beacon frames */
    if (extract_ssid(packet, packet_length, ssid, &ssid_length)) {
        if (handshake->ssid_length == 0) {
            memcpy(handshake->ssid, ssid, ssid_length);
            handshake->ssid_length = ssid_length;
        }
        return;
    }
    
    /* Try to extract EAPOL frame */
    if (!extract_eapol(packet, packet_length, eapol, &eapol_length, mac_ap, mac_client)) {
        return;
    }
    
    /* If this is the first EAPOL frame, initialize the MAC addresses */
    if (handshake->eapol_length == 0) {
        memcpy(handshake->mac_ap, mac_ap, MAC_ADDR_LENGTH);
        memcpy(handshake->mac_client, mac_client, MAC_ADDR_LENGTH);
    }
    
    /* Check if this packet matches our handshake's MAC addresses */
    if (memcmp(handshake->mac_ap, mac_ap, MAC_ADDR_LENGTH) != 0 ||
        memcmp(handshake->mac_client, mac_client, MAC_ADDR_LENGTH) != 0) {
        return;
    }
    
    /* Try to extract nonce */
    if (extract_nonce(eapol, eapol_length, nonce)) {
        /* Determine if it's ANonce or SNonce based on sender */
        if (memcmp(mac_ap, handshake->mac_ap, MAC_ADDR_LENGTH) == 0) {
            /* From AP to client: ANonce */
            memcpy(handshake->anonce, nonce, NONCE_LENGTH);
        } else {
            /* From client to AP: SNonce */
            memcpy(handshake->snonce, nonce, NONCE_LENGTH);
        }
    }
    
    /* Try to extract MIC */
    if (extract_mic(eapol, eapol_length, mic)) {
        /* Save the EAPOL frame and MIC */
        memcpy(handshake->eapol, eapol, eapol_length);
        handshake->eapol_length = eapol_length;
        memcpy(handshake->mic, mic, MIC_LENGTH);
        
        /* Zero out the MIC in the saved EAPOL frame (for verification later) */
        memset(handshake->eapol + 81, 0, MIC_LENGTH);
    }
    
    /* Check if we have a complete handshake */
    if (handshake->ssid_length > 0 &&
        !is_zero(handshake->anonce, NONCE_LENGTH) &&
        !is_zero(handshake->snonce, NONCE_LENGTH) &&
        handshake->eapol_length > 0 &&
        !is_zero(handshake->mic, MIC_LENGTH)) {
        handshake->valid = true;
    }
}

/**
 * Check if a buffer contains only zeros
 */
static bool is_zero(const uint8_t *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (buffer[i] != 0) {
            return false;
        }
    }
    return true;
}

/**
 * Read a handshake from a pcap file
 */
bool read_handshake(const char *filename, wpa_handshake_t *handshake) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    
    /* Initialize the handshake structure */
    memset(handshake, 0, sizeof(wpa_handshake_t));
    
    /* Open the pcap file */
    pcap = pcap_open_offline(filename, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return false;
    }
    
    /* Process each packet */
    while ((packet = pcap_next(pcap, &header)) != NULL) {
        process_packet(packet, header.caplen, handshake);
        
        /* If we have a valid handshake, we can stop */
        if (handshake->valid) {
            break;
        }
    }
    
    /* Clean up */
    pcap_close(pcap);
    
    return handshake->valid;
}

/**
 * Print information about a handshake
 */
void print_handshake_info(const wpa_handshake_t *handshake) {
    char mac_ap_str[18];
    char mac_client_str[18];
    
    mac_to_string(handshake->mac_ap, mac_ap_str);
    mac_to_string(handshake->mac_client, mac_client_str);
    
    printf("Handshake Information:\n");
    printf("  Valid: %s\n", handshake->valid ? "Yes" : "No");
    printf("  SSID: ");
    for (size_t i = 0; i < handshake->ssid_length; i++) {
        printf("%c", handshake->ssid[i]);
    }
    printf("\n");
    printf("  AP MAC: %s\n", mac_ap_str);
    printf("  Client MAC: %s\n", mac_client_str);
    printf("  ANonce: ");
    print_hex(handshake->anonce, NONCE_LENGTH);
    printf("\n  SNonce: ");
    print_hex(handshake->snonce, NONCE_LENGTH);
    printf("\n  MIC: ");
    print_hex(handshake->mic, MIC_LENGTH);
    printf("\n");
}
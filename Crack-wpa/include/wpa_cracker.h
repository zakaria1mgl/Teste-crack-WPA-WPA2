/**
 * WPA/WPA2 Handshake Cracker
 * Header file containing all declarations
 */

#ifndef WPA_CRACKER_H
#define WPA_CRACKER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <pcap.h>

/* Constants */
#define MAX_SSID_LENGTH 32
#define MAC_ADDR_LENGTH 6
#define PMK_LENGTH 32
#define PTK_LENGTH 64
#define MIC_LENGTH 16
#define NONCE_LENGTH 32
#define MAX_PASSWORD_LENGTH 64
#define EAPOL_MAX_LENGTH 256

/* Structures */
typedef struct {
    uint8_t mac_ap[MAC_ADDR_LENGTH];      /* MAC address of the access point */
    uint8_t mac_client[MAC_ADDR_LENGTH];   /* MAC address of the client */
    uint8_t ssid[MAX_SSID_LENGTH];         /* SSID of the network */
    size_t ssid_length;                    /* Length of the SSID */
    uint8_t anonce[NONCE_LENGTH];          /* Authenticator nonce */
    uint8_t snonce[NONCE_LENGTH];          /* Supplicant nonce */
    uint8_t eapol[EAPOL_MAX_LENGTH];       /* EAPOL frame data */
    size_t eapol_length;                   /* Length of EAPOL data */
    uint8_t mic[MIC_LENGTH];               /* Message Integrity Code */
    bool valid;                            /* Whether the handshake is valid */
} wpa_handshake_t;

typedef struct {
    char *filename;                        /* Path to the wordlist file */
    FILE *file;                            /* File handle */
    char *buffer;                          /* Memory mapped region or buffer */
    size_t buffer_size;                    /* Size of the buffer */
    size_t position;                       /* Current position in the buffer */
    pthread_mutex_t mutex;                 /* Mutex for thread safety */
} wordlist_t;

typedef struct {
    wpa_handshake_t *handshake;           /* Pointer to the handshake data */
    wordlist_t *wordlist;                  /* Pointer to the wordlist */
    int thread_id;                         /* Thread identifier */
    int num_threads;                       /* Total number of threads */
    bool *password_found;                  /* Flag indicating if password was found */
    char *found_password;                  /* Buffer to store the found password */
    pthread_mutex_t *result_mutex;         /* Mutex for accessing result */
    bool use_gpu;                          /* Whether to use GPU acceleration */
    volatile bool *stop_flag;              /* Flag to stop all threads */
} crack_job_t;

/* Function prototypes */

/* handshake.c */
bool read_handshake(const char *filename, wpa_handshake_t *handshake);
void print_handshake_info(const wpa_handshake_t *handshake);

/* wordlist.c */
wordlist_t* wordlist_open(const char *filename);
bool wordlist_get_next(wordlist_t *wordlist, char *password, size_t max_length);
void wordlist_close(wordlist_t *wordlist);

/* crypto.c */
bool calculate_pmk(const uint8_t *passphrase, size_t passphrase_length,
                  const uint8_t *ssid, size_t ssid_length, uint8_t *pmk);
bool calculate_ptk(const uint8_t *pmk, const uint8_t *mac_ap, const uint8_t *mac_client,
                  const uint8_t *anonce, const uint8_t *snonce, uint8_t *ptk, size_t ptk_length);
bool verify_mic(const uint8_t *ptk, const uint8_t *eapol, size_t eapol_length,
                const uint8_t *mic);

/* utils.c */
void print_hex(const uint8_t *data, size_t length);
void print_progress(uint64_t tested_passwords, uint64_t total_passwords, double elapsed_time);
void mac_to_string(const uint8_t *mac, char *str);
bool string_to_mac(const char *str, uint8_t *mac);

/* main.c */
void* crack_thread(void *arg);
#ifdef USE_CUDA
bool init_cuda();
void cleanup_cuda();
bool crack_with_cuda(wpa_handshake_t *handshake, const char *password, size_t password_length);
#endif

#endif /* WPA_CRACKER_H */
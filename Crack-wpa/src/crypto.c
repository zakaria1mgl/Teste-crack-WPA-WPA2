/**
 * crypto.c
 * Cryptographic functions for WPA/WPA2 handshake cracking
 */

#include "../include/wpa_cracker.h"

/* PBKDF2 iteration count for WPA/WPA2 */
#define PBKDF2_ITERATIONS 4096

/**
 * Calculate the PMK (Pairwise Master Key) from the passphrase and SSID
 * using PBKDF2-SHA1
 */
bool calculate_pmk(const uint8_t *passphrase, size_t passphrase_length,
                  const uint8_t *ssid, size_t ssid_length, uint8_t *pmk) {
    if (passphrase == NULL || ssid == NULL || pmk == NULL ||
        passphrase_length == 0 || ssid_length == 0 || ssid_length > MAX_SSID_LENGTH) {
        return false;
    }
    
    /* Use OpenSSL's PKCS5_PBKDF2_HMAC_SHA1 function */
    PKCS5_PBKDF2_HMAC_SHA1(
        (const char *)passphrase,
        passphrase_length,
        (const unsigned char *)ssid,
        ssid_length,
        PBKDF2_ITERATIONS,
        PMK_LENGTH,
        pmk
    );
    
    return true;
}

/**
 * PRF (Pseudo-Random Function) for WPA/WPA2 key derivation
 */
static void prf_sha1(const uint8_t *key, size_t key_length,
                    const uint8_t *prefix, size_t prefix_length,
                    const uint8_t *data, size_t data_length,
                    uint8_t *output, size_t output_length) {
    HMAC_CTX *ctx;
    unsigned int hmac_length;
    uint8_t counter = 0;
    uint8_t *buffer;
    size_t buffer_length;
    size_t offset = 0;
    
    /* Allocate a buffer for the HMAC input */
    buffer_length = prefix_length + data_length + 1; /* +1 for the counter */
    buffer = (uint8_t *)malloc(buffer_length);
    if (buffer == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        return;
    }
    
    /* Copy the prefix and data into the buffer */
    memcpy(buffer, prefix, prefix_length);
    memcpy(buffer + prefix_length, data, data_length);
    
    /* Initialize the HMAC context */
    ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: Could not create HMAC context\n");
        free(buffer);
        return;
    }
    
    /* Generate the required amount of key material */
    while (offset < output_length) {
        /* Set the counter */
        counter++;
        buffer[buffer_length - 1] = counter;
        
        /* Calculate the HMAC */
        HMAC_Init_ex(ctx, key, key_length, EVP_sha1(), NULL);
        HMAC_Update(ctx, buffer, buffer_length);
        
        /* Copy the result to the output buffer */
        if (offset + SHA_DIGEST_LENGTH <= output_length) {
            HMAC_Final(ctx, output + offset, &hmac_length);
            offset += hmac_length;
        } else {
            uint8_t temp[SHA_DIGEST_LENGTH];
            HMAC_Final(ctx, temp, &hmac_length);
            memcpy(output + offset, temp, output_length - offset);
            offset = output_length;
        }
        
        /* Reset the HMAC context for the next iteration */
        HMAC_CTX_reset(ctx);
    }
    
    /* Clean up */
    HMAC_CTX_free(ctx);
    free(buffer);
}

/**
 * Calculate the PTK (Pairwise Transient Key) from the PMK and handshake data
 */
bool calculate_ptk(const uint8_t *pmk, const uint8_t *mac_ap, const uint8_t *mac_client,
                  const uint8_t *anonce, const uint8_t *snonce, uint8_t *ptk, size_t ptk_length) {
    if (pmk == NULL || mac_ap == NULL || mac_client == NULL ||
        anonce == NULL || snonce == NULL || ptk == NULL) {
        return false;
    }
    
    /* Allocate a buffer for the PRF data */
    uint8_t *data = (uint8_t *)malloc(2 * MAC_ADDR_LENGTH + 2 * NONCE_LENGTH);
    if (data == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        return false;
    }
    
    /* Determine the minimum of the two MAC addresses */
    const uint8_t *mac1, *mac2;
    if (memcmp(mac_ap, mac_client, MAC_ADDR_LENGTH) < 0) {
        mac1 = mac_ap;
        mac2 = mac_client;
    } else {
        mac1 = mac_client;
        mac2 = mac_ap;
    }
    
    /* Determine the minimum of the two nonces */
    const uint8_t *nonce1, *nonce2;
    if (memcmp(anonce, snonce, NONCE_LENGTH) < 0) {
        nonce1 = anonce;
        nonce2 = snonce;
    } else {
        nonce1 = snonce;
        nonce2 = anonce;
    }
    
    /* Construct the PRF data: min(AA, SA) || max(AA, SA) || min(ANonce, SNonce) || max(ANonce, SNonce) */
    memcpy(data, mac1, MAC_ADDR_LENGTH);
    memcpy(data + MAC_ADDR_LENGTH, mac2, MAC_ADDR_LENGTH);
    memcpy(data + 2 * MAC_ADDR_LENGTH, nonce1, NONCE_LENGTH);
    memcpy(data + 2 * MAC_ADDR_LENGTH + NONCE_LENGTH, nonce2, NONCE_LENGTH);
    
    /* Calculate the PTK using the PRF */
    const uint8_t prefix[] = "Pairwise key expansion";
    prf_sha1(pmk, PMK_LENGTH, prefix, sizeof(prefix) - 1, data, 2 * MAC_ADDR_LENGTH + 2 * NONCE_LENGTH, ptk, ptk_length);
    
    /* Clean up */
    free(data);
    
    return true;
}

/**
 * Verify the MIC (Message Integrity Code) of an EAPOL frame
 */
bool verify_mic(const uint8_t *ptk, const uint8_t *eapol, size_t eapol_length, const uint8_t *mic) {
    if (ptk == NULL || eapol == NULL || mic == NULL) {
        return false;
    }
    
    /* The MIC key is located at offset 0 in the PTK */
    const uint8_t *mic_key = ptk;
    
    /* Calculate the MIC */
    uint8_t calculated_mic[MIC_LENGTH];
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: Could not create HMAC context\n");
        return false;
    }
    
    /* Initialize the HMAC context with the MIC key */
    HMAC_Init_ex(ctx, mic_key, 16, EVP_sha1(), NULL);
    
    /* Update with the EAPOL frame data */
    HMAC_Update(ctx, eapol, eapol_length);
    
    /* Finalize the HMAC */
    unsigned int hmac_length;
    HMAC_Final(ctx, calculated_mic, &hmac_length);
    
    /* Clean up */
    HMAC_CTX_free(ctx);
    
    /* Compare the calculated MIC with the provided MIC */
    return (memcmp(calculated_mic, mic, MIC_LENGTH) == 0);
}

#ifdef USE_CUDA
/* CUDA implementation would go here */
#include "crypto_cuda.c"
#endif
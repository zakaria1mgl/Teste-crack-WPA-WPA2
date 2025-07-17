/**
 * utils.c
 * Utility functions for the WPA/WPA2 handshake cracker
 */

#include "../include/wpa_cracker.h"
#include <time.h>
#include <ctype.h>

/**
 * Print binary data in hexadecimal format
 */
void print_hex(const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < length) {
            printf("\n");
        } else if ((i + 1) % 4 == 0 && i + 1 < length) {
            printf(" ");
        }
    }
}

/**
 * Print progress information
 */
void print_progress(uint64_t tested_passwords, uint64_t total_passwords, double elapsed_time) {
    double percentage = 0.0;
    double passwords_per_second = 0.0;
    double estimated_time_remaining = 0.0;
    char progress_bar[51] = {0};
    int bar_width = 50;
    int pos = 0;
    
    /* Calculate percentage */
    if (total_passwords > 0) {
        percentage = 100.0 * tested_passwords / total_passwords;
    }
    
    /* Calculate passwords per second */
    if (elapsed_time > 0.0) {
        passwords_per_second = tested_passwords / elapsed_time;
    }
    
    /* Calculate estimated time remaining */
    if (passwords_per_second > 0.0 && total_passwords > tested_passwords) {
        estimated_time_remaining = (total_passwords - tested_passwords) / passwords_per_second;
    }
    
    /* Create progress bar */
    if (total_passwords > 0) {
        pos = bar_width * tested_passwords / total_passwords;
    }
    
    for (int i = 0; i < bar_width; i++) {
        if (i < pos) {
            progress_bar[i] = '=';
        } else if (i == pos) {
            progress_bar[i] = '>';
        } else {
            progress_bar[i] = ' ';
        }
    }
    progress_bar[bar_width] = '\0';
    
    /* Print progress information */
    printf("\r[%s] %.2f%% %lu/%lu (%.2f p/s) ETA: %.2f s", 
           progress_bar, percentage, tested_passwords, total_passwords,
           passwords_per_second, estimated_time_remaining);
    fflush(stdout);
}

/**
 * Convert a MAC address to a string
 */
void mac_to_string(const uint8_t *mac, char *str) {
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/**
 * Convert a string to a MAC address
 */
bool string_to_mac(const char *str, uint8_t *mac) {
    unsigned int values[6];
    int count;
    
    count = sscanf(str, "%x:%x:%x:%x:%x:%x",
                   &values[0], &values[1], &values[2],
                   &values[3], &values[4], &values[5]);
    
    if (count != 6) {
        return false;
    }
    
    for (int i = 0; i < 6; i++) {
        if (values[i] > 255) {
            return false;
        }
        mac[i] = (uint8_t)values[i];
    }
    
    return true;
}

/**
 * Check if a string is a valid hexadecimal string
 */
bool is_hex_string(const char *str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        if (!isxdigit((unsigned char)str[i])) {
            return false;
        }
    }
    return true;
}

/**
 * Convert a hexadecimal string to binary data
 */
bool hex_to_bytes(const char *hex, uint8_t *bytes, size_t length) {
    size_t hex_length = strlen(hex);
    
    if (hex_length != length * 2) {
        return false;
    }
    
    for (size_t i = 0; i < length; i++) {
        unsigned int value;
        if (sscanf(hex + i * 2, "%2x", &value) != 1) {
            return false;
        }
        bytes[i] = (uint8_t)value;
    }
    
    return true;
}

/**
 * Get the current time in seconds with microsecond precision
 */
double get_time() {
#ifdef _WIN32
    /* Windows implementation */
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    
    return (double)counter.QuadPart / (double)frequency.QuadPart;
#else
    /* Unix/Linux implementation */
    struct timespec ts;
    
    clock_gettime(CLOCK_MONOTONIC, &ts);
    
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
#endif
}

/**
 * Count the number of lines in a file
 */
uint64_t count_lines(const char *filename) {
    FILE *file;
    uint64_t count = 0;
    int ch;
    bool empty_line = true;
    
    file = fopen(filename, "rb");
    if (file == NULL) {
        return 0;
    }
    
    while ((ch = fgetc(file)) != EOF) {
        if (ch == '\n') {
            if (!empty_line) {
                count++;
                empty_line = true;
            }
        } else if (ch != '\r') {
            empty_line = false;
        }
    }
    
    /* Count the last line if it doesn't end with a newline */
    if (!empty_line) {
        count++;
    }
    
    fclose(file);
    
    return count;
}
#include "../include/wpa_cracker.h"

int read_wordlist(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen");
        return 1;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, file)) != -1) {
        // Remove trailing newline
        if (line[read - 1] == '\n') {
            line[read - 1] = '\0';
        }
        printf("Read password: %s\n", line);
    }

    fclose(file);
    if (line) {
        free(line);
    }

    return 0;
}

/**
 * wordlist.c
 * Functions for efficiently reading and processing wordlists
 */

#include "../include/wpa_cracker.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define MMAP_FAILED NULL
#else
#include <unistd.h>
#include <sys/mman.h>
#define MMAP_FAILED MAP_FAILED
#endif

#define BUFFER_SIZE (1024 * 1024) /* 1MB buffer */

/**
 * Open a wordlist file and prepare it for reading
 */
wordlist_t* wordlist_open(const char *filename) {
    wordlist_t *wordlist = NULL;
    struct stat st;
    int fd;
    
    /* Allocate the wordlist structure */
    wordlist = (wordlist_t*)malloc(sizeof(wordlist_t));
    if (wordlist == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        return NULL;
    }
    
    /* Initialize the structure */
    memset(wordlist, 0, sizeof(wordlist_t));
    wordlist->filename = strdup(filename);
    if (wordlist->filename == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        free(wordlist);
        return NULL;
    }
    
    /* Open the file */
    wordlist->file = fopen(filename, "rb");
    if (wordlist->file == NULL) {
        fprintf(stderr, "Error: Could not open wordlist file '%s'\n", filename);
        free(wordlist->filename);
        free(wordlist);
        return NULL;
    }
    
    /* Get the file size */
    if (stat(filename, &st) != 0) {
        fprintf(stderr, "Error: Could not stat wordlist file '%s'\n", filename);
        fclose(wordlist->file);
        free(wordlist->filename);
        free(wordlist);
        return NULL;
    }
    
    /* Try to memory map the file for faster access */
#ifdef _WIN32
    /* Windows implementation */
    HANDLE file_handle = (HANDLE)_get_osfhandle(_fileno(wordlist->file));
    HANDLE mapping = CreateFileMapping(file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    
    if (mapping != NULL) {
        wordlist->buffer = (char*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        CloseHandle(mapping);
        
        if (wordlist->buffer != NULL) {
            wordlist->buffer_size = st.st_size;
            wordlist->position = 0;
            pthread_mutex_init(&wordlist->mutex, NULL);
            return wordlist;
        }
    }
#else
    /* Unix/Linux implementation */
    fd = fileno(wordlist->file);
    wordlist->buffer = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    
    if (wordlist->buffer != MMAP_FAILED) {
        wordlist->buffer_size = st.st_size;
        wordlist->position = 0;
        pthread_mutex_init(&wordlist->mutex, NULL);
        return wordlist;
    }
#endif
    
    /* If memory mapping failed, fall back to buffered I/O */
    wordlist->buffer = (char*)malloc(BUFFER_SIZE);
    if (wordlist->buffer == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        fclose(wordlist->file);
        free(wordlist->filename);
        free(wordlist);
        return NULL;
    }
    
    wordlist->buffer_size = fread(wordlist->buffer, 1, BUFFER_SIZE, wordlist->file);
    wordlist->position = 0;
    pthread_mutex_init(&wordlist->mutex, NULL);
    
    return wordlist;
}

/**
 * Get the next password from the wordlist
 */
bool wordlist_get_next(wordlist_t *wordlist, char *password, size_t max_length) {
    bool result = false;
    size_t i, j;
    
    /* Lock the mutex for thread safety */
    pthread_mutex_lock(&wordlist->mutex);
    
    /* Check if we've reached the end of the buffer */
    if (wordlist->position >= wordlist->buffer_size) {
        /* If we're using memory mapping, we're done */
        if (wordlist->file == NULL) {
            pthread_mutex_unlock(&wordlist->mutex);
            return false;
        }
        
        /* Otherwise, read more data from the file */
        wordlist->buffer_size = fread(wordlist->buffer, 1, BUFFER_SIZE, wordlist->file);
        wordlist->position = 0;
        
        /* Check if we've reached the end of the file */
        if (wordlist->buffer_size == 0) {
            pthread_mutex_unlock(&wordlist->mutex);
            return false;
        }
    }
    
    /* Find the end of the current line */
    for (i = wordlist->position; i < wordlist->buffer_size; i++) {
        if (wordlist->buffer[i] == '\n' || wordlist->buffer[i] == '\r') {
            break;
        }
    }
    
    /* Copy the password, respecting the maximum length */
    j = 0;
    for (size_t k = wordlist->position; k < i && j < max_length - 1; k++, j++) {
        password[j] = wordlist->buffer[k];
    }
    password[j] = '\0';
    
    /* Skip past any newline characters */
    while (i < wordlist->buffer_size && 
           (wordlist->buffer[i] == '\n' || wordlist->buffer[i] == '\r')) {
        i++;
    }
    
    /* Update the position */
    wordlist->position = i;
    
    /* If we found a non-empty password, return success */
    result = (j > 0);
    
    /* Unlock the mutex */
    pthread_mutex_unlock(&wordlist->mutex);
    
    return result;
}

/**
 * Close the wordlist and free resources
 */
void wordlist_close(wordlist_t *wordlist) {
    if (wordlist == NULL) {
        return;
    }
    
    /* Clean up the mutex */
    pthread_mutex_destroy(&wordlist->mutex);
    
    /* Free the filename */
    if (wordlist->filename != NULL) {
        free(wordlist->filename);
    }
    
    /* Clean up the memory mapping or buffer */
#ifdef _WIN32
    /* Windows implementation */
    if (wordlist->file == NULL) {
        /* Memory mapped file */
        UnmapViewOfFile(wordlist->buffer);
    } else {
        /* Buffered I/O */
        if (wordlist->buffer != NULL) {
            free(wordlist->buffer);
        }
        fclose(wordlist->file);
    }
#else
    /* Unix/Linux implementation */
    if (wordlist->file == NULL) {
        /* Memory mapped file */
        munmap(wordlist->buffer, wordlist->buffer_size);
    } else {
        /* Buffered I/O */
        if (wordlist->buffer != NULL) {
            free(wordlist->buffer);
        }
        fclose(wordlist->file);
    }
#endif
    
    /* Free the wordlist structure */
    free(wordlist);
}
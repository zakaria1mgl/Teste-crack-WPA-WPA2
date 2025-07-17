/**
 * main.c
 * Main entry point and command-line interface for the WPA/WPA2 handshake cracker
 */

#include "../include/wpa_cracker.h"
#include <getopt.h>
#include <signal.h>

/* Global variables */
static volatile bool g_stop = false;
static uint64_t g_passwords_tested = 0;
static double g_start_time = 0.0;

/* Function prototypes */
static void print_usage(const char *program_name);
static void signal_handler(int signum);

/**
 * Main entry point
 */
int main(int argc, char *argv[]) {
    char *handshake_file = NULL;
    char *wordlist_file = NULL;
    int num_threads = 1;
    bool use_gpu = false;
    int opt;
    wpa_handshake_t handshake;
    wordlist_t *wordlist;
    pthread_t *threads;
    crack_job_t *jobs;
    pthread_mutex_t result_mutex;
    bool password_found = false;
    char found_password[MAX_PASSWORD_LENGTH];
    uint64_t total_passwords;
    
    /* Parse command-line arguments */
    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"wordlist", required_argument, 0, 'w'},
        {"threads", required_argument, 0, 't'},
        {"gpu", no_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "f:w:t:gh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'f':
                handshake_file = optarg;
                break;
            case 'w':
                wordlist_file = optarg;
                break;
            case 't':
                num_threads = atoi(optarg);
                if (num_threads < 1) {
                    num_threads = 1;
                }
                break;
            case 'g':
                use_gpu = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                return 1;
        }
    }
    
    /* Check required arguments */
    if (handshake_file == NULL || wordlist_file == NULL) {
        fprintf(stderr, "Error: Missing required arguments\n");
        print_usage(argv[0]);
        return 1;
    }
    
    /* Set up signal handler */
    signal(SIGINT, signal_handler);
    
    /* Read the handshake */
    printf("Reading handshake from '%s'...\n", handshake_file);
    if (!read_handshake(handshake_file, &handshake)) {
        fprintf(stderr, "Error: Could not read a valid handshake from '%s'\n", handshake_file);
        return 1;
    }
    
    /* Print handshake information */
    print_handshake_info(&handshake);
    
    /* Open the wordlist */
    printf("Opening wordlist '%s'...\n", wordlist_file);
    wordlist = wordlist_open(wordlist_file);
    if (wordlist == NULL) {
        fprintf(stderr, "Error: Could not open wordlist '%s'\n", wordlist_file);
        return 1;
    }
    
    /* Count the number of passwords in the wordlist */
    printf("Counting passwords in wordlist...\n");
    total_passwords = count_lines(wordlist_file);
    printf("Found %lu passwords in wordlist\n", total_passwords);
    
#ifdef USE_CUDA
    /* Initialize CUDA if requested */
    if (use_gpu) {
        printf("Initializing GPU...\n");
        if (!init_cuda()) {
            fprintf(stderr, "Warning: Could not initialize GPU, falling back to CPU\n");
            use_gpu = false;
        }
    }
#else
    if (use_gpu) {
        fprintf(stderr, "Warning: GPU support not compiled in, falling back to CPU\n");
        use_gpu = false;
    }
#endif
    
    /* Initialize the mutex */
    pthread_mutex_init(&result_mutex, NULL);
    
    /* Allocate thread and job arrays */
    threads = (pthread_t*)malloc(num_threads * sizeof(pthread_t));
    jobs = (crack_job_t*)malloc(num_threads * sizeof(crack_job_t));
    if (threads == NULL || jobs == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        wordlist_close(wordlist);
        return 1;
    }
    
    /* Initialize the jobs */
    for (int i = 0; i < num_threads; i++) {
        jobs[i].handshake = &handshake;
        jobs[i].wordlist = wordlist;
        jobs[i].thread_id = i;
        jobs[i].num_threads = num_threads;
        jobs[i].password_found = &password_found;
        jobs[i].found_password = found_password;
        jobs[i].result_mutex = &result_mutex;
        jobs[i].use_gpu = use_gpu;
        jobs[i].stop_flag = &g_stop;
    }
    
    /* Start the timer */
    g_start_time = get_time();
    
    /* Create the threads */
    printf("Starting %d cracking threads...\n", num_threads);
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, crack_thread, &jobs[i]) != 0) {
            fprintf(stderr, "Error: Could not create thread %d\n", i);
            g_stop = true;
            break;
        }
    }
    
    /* Wait for the threads to finish */
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    /* Clean up */
    pthread_mutex_destroy(&result_mutex);
    free(threads);
    free(jobs);
    wordlist_close(wordlist);
    
#ifdef USE_CUDA
    /* Clean up CUDA */
    if (use_gpu) {
        cleanup_cuda();
    }
#endif
    
    /* Print the result */
    printf("\n");
    if (password_found) {
        printf("Password found: %s\n", found_password);
        return 0;
    } else if (g_stop) {
        printf("Cracking stopped by user\n");
        return 1;
    } else {
        printf("Password not found in wordlist\n");
        return 1;
    }
}

/**
 * Print usage information
 */
static void print_usage(const char *program_name) {
    printf("Usage: %s -f <handshake_file> -w <wordlist_file> [options]\n", program_name);
    printf("\nOptions:\n");
    printf("  -f, --file <file>      Handshake capture file (.cap or .pcap)\n");
    printf("  -w, --wordlist <file>  Wordlist file\n");
    printf("  -t, --threads <num>    Number of threads to use (default: 1)\n");
    printf("  -g, --gpu              Use GPU acceleration if available\n");
    printf("  -h, --help             Display this help message\n");
}

/**
 * Signal handler for Ctrl+C
 */
static void signal_handler(int signum) {
    if (signum == SIGINT) {
        g_stop = true;
    }
}

/**
 * Thread function for cracking
 */
void* crack_thread(void *arg) {
    crack_job_t *job = (crack_job_t*)arg;
    wpa_handshake_t *handshake = job->handshake;
    wordlist_t *wordlist = job->wordlist;
    int thread_id = job->thread_id;
    int num_threads = job->num_threads;
    bool *password_found = job->password_found;
    char *found_password = job->found_password;
    pthread_mutex_t *result_mutex = job->result_mutex;
    bool use_gpu = job->use_gpu;
    volatile bool *stop_flag = job->stop_flag;
    
    char password[MAX_PASSWORD_LENGTH];
    uint8_t pmk[PMK_LENGTH];
    uint8_t ptk[PTK_LENGTH];
    uint64_t passwords_tested_local = 0;
    int skip_count = 0;
    
    /* Process passwords from the wordlist */
    while (!*stop_flag && !*password_found && wordlist_get_next(wordlist, password, MAX_PASSWORD_LENGTH)) {
        /* Skip passwords based on thread ID for load balancing */
        skip_count = (skip_count + 1) % num_threads;
        if (skip_count != thread_id) {
            continue;
        }
        
        /* Calculate the PMK */
        if (!calculate_pmk((const uint8_t*)password, strlen(password),
                          handshake->ssid, handshake->ssid_length, pmk)) {
            continue;
        }
        
        /* Calculate the PTK */
        if (!calculate_ptk(pmk, handshake->mac_ap, handshake->mac_client,
                          handshake->anonce, handshake->snonce, ptk, PTK_LENGTH)) {
            continue;
        }
        
        /* Verify the MIC */
        if (verify_mic(ptk, handshake->eapol, handshake->eapol_length, handshake->mic)) {
            /* Password found! */
            pthread_mutex_lock(result_mutex);
            *password_found = true;
            strncpy(found_password, password, MAX_PASSWORD_LENGTH - 1);
            found_password[MAX_PASSWORD_LENGTH - 1] = '\0';
            pthread_mutex_unlock(result_mutex);
            break;
        }
        
        /* Update the counter */
        passwords_tested_local++;
        
        /* Update the global counter periodically */
        if (passwords_tested_local % 1000 == 0) {
            pthread_mutex_lock(result_mutex);
            g_passwords_tested += 1000;
            print_progress(g_passwords_tested, total_passwords, get_time() - g_start_time);
            pthread_mutex_unlock(result_mutex);
        }
    }
    
    /* Update the global counter with any remaining passwords */
    pthread_mutex_lock(result_mutex);
    g_passwords_tested += passwords_tested_local % 1000;
    pthread_mutex_unlock(result_mutex);
    
    return NULL;
}
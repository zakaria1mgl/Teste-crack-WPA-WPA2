# Makefile for WPA/WPA2 Handshake Cracker

# Compiler and flags
CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -pedantic
LDFLAGS =
LDLIBS = -lpcap -lssl -lcrypto -ldbus-1 -libverbs -lnl-3 -lnl-route-3

# Source files
SRCS = src/main.c src/handshake.c src/wordlist.c src/crypto.c src/utils.c
OBJS = $(SRCS:.c=.o)

# Target executable
TARGET = wpa-cracker

# Default rule
all: $(TARGET)

# Rule to build the target executable
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

# Rule to compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to clean up the aild files
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean

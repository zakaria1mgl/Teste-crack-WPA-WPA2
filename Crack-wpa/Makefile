# Makefile for WPA/WPA2 Handshake Cracker

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -fopenmp
LDFLAGS = -static
LIBS = -lpcap -lcrypto -lssl -lpthread

# CUDA support
CUDA_ENABLED = 0
ifeq ($(CUDA_ENABLED), 1)
    NVCC = nvcc
    NVCCFLAGS = -O3 -arch=sm_50
    CFLAGS += -DUSE_CUDA
    CUDA_OBJS = obj/crypto_cuda.o
    CUDA_LIBS = -lcudart
endif

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin

# Source files
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))

# Target executable
TARGET = $(BINDIR)/wpa-cracker

# Default target
all: directories $(TARGET)

# Create directories
directories:
	mkdir -p $(OBJDIR)
	mkdir -p $(BINDIR)

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# Compile CUDA files
ifeq ($(CUDA_ENABLED), 1)
$(OBJDIR)/crypto_cuda.o: $(SRCDIR)/crypto_cuda.cu
	$(NVCC) $(NVCCFLAGS) -I$(INCDIR) -c $< -o $@
endif

# Link the executable
$(TARGET): $(OBJS) $(CUDA_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS) $(CUDA_LIBS)

# Clean up
clean:
	rm -rf $(OBJDIR) $(BINDIR)

# Install
install: all
	mkdir -p $(DESTDIR)/usr/local/bin
	cp $(TARGET) $(DESTDIR)/usr/local/bin/

# Uninstall
uninstall:
	rm -f $(DESTDIR)/usr/local/bin/wpa-cracker

# Phony targets
.PHONY: all directories clean install uninstall
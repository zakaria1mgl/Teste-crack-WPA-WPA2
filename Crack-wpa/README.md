# WPA/WPA2 Handshake Cracker

A high-performance tool for cracking WPA/WPA2 handshakes using wordlist-based attacks.

## Features

- Fast WPA/WPA2 handshake cracking
- Multi-threaded processing
- Optional GPU acceleration (CUDA)
- Memory-efficient wordlist processing
- Static compilation for portability

## Requirements

- GCC compiler
- OpenSSL development libraries
- libpcap development libraries
- CUDA toolkit (optional, for GPU acceleration)
- pthread library
- OpenMP support

## Building

### Standard Build (CPU only)

```bash
make
```

### With CUDA Support (GPU acceleration)

```bash
make CUDA_ENABLED=1
```

## Usage

```bash
# Basic usage
./bin/wpa-cracker -f handshake.cap -w wordlist.txt

# With multiple threads
./bin/wpa-cracker -f handshake.cap -w wordlist.txt -t 8

# With GPU acceleration (if compiled with CUDA support)
./bin/wpa-cracker -f handshake.cap -w wordlist.txt --gpu
```

### Command-line Options

- `-f, --file <file>`: Handshake capture file (.cap or .pcap)
- `-w, --wordlist <file>`: Wordlist file
- `-t, --threads <num>`: Number of threads to use (default: 1)
- `-g, --gpu`: Use GPU acceleration if available
- `-h, --help`: Display help message

## How It Works

1. **Handshake Parsing**: Extracts the 4-way handshake from a .cap file
2. **Wordlist Processing**: Efficiently reads passwords from a dictionary file
3. **PMK Calculation**: Uses PBKDF2-SHA1 to derive the PMK from each password
4. **PTK Derivation**: Calculates the PTK from the PMK and handshake data
5. **MIC Verification**: Checks if the calculated MIC matches the one in the handshake

## Performance Optimizations

- Memory mapping for efficient wordlist processing
- Multi-threading for parallel password testing
- Assembly optimizations for cryptographic operations
- SIMD instructions (AVX2) when available
- GPU acceleration for PBKDF2 calculations (with CUDA)

## Building for Different Platforms

### Linux

```bash
# Install dependencies
sudo apt-get install build-essential libssl-dev libpcap-dev

# Build
make
```

### Windows (using MinGW)

```bash
# Install dependencies (using MSYS2)
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl mingw-w64-x86_64-winpcap

# Build
make
```

### macOS

```bash
# Install dependencies (using Homebrew)
brew install openssl libpcap

# Build
make CFLAGS="-I/usr/local/opt/openssl/include" LDFLAGS="-L/usr/local/opt/openssl/lib"
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational purposes and legitimate security testing only. Unauthorized access to wireless networks is illegal and unethical. Always obtain proper authorization before testing any network security.
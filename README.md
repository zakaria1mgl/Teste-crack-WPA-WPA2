# WPA/WPA2 Handshake Cracker

A Python tool for testing passwords against WPA/WPA2 handshakes captured in pcap files.

## Requirements

### Required Libraries
```bash
pip install scapy prettytable
```

### System Requirements
- Python 3.x
- Multi-core processor (for parallel processing optimization)

## Features

- **Automatic handshake analysis**: Parses pcap files and extracts WPA/WPA2 handshakes
- **Parallel processing**: Uses multiprocessing to utilize all CPU cores
- **Real-time statistics**: Shows password testing rate in real-time
- **Multi-SSID support**: Can handle multiple networks in the same file
- **User-friendly interface**: Tabular display of all available handshakes

## Usage

### Basic Commands

```bash
# Crack handshake using wordlist
python3 wpa_cracker.py -c capture.pcap -w wordlist.txt

# Crack specific handshake by SSID
python3 wpa_cracker.py -c capture.pcap -w wordlist.txt -s "NetworkName"

# Specify number of threads
python3 wpa_cracker.py -c capture.pcap -w wordlist.txt -t 8

# Set statistics update interval
python3 wpa_cracker.py -c capture.pcap -w wordlist.txt --update-interval 5
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-c, --capture` | Path to pcap file containing the handshake |
| `-w, --wordlist` | Path to wordlist file |
| `-s, --ssid` | Specific SSID to crack (optional) |
| `-t, --threads` | Number of threads (default: CPU core count) |
| `--update-interval` | Statistics update interval in seconds (default: 1) |
| `--stdin` | Read passwords from stdin |

## Example Usage

```bash
# Run the tool
python3 wpa_cracker.py -c handshake.pcap -w rockyou.txt

# Expected output
[+] Loading capture file: handshake.pcap
[+] Loaded 1547 packets
[+] Analyzing handshakes...
[+] Searching for SSIDs in Beacon frames...
[+] Found 2 SSIDs
    aa:bb:cc:dd:ee:ff -> MyNetwork
    11:22:33:44:55:66 -> TestWiFi
[+] Searching for EAPOL packets...
[+] Found 4 EAPOL packets
[+] Found 1 handshakes

+----+-------------------+-------------------+-----------+--------+--------+-----+----------+
| ID |      AP MAC       |   Client MAC      |   SSID    | ANonce | SNonce | MIC | Complete |
+----+-------------------+-------------------+-----------+--------+--------+-----+----------+
| 0  | aa:bb:cc:dd:ee:ff | 66:77:88:99:aa:bb | MyNetwork |   ✓    |   ✓    |  ✓  |   Yes    |
+----+-------------------+-------------------+-----------+--------+--------+-----+----------+

[+] Selected handshake for SSID: MyNetwork
[+] Loaded 14,344,392 words from file
[+] Starting crack with 8 processes
[+] Statistics updated every 1 seconds
[+] Testing: 45,231 | Rate: 4,523.1/s | Total Rate: 4,523.1/s | Time: 00:10
[+] Password found: password123
[+] Process completed in 00:15
[+] Tested 67,845 passwords
[+] Final rate: 4,523.00 passwords/second
```

## File Structure

```
wpa_cracker.py          # Main script
├── capture.pcap        # Handshake file
├── wordlist.txt        # Password wordlist
└── NetworkName.cracked # Result file (created when password is found)
```

## Result File

When a password is found, it's saved in a file with the format:
```
SSID: MyNetwork
Password: password123
Time: 15.23 seconds
Passwords tested: 67845
```

## Usage Tips

### For Better Performance:
1. **Use SSD**: For fast reading from wordlist files
2. **Optimize threads**: Try different `-t` values to find optimal for your system
3. **Optimized wordlists**: Use wordlists sorted by password frequency

### To Avoid Issues:
- Ensure pcap file contains complete handshake
- Use UTF-8 encoded wordlists
- Ensure sufficient disk space is available

## Troubleshooting

### If no handshakes are found:
1. Verify the file contains WPA/WPA2 traffic
2. Check for beacon frames in the file
3. Ensure handshake is complete (4 EAPOL messages)

### If performance is slow:
1. Reduce thread count if there's excessive memory usage
2. Increase statistics update interval to reduce overhead
3. Use smaller wordlist for testing

## Security and Legal Notice

⚠️ **Warning**: This tool is intended for educational and ethical testing purposes only.

- Use this tool only on networks you own or have explicit permission to test
- Do not use this tool for illegal purposes
- Respect your country's laws and regulations regarding network security

## Technical Details

### Handshake Analysis Process:
1. **Beacon Frame Analysis**: Extracts SSIDs from beacon frames
2. **EAPOL Packet Processing**: Identifies and processes EAPOL-Key messages
3. **Handshake Reconstruction**: Combines partial handshakes into complete ones
4. **Data Validation**: Ensures all required components are present

### Cracking Process:
1. **PMK Generation**: Uses PBKDF2 with SSID as salt
2. **PTK Derivation**: Applies PRF-512 for Pairwise Transient Key
3. **MIC Calculation**: Uses HMAC-SHA1 with derived KCK
4. **Verification**: Compares calculated MIC with captured MIC

## Supported Formats

- **Input**: pcap, pcapng files
- **Wordlists**: Plain text files (UTF-8 encoding recommended)
- **Output**: Plain text result files

## Performance Optimization

### Memory Usage:
- Queue size limited to 1000 words to prevent memory overflow
- Efficient packet processing to minimize memory footprint

### CPU Utilization:
- Automatic CPU core detection
- Balanced workload distribution across processes
- Minimal inter-process communication overhead

## Support

For issues or questions:
- Ensure all requirements are properly installed
- Check pcap file format and wordlist encoding
- Review error messages for detailed information
- Verify file permissions and disk space

## License

This tool is provided for educational and ethical testing purposes only. Use responsibly and in accordance with applicable laws.

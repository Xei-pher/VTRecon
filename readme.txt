# VTRecon: A Command-Line Threat Analysis Tool

VTRecon is a powerful and versatile command-line tool designed for cybersecurity professionals and enthusiasts. It enables users to analyze file hashes, IP addresses, and URLs using the VirusTotal API, perform WHOIS lookups for domains, and gather essential threat intelligence.

---

## Features
- File hash scanning using VirusTotal
- IP address threat analysis
- URL scanning and analysis
- WHOIS lookup for domain details
- Simple and user-friendly interface

---

## Prerequisites

### 1. Python Environment
Ensure you have Python 3.x installed on your system. You can check your Python version by running:
```bash
python --version
```

### 2. Required Libraries
Install the necessary Python libraries by running the following command:
```bash
pip install requests python-whois
```

### 3. VirusTotal API Key
- Sign up for a free VirusTotal account at [VirusTotal](https://www.virustotal.com/).
- Obtain your API key from the account settings.
- Add your API key to the tool (instructions below).

---

## Installation
1. Clone or download the VTRecon repository.
2. Save the script as `vtrecon.py` in your desired directory.

---

## Configuration
Update the script with your VirusTotal API key:
1. Open `vtrecon.py` in a text editor.
2. Locate the following line:
   ```python
   VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'
   ```
3. Replace `'your_virustotal_api_key'` with your actual API key.
4. Save the file.

---

## Usage
Run the script from the command line with the following options:

### 1. Scan a File Hash
Scan a file hash (MD5, SHA256, etc.) for potential threats:
```bash
python vtrecon.py -f <file_hash>
```
Example:
```bash
python vtrecon.py -f 44d88612fea8a8f36de82e1278abb02f
```

### 2. Scan an IP Address
Analyze an IP address for malicious activity:
```bash
python vtrecon.py -i <ip_address>
```
Example:
```bash
python vtrecon.py -i 8.8.8.8
```

### 3. Scan a URL
Check a URL for potential threats:
```bash
python vtrecon.py -u <url>
```
Example:
```bash
python vtrecon.py -u https://example.com
```

### 4. WHOIS Lookup
Retrieve WHOIS information for a domain:
```bash
python vtrecon.py -d <domain>
```
Example:
```bash
python vtrecon.py -d example.com
```

### 5. Help
View the help menu for more options:
```bash
python vtrecon.py -h
```

---

## Output
CyberSleuth displays the results in the terminal in a human-readable format, including essential details like:
- VirusTotal detection rates
- WHOIS registration data
- IP geolocation (if extended features are added)

---

## Future Enhancements
- Geolocation of IP addresses
- DNS record lookups
- SSL/TLS certificate analysis
- Phishing detection

---

## Troubleshooting
1. **API Key Errors**:
   - Ensure your API key is valid and properly configured.
2. **Library Installation Issues**:
   - Reinstall the required libraries:
     ```bash
     pip install --force-reinstall requests python-whois
     ```
3. **Unexpected Errors**:
   - Run the script in verbose mode by adding debugging code (optional).

---

## License
VTRecon is an open-source project. Feel free to modify and use it as needed.


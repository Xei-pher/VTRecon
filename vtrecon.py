import argparse
import requests
import whois
import socket
import sys
from textwrap import dedent

# Set your VirusTotal API key here
VIRUSTOTAL_API_KEY = 'you_api_key_here'

# Free IP Geolocation API
IP_GEOLOCATION_API_URL = "http://ip-api.com/json/"

def print_banner():
    banner = dedent("""
                    
██╗   ██╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██║   ██║╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║   ██║   ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
╚██╗ ██╔╝   ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚████╔╝    ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═══╝     ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
          
             VTRecon - Threat Analyzer
    ===========================================
    """)
    print(banner)

def format_output(title, data):
    """Format output to be human-readable."""
    print("\n" + "=" * 50)
    print(f"[+] {title}")
    print("=" * 50)
    for key, value in data.items():
        print(f"{key}: {value}")
    print("=" * 50 + "\n")

def validate_api_key():
    """Validate the VirusTotal API key."""
    if not VIRUSTOTAL_API_KEY or len(VIRUSTOTAL_API_KEY) < 10:
        print("[-] Invalid or missing VirusTotal API key. Please set it in the script.")
        sys.exit(1)

def request_with_error_handling(url, headers=None, data=None, method="get"):
    """Handle API requests with error handling."""
    try:
        if method == "get":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "post":
            response = requests.post(url, headers=headers, data=data, timeout=10)
        else:
            return {"Error": "Invalid HTTP method"}

        if response.status_code == 200:
            return response.json()
        else:
            return {"Error": f"HTTP {response.status_code}: {response.text}"}
    except requests.exceptions.RequestException as e:
        return {"Error": str(e)}

def scan_hash(file_hash):
    """Scan a file hash on VirusTotal."""
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = request_with_error_handling(url, headers=headers)
    if "Error" in response:
        return response

    attributes = response.get('data', {}).get('attributes', {})
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    malicious_count = last_analysis_stats.get("malicious", 0)
    total_count = sum(last_analysis_stats.values())
    risk_score = round((malicious_count / total_count) * 100, 2) if total_count > 0 else 0

    detected_by = [
        f"{engine} ({result.get('result', 'N/A')})"
        for engine, result in attributes.get("last_analysis_results", {}).items()
        if result.get("category") == "malicious"
    ]

    result = {
        "File Name": attributes.get("meaningful_name", "N/A"),
        "Risk Score": f"{risk_score}%",
        "Malicious Detections": malicious_count,
        "Detection Engines": ", ".join(detected_by[:5]) + ("..." if len(detected_by) > 5 else ""),
        "Malicious Status": "Yes" if malicious_count > 0 else "No",
        "First Submission": attributes.get("first_submission_date", "N/A"),
        "Last Submission": attributes.get("last_submission_date", "N/A"),
        "File Tags": ", ".join(attributes.get("tags", [])),
    }

    behavior = attributes.get("sandbox_verdicts", {})
    if behavior:
        result["Behavioral Summary"] = "; ".join([f"{key}: {value}" for key, value in behavior.items()])

    return result

def geolocation_lookup(ip):
    """Get geolocation information for an IP address."""
    url = f"{IP_GEOLOCATION_API_URL}{ip}"
    geo_data = request_with_error_handling(url)
    if "Error" in geo_data:
        return geo_data

    return {
        "Country": geo_data.get("country", "N/A"),
        "Region": geo_data.get("regionName", "N/A"),
        "City": geo_data.get("city", "N/A"),
        "ISP": geo_data.get("isp", "N/A"),
        "Latitude": geo_data.get("lat", "N/A"),
        "Longitude": geo_data.get("lon", "N/A"),
    }

def dns_lookup(domain):
    """Perform DNS lookup for a domain."""
    try:
        ip_address = socket.gethostbyname(domain)
        return {"Domain": domain, "Resolved IP": ip_address}
    except socket.gaierror as e:
        return {"Error": f"DNS Lookup failed: {str(e)}"}

def scan_ip(ip):
    """Scan an IP address on VirusTotal and include geolocation."""
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = request_with_error_handling(url, headers=headers)
    if "Error" in response:
        return response

    attributes = response.get('data', {}).get('attributes', {})
    geolocation = geolocation_lookup(ip)
    return {
        "Owner": attributes.get("as_owner", "N/A"),
        "Malicious Detections": attributes.get("last_analysis_stats", {}).get("malicious", 0),
        "Reputation": attributes.get("reputation", "N/A"),
        **geolocation,
    }

def scan_url(url_input):
    """Scan a URL on VirusTotal."""
    vt_url = 'https://www.virustotal.com/api/v3/urls'
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url_input}

    # Submit URL for scanning
    response = request_with_error_handling(vt_url, headers=headers, data=data, method="post")
    if "Error" in response:
        return response

    # Extract scan ID from the submission response
    scan_id = response.get("data", {}).get("id", "")
    if not scan_id:
        return {"Error": "Failed to retrieve scan ID from VirusTotal response"}

    # Retrieve analysis report
    report_url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    report_response = request_with_error_handling(report_url, headers=headers)
    if "Error" in report_response:
        return report_response

    # Parse the analysis report
    attributes = report_response.get('data', {}).get('attributes', {})
    return {
        "URL": url_input,
        "Malicious Detections": attributes.get("stats", {}).get("malicious", 0),
        "Suspicious Detections": attributes.get("stats", {}).get("suspicious", 0),
        "Harmless Detections": attributes.get("stats", {}).get("harmless", 0),
        "Undetected": attributes.get("stats", {}).get("undetected", 0),
        "Last Analysis Date": attributes.get("date", "N/A")
    }

def whois_lookup(domain):
    """Perform a WHOIS lookup on a domain."""
    try:
        w = whois.whois(domain)
        return {
            "Domain Name": w.domain_name,
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Name Servers": ", ".join(w.name_servers) if w.name_servers else "N/A",
        }
    except Exception as e:
        return {"Error": f"WHOIS Lookup failed: {str(e)}"}

def main():
    validate_api_key()
    print_banner()
    parser = argparse.ArgumentParser(description="VTRecon: A CLI Threat Analysis Tool")
    parser.add_argument("-f", "--filehash", help="Scan a file hash on VirusTotal.")
    parser.add_argument("-i", "--ip", help="Scan an IP address and retrieve geolocation info.")
    parser.add_argument("-u", "--url", help="Scan a URL on VirusTotal.")
    parser.add_argument("-d", "--domain", help="Perform a WHOIS and DNS lookup for a domain.")
    args = parser.parse_args()

    if args.filehash:
        print("[*] Scanning file hash...")
        result = scan_hash(args.filehash)
        format_output("File Hash Scan Results", result)
    elif args.ip:
        print("[*] Scanning IP address...")
        result = scan_ip(args.ip)
        format_output("IP Address Scan Results", result)
    elif args.url:
        print("[*] Scanning URL...")
        result = scan_url(args.url)
        format_output("URL Scan Results", result)
    elif args.domain:
        print("[*] Performing WHOIS and DNS lookup...")
        result = dns_lookup(args.domain)
        whois_result = whois_lookup(args.domain)
        format_output("DNS Lookup Results", result)
        format_output("WHOIS Lookup Results", whois_result)
    else:
        print("[-] Please provide an argument. Use -h for help.")
        sys.exit(1)

if __name__ == "__main__":
    main()

import socket
import requests
import whois
from urllib.parse import urlparse

# Initialize colorama (you can remove this if you don't want color output)

def extract_domain(url_or_domain):
    parsed = urlparse(url_or_domain)
    return parsed.netloc if parsed.netloc else parsed.path

def get_ip(domain):
    return socket.gethostbyname(domain)

def get_http_headers(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        response = requests.get(url, timeout=10)
        return {key: value for key, value in response.headers.items()}
    except Exception as e:
        return {"Error": str(e)}

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        return {
            "Registrar": domain_info.get("registrar", "N/A"),
            "Updated": str(domain_info.get("updated_date", "N/A")),
            "Created": str(domain_info.get("creation_date", "N/A")),
            "Expires": str(domain_info.get("expiration_date", "N/A"))
        }
    except Exception as e:
        return {"Error": str(e)}

def check_cdn(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
        if "cloudflare" in host.lower():
            return "Cloudflare"
        elif "akamai" in host.lower():
            return "Akamai"
        elif "fastly" in host.lower():
            return "Fastly"
        return "Unknown"
    except:
        return "Not detected"

def perform_server_fingerprinting(url_or_domain):
    result = ""
    try:
        domain = extract_domain(url_or_domain)
        result += f"\n🔍 Server Fingerprint for: {domain}\n"
        
        # Get IP Address
        ip = get_ip(domain)
        result += f"🌍 IP Address: {ip}\n"
        
        # Check CDN
        cdn = check_cdn(ip)
        result += f"🚛 CDN Detected: {cdn}\n"
        
        # Get HTTP Headers
        headers = get_http_headers(domain)
        result += f"\n🔑 HTTP Headers:\n"
        for key, value in headers.items():
            result += f"- {key}: {value}\n"
        
        # Get Server Technology
        tech = headers.get('X-Powered-By') or headers.get('Server') or "Not disclosed"
        result += f"\n🛠️ Server Technology: {tech}\n"
        
        # Get WHOIS Info
        whois_info = get_whois_info(domain)
        result += f"\n📜 WHOIS Info:\n"
        result += f"- Registrar: {whois_info['Registrar']}\n"
        result += f"- Updated: {whois_info['Updated']}\n"
        result += f"- Created: {whois_info['Created']}\n"
        result += f"- Expires: {whois_info['Expires']}\n"
        
    except Exception as e:
        result += f"\n❌ Error: {str(e)}\n"
    
    return result

# For standalone testing
if __name__ == "__main__":
    target = input("Enter website URL: ").strip()
    print(perform_server_fingerprinting(target))

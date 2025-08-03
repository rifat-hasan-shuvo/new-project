import socket
import re
from urllib.parse import urlparse

def get_whois_data(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("whois.iana.org", 43))
        s.send(f"{ip}\r\n".encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()

        match = re.search(r'refer:\s*(\S+)', response.decode('utf-8', 'ignore'))
        if not match:
            return response.decode('utf-8', 'ignore')
        whois_server = match.group(1).strip()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((whois_server, 43))
        s.send(f"{ip}\r\n".encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()

        return response.decode('utf-8', 'ignore')
    except Exception as e:
        return f"Error: {str(e)}"

def extract_geo_info(whois_data):
    info = {
        'country': 'N/A',
        'organization': 'N/A',
        'network': 'N/A',
        'created': 'N/A',
        'city': 'N/A',
        'asn': 'N/A',
        'cidr': 'N/A',
        'abuse_email': 'N/A'
    }

    patterns = {
        'country': r'(?i)^country:\s*(.+)$',
        'organization': r'(?i)^(org-name|orgname|owner|descr):\s*(.+)$',
        'network': r'(?i)^netname:\s*(.+)$',
        'created': r'(?i)^(created|RegDate):\s*(.+)$',
        'city': r'(?i)^city:\s*(.+)$',
        'asn': r'(?i)^origin:\s*(AS\d+)',
        'cidr': r'(?i)^(CIDR|route|inetnum):\s*(.+)$',
        'abuse_email': r'(?i)(abuse-mailbox|OrgAbuseEmail|e-mail|email):\s*([\w\.-]+@[\w\.-]+\.\w+)'
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, whois_data, re.MULTILINE)
        if match:
            info[key] = match.group(1 if key in ['country', 'network', 'city', 'asn'] else 2).strip()

    return info

def get_host_info(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return "N/A"

def analyze_security(hostname, org):
    warnings = []
    vpn_keywords = ['vpn', 'proxy', 'hosting', 'cloud', 'server']

    if any(kw in hostname.lower() for kw in vpn_keywords) or \
       any(kw in org.lower() for kw in vpn_keywords):
        warnings.append("Potential VPN/Proxy detected")

    if 'google' in hostname.lower():
        warnings.append("Google infrastructure detected")

    if 'amazon' in hostname.lower() or 'aws' in hostname.lower():
        warnings.append("Amazon Web Services detected")

    return warnings if warnings else ["No obvious security flags"]

def perform_ip_location_lookup(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        if not domain:
            return "Invalid URL format."

        ip = socket.gethostbyname(domain)
        output = f"📊 Scan Results\n"
        output += f"✅ Resolved IP: {ip}\n"

        whois_raw = get_whois_data(ip)
        geo_info = extract_geo_info(whois_raw)
        hostname = get_host_info(ip)
        security_warnings = analyze_security(hostname, geo_info['organization'])

        output += f"\n📍 Basic Information:\n"
        output += f"• Hostname: {hostname}\n"
        output += f"• Organization: {geo_info['organization']}\n"
        output += f"• Network: {geo_info['network']}\n"
        output += f"• Country: {geo_info['country']}\n"
        output += f"• City: {geo_info['city']}\n"

        output += f"\n🛰️ ASN & Network Info:\n"
        output += f"• ASN: {geo_info['asn']}\n"
        output += f"• CIDR: {geo_info['cidr']}\n"

        output += f"\n📬 Abuse Contact:\n"
        output += f"• Email: {geo_info['abuse_email']}\n"

        output += f"\n🛡️ Security Analysis:\n"
        for warning in security_warnings:
            output += f"• {warning}\n"

        output += f"\n📅 Registration Info:\n"
        output += f"• Created: {geo_info['created']}\n"

        return output
    except socket.gaierror:
        return "❌ Failed to resolve domain"
    except Exception as e:
        return f"❌ Error: {str(e)}"

if __name__ == "__main__":
    website = input("Enter website URL: ").strip()
    print(perform_ip_location_lookup(website))

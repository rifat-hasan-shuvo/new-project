import socket

def perform_port_scan(website):
    website = website.strip()
    if website.startswith("http://"):
        website = website[len("http://"):]
    elif website.startswith("https://"):
        website = website[len("https://"):]
    website = website.strip("/")

    try:
        ip = socket.gethostbyname(website)
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Alt"
        }
        result = "🔍 Scanning common ports...\n"
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            scan_result = sock.connect_ex((ip, port))
            if scan_result == 0:
                result += f"🟢 Port {port} ({service}) is OPEN\n"
            else:
                result += f"🔴 Port {port} ({service}) is CLOSED\n"
            sock.close()
        return result
    except socket.gaierror:
        return "❌ Failed to resolve the domain.\n"
    except Exception as e:
        return f"❗ Error: {e}\n"

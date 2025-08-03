import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import OpenSSL
import ssl as ssl_lib

# Core SSL scan function
def _scan_ssl_details(domain):
    result = ""  # Initialize an empty string to collect results
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            not_after = cert['notAfter']
            not_before = cert['notBefore']
            cert_expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
            cert_valid_from = datetime.strptime(not_before, "%b %d %H:%M:%S %Y GMT")
            days_until_expiry = (cert_expiry_date - datetime.now()).days

            result += f"🔍 Certificate Subject: {subject.get('commonName')}\n"
            result += f"🔍 Certificate Issuer: {issuer.get('commonName')}\n"
            result += f"📅 Valid From: {cert_valid_from}\n"
            result += f"📅 Valid Until: {cert_expiry_date}\n"
            result += f"🔖 Days Until Expiry: {days_until_expiry} days\n"

            if cert_expiry_date < datetime.now():
                result += "⚠️ SSL Certificate has expired!\n"
            else:
                result += "✅ SSL Certificate is valid.\n"

            cipher = ssock.cipher()
            result += f"🔐 Cipher: {cipher[0]} with strength {cipher[1]} bits\n"

            ssl_version = ssock.version()
            result += f"📜 TLS Version: {ssl_version}\n"

            try:
                cert_chain = ssl_lib.get_server_certificate((domain, 443), ssl_context=context)
                cert_chain_info = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_chain)
                cert_version = cert_chain_info.get_version()
                result += f"🔗 Certificate Chain Valid: Version {cert_version}\n"
            except Exception as e:
                result += f"⚠️ Certificate Chain Validation failed: {e}\n"

            result += "🔒 (Advanced) Checking certificate revocation status... (Not Implemented)\n"

    return result

# Reusable function
def perform_ssl_check(url):
    result = ""  # Initialize an empty string to collect results
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path

        if not domain:
            result += "❌ Invalid URL provided.\n"
            return result

        result += _scan_ssl_details(domain)

    except ssl.SSLError as ssl_error:
        result += f"❌ SSL/TLS Error: {ssl_error}\n"
    except Exception as e:
        result += f"❌ Error: {e}\n"
    
    return result

# Optional CLI execution
if __name__ == "__main__":
    user_url = input("🌐 Enter the URL of the website (e.g., https://example.com): ").strip()
    if not user_url.startswith(("http://", "https://")):
        user_url = "https://" + user_url
    print(perform_ssl_check(user_url))

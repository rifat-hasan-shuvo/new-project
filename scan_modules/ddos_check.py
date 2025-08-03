import requests
import socket
from urllib.parse import urlparse
import time

def measure_response_time(url):
    try:
        start_time = time.time()
        response = requests.get(url, timeout=10)
        return time.time() - start_time, response
    except:
        return float('inf'), None

def perform_ddos_attack_check(url):
    result = []
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc or parsed_url.path
        if not parsed_url.scheme:
            url = "https://" + host

        result.append(f"\nDDoS Protection Check for: {url}")
        ip = socket.gethostbyname(host)
        result.append(f"\n🌐 IP Address: {ip}")

        response_time, response = measure_response_time(url)
        result.append(f"⏱ Response Time: {response_time:.2f} seconds")

        if response is None:
            result.append("❌ Could not fetch response headers.")
            return "\n".join(result)

        protections = []

        # Detect common DDoS protection providers based on headers
        server_header = response.headers.get('Server', '').lower()

        # Cloudflare detection
        if 'cloudflare' in server_header:
            protections.append("Cloudflare (Server Header)")
        if 'cf-ray' in response.headers:
            protections.append("Cloudflare (CF-RAY Header)")
        if 'cf-cache-status' in response.headers:
            protections.append("Cloudflare (Cache Status Header)")
        if 'cf-connecting-ip' in response.headers:
            protections.append("Cloudflare (Connecting IP Header)")

        # Akamai detection
        if 'x-akamai-edgescape' in response.headers:
            protections.append("Akamai (Edgescape Header)")
        if 'x-edge-location' in response.headers:
            protections.append("Akamai (Edge Location Header)")

        # Custom DDoS Protection Indicators
        if 'x-sucuri-id' in response.headers:
            protections.append("Sucuri (Protection Header)")
        if 'x-captcha' in response.headers or 'x-bot' in response.headers:
            protections.append("Bot/Captcha Challenge Detected")

        # Rate limiting headers
        if 'x-rate-limit' in response.headers:
            protections.append("Rate Limiting Detected (X-Rate-Limit)")
        elif 'retry-after' in response.headers:
            protections.append("Retry-After Header (Possible Rate Limiting)")

        # Response code checks
        if response.status_code == 403:
            protections.append("403 Forbidden (Possible Cloudflare or Bot Protection)")
        elif response.status_code == 429:
            protections.append("429 Too Many Requests (Rate Limiting Triggered)")

        if protections:
            result.append("\n🛡️ Detected Protections:")
            for p in protections:
                result.append(f"  - {p}")
        else:
            # Advanced DDoS Protection Check (Huge traffic control systems)
            if response_time < 2.5:
                result.append("\n⚠️ Website has a **highly optimized traffic control system** — very likely protected by advanced DDoS mitigation tools.")
            else:
                result.append("\n⚠️ No obvious DDoS protection detected — website may be vulnerable!")

        result.append(f"\n📶 HTTP Status Code: {response.status_code}")
        if 300 <= response.status_code < 400:
            result.append("↪️ Redirection detected (Possible protection layer)")

        # High response times indicating rate-limiting
        if response_time > 2.5:
            result.append("🚨 High response time — may indicate rate limiting or filtering")

    except Exception as e:
        result.append(f"\n❌ Error occurred: {str(e)}")

    return "\n".join(result)

if __name__ == "__main__":
    target = input("Enter URL: ").strip()
    print(perform_ddos_attack_check(target))

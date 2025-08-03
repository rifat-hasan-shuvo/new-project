import requests

# Security headers and their explanations
security_headers = {
    "Content-Security-Policy": "🛡️ Helps prevent Cross-Site Scripting (XSS) attacks by controlling resources the page can load.",
    "Strict-Transport-Security": "🔒 Enforces HTTPS for all future requests to ensure a secure connection.",
    "X-Frame-Options": "🖼️ Protects against clickjacking by preventing the page from being embedded in a frame.",
    "X-Content-Type-Options": "📦 Stops MIME-sniffing attacks by forcing the browser to respect the declared content-type.",
    "Referrer-Policy": "📤 Controls how much referrer information is sent with requests.",
    "Permissions-Policy": "🎛️ Controls which browser features can be used on the page, like the camera or microphone.",
    "Access-Control-Allow-Origin": "🌐 Defines the CORS (Cross-Origin Resource Sharing) policy, determining which domains are allowed to access the resource."
}

def normalize_url(url):
    """Ensure the URL starts with http:// or https://"""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

def run_http_header_scan(target_url):
    """Scan the provided URL for common security headers and return the results."""
    url = normalize_url(target_url)
    results = []

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        for header, explanation in security_headers.items():
            if header in headers:
                results.append({
                    "header": header,
                    "status": "✅ FOUND",
                    "value": headers[header],
                    "info": explanation
                })
            else:
                results.append({
                    "header": header,
                    "status": "❌ MISSING",
                    "value": None,
                    "info": explanation
                })

    except requests.exceptions.RequestException as e:
        results.append({"error": f"⚠️ Connection error: {str(e)}"})

    return results

def perform_http_header_check(url):
    """Display the results of the HTTP header scan in a professional format."""
    results = run_http_header_scan(url)
    
    if not results:
        return "No results found."

    output = f"\n🔎 Scan Results for: {url}\n"
    output += "📋 --- HTTP Header Check ---\n"

    for item in results:
        if "error" in item:
            output += f"{item['error']}\n"
        else:
            output += f"{item['status']}: {item['header']}\n"
            output += f"   ℹ️ {item['info']}\n"
            if item["value"]:
                output += f"   🧾 Value: {item['value']}\n"
            output += "\n"

    return output

# Optional CLI execution
if __name__ == "__main__":
    target = input("📝 Enter the target URL (e.g., example.com): ").strip()
    result = perform_http_header_check(target)
    print(result)

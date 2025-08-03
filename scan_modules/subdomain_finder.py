import requests
import socket
import json
import concurrent.futures
from urllib.parse import urlparse

class AdvancedSubdomainScanner:
    def __init__(self, target_domain):
        self.target_domain = self.clean_domain(target_domain)
        self.found_subdomains = set()
        self.valid_http_subdomains = []
        self.valid_https_subdomains = []
        self.wordlist = self.get_wordlist()
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    def clean_domain(self, domain):
        parsed = urlparse(domain)
        return parsed.netloc if parsed.netloc else domain.lower().replace('www.', '').strip()

    def get_wordlist(self):
        return [
            "www", "mail", "api", "blog", "ftp", "dev", "staging", "shop",
            "test", "m", "secure", "admin", "app", "cdn", "beta", "alpha"
        ]

    def dns_lookup(self, subdomain):
        try:
            full_domain = f"{subdomain}.{self.target_domain}"
            socket.gethostbyname(full_domain)
            return full_domain
        except:
            return None

    def check_http(self, subdomain):
        full_domain = f"{subdomain}.{self.target_domain}"
        results = {'http': False, 'https': False}

        try:
            https_url = f"https://{full_domain}"
            response = requests.get(https_url, headers=self.headers, timeout=10, verify=False)
            if response.status_code < 400:
                results['https'] = True
                self.valid_https_subdomains.append(https_url)
        except:
            pass

        try:
            http_url = f"http://{full_domain}"
            response = requests.get(http_url, headers=self.headers, timeout=10)
            if response.status_code < 400:
                results['http'] = True
                self.valid_http_subdomains.append(http_url)
        except:
            pass

        return results

    def check_crtsh(self):
        try:
            url = f"https://crt.sh/?q=%25.{self.target_domain}&output=json"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = json.loads(response.text)
                for entry in data:
                    subdomain = entry['name_value'].split('\n')[0].lower()
                    if self.target_domain in subdomain:
                        self.found_subdomains.add(subdomain.replace(f'.{self.target_domain}', ''))
        except:
            pass

    def scan_subdomain(self, subdomain):
        if self.dns_lookup(subdomain):
            self.found_subdomains.add(subdomain)
            return self.check_http(subdomain)
        return None

    def generate_report(self):
        report = []
        report.append("\n🔍 Subdomain Scanner Report:")

        report.append(f"\n📡 DNS Resolved Subdomains: {len(self.found_subdomains)}")
        report.append(f"🔒 HTTPS Available: {len(self.valid_https_subdomains)}")
        report.append(f"🌐 HTTP Available : {len(self.valid_http_subdomains)}")

        if not (self.valid_http_subdomains or self.valid_https_subdomains):
            report.append("\n❌ No active services found.\n")
            return "\n".join(report)

        if self.valid_https_subdomains:
            report.append(f"\n🔒 HTTPS Subdomains:")
            for sub in self.valid_https_subdomains:
                report.append(f"   ✅ {sub}")

        if self.valid_http_subdomains:
            report.append(f"\n🌐 HTTP Subdomains:")
            for sub in self.valid_http_subdomains:
                report.append(f"   ⚠️  {sub}")

        report.append("\n✅ Scan completed.\n")
        return "\n".join(report)

    def perform_scan(self):
        self.check_crtsh()
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(self.scan_subdomain, sub) for sub in self.wordlist]
            for future in concurrent.futures.as_completed(futures):
                future.result()
        return self.generate_report()

def perform_subdomain_finder(url):
    scanner = AdvancedSubdomainScanner(url)
    return scanner.perform_scan()

if __name__ == "__main__":
    target = input("🔗 Enter domain to scan: ")
    result = perform_subdomain_finder(target)
    print(result)

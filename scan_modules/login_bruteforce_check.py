import requests
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class AdvancedLoginScanner:
    def __init__(self, target_url):
        self.target_url = self.normalize_url(target_url)
        self.session = requests.Session()
        self.results = {
            'status': 'not_started',
            'protection': {
                'captcha': False,
                'rate_limit': False,
                'csrf': False,
                'lockout': False,
                '2fa': False
            },
            'credentials_tested': 0,
            'vulnerable': False
        }
        self.COMMON_CREDENTIALS = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password123'},
            {'username': 'root', 'password': 'toor'},
            {'username': 'administrator', 'password': 'admin@123'},
            {'username': 'sysadmin', 'password': 's@pass'},
            {'username': 'test', 'password': 'test1234'},
            {'username': 'admin', 'password': 'Admin@2023'},
            {'username': 'user', 'password': 'Welcome123'},
            {'username': 'admin', 'password': 'P@ssw0rd'},
            {'username': 'superuser', 'password': 'Super@123'}
        ]

    def normalize_url(self, url):
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"
        return url.strip('/') + '/'

    def detect_protections(self):
        try:
            # Initial request analysis
            response = self.session.get(self.target_url, timeout=15)
            content = response.text.lower()
            
            # Protection checks
            self.results['protection']['captcha'] = any(
                kw in content for kw in ['captcha', 'recaptcha', 'hcaptcha']
            )
            self.results['protection']['csrf'] = 'csrf_token' in content
            self.results['protection']['2fa'] = 'two-factor' in content
            
            # Rate limit test
            test_responses = []
            for _ in range(5):
                test_responses.append(
                    self.session.post(
                        self.target_url, 
                        data={'test': 'rate_check'},
                        timeout=10
                    ).status_code
                )
                time.sleep(0.3)
            self.results['protection']['rate_limit'] = 429 in test_responses
            
            # Account lockout test
            lockout_test = self.test_credentials(
                'lockout_test_user', 
                'wrong_password_123!', 
                3
            )
            self.results['protection']['lockout'] = lockout_test == 'locked'
            
            return True
        except Exception as e:
            return False

    def test_credentials(self, username, password, attempts=1):
        try:
            for _ in range(attempts):
                response = self.session.post(
                    self.target_url,
                    data={'username': username, 'password': password},
                    allow_redirects=False,
                    timeout=15
                )
                
                if response.status_code == 403:
                    return 'locked'
                if 'lock' in response.text.lower():
                    return 'locked'
                if response.cookies.get('session'):
                    return 'success'
                if response.status_code in [301, 302]:
                    return 'redirect'
                
                time.sleep(random.uniform(0.5, 1.5))
            
            return 'failed'
        except:
            return 'error'

    def generate_report(self):
        report = [
            "🔒 Login Security Report",
            f"Target: {self.target_url}",
            ""
        ]
        
        # Status Summary
        if self.results['status'] == 'vulnerable':
            report.append("🛑 Critical Vulnerability Found!")
            report.append("System allows access with weak credentials")
        elif self.results['status'] == 'protected':
            report.append("🛡️ Strong Protection Detected")
            report.append("No successful breaches during testing")
        elif self.results['status'] == 'undetected':
            report.append("⚠️ Security Status Unclear")
            report.append("Potential protections may be in place")
        else:
            report.append("❌ Login Form Not Found")
            report.append("No password field detected")
        
        # Protection Details
        report.append("\n🔍 Protection Analysis:")
        protections = [
            ("CAPTCHA", self.results['protection']['captcha']),
            ("Rate Limiting", self.results['protection']['rate_limit']),
            ("CSRF Protection", self.results['protection']['csrf']),
            ("Account Lockout", self.results['protection']['lockout']),
            ("2FA Enabled", self.results['protection']['2fa'])
        ]
        
        for name, status in protections:
            report.append(f"• {name}: {'✅ Active' if status else '❌ Not Found'}")
        
        # Test Summary
        report.append(f"\n📊 Tested {self.results['credentials_tested']} credentials")
        return "\n".join(report)

    def execute_scan(self):
        if not self.detect_login_form():
            self.results['status'] = 'no_form'
            return self.generate_report()
            
        if not self.detect_protections():
            self.results['status'] = 'undetected'
            return self.generate_report()
        
        # Smart credential testing
        tested = 0
        for creds in self.COMMON_CREDENTIALS:
            result = self.test_credentials(creds['username'], creds['password'])
            tested += 1
            
            if result in ['success', 'redirect']:
                self.results.update({
                    'status': 'vulnerable',
                    'vulnerable': True,
                    'credentials_tested': tested
                })
                break
                
            if result == 'locked':
                self.results['status'] = 'protected'
                break
                
            time.sleep(random.uniform(1, 3))
        
        if self.results['status'] == 'not_started':
            self.results['status'] = 'protected' if any(
                self.results['protection'].values()
            ) else 'undetected'
        
        self.results['credentials_tested'] = tested
        return self.generate_report()

    def detect_login_form(self):
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            return bool(soup.find('input', {'type': 'password'}))
        except:
            return False

def perform_login_bruteforce_check(target_url):
    scanner = AdvancedLoginScanner(target_url)
    return scanner.execute_scan()
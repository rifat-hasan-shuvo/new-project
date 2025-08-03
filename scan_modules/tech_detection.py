import requests
import re
from urllib.parse import urlparse
from datetime import datetime

def detect_technologies(url):
    result = []
    try:
        start_time = datetime.now()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.get(url, timeout=15, headers=headers)
        html = response.text.lower()
        headers = {k.lower(): v for k, v in response.headers.items()}

        result.append(f"🔍 Technology Detection Report for {url}")
        result.append(f"🕒 Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        security_headers = {
            'content-security-policy': 'Content Security Policy',
            'strict-transport-security': 'HTTP Strict Transport Security',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-frame-options': 'X-Frame-Options',
            'x-xss-protection': 'X-XSS-Protection'
        }

        result.append(f"\n🛡️ Security Headers:")
        for header, name in security_headers.items():
            if header in headers:
                value = headers[header].split(';')[0]
                result.append(f"  • {name}: ✅ Present ({value})")
            else:
                result.append(f"  • {name}: ❌ Missing")

        result.append(f"\n🖥️ Server Information:")
        server = headers.get('server', 'Not detected')
        powered_by = headers.get('x-powered-by', 'Not detected')
        result.append(f"  • Server: {server}")
        result.append(f"  • Powered By: {powered_by}")

        cms_signatures = {
            'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
            'Drupal': [r'drupal\.js', r'sites/all/modules'],
            'Joomla': [r'/media/system/js/', r'joomla\.org'],
            'Shopify': [r'shopify\.com', r'cdn\.shopify\.com'],
            'Magento': [r'/static/version\d+/', r'magento'],
            'Wix': [r'static\.parastorage\.com', r'wix\.com']
        }

        detected_cms = []
        for cms, patterns in cms_signatures.items():
            for pattern in patterns:
                if re.search(pattern, html):
                    detected_cms.append(cms)
                    break

        result.append(f"\n📦 CMS Detection:")
        if detected_cms:
            result.append(f"✅ Detected CMS:")
            for cms in list(set(detected_cms)):
                result.append(f"  • {cms}")
        else:
            result.append(f"⚠️ No CMS detected")

        js_frameworks = {
            'React': [r'react-dom', r'__reactcontainer__'],
            'Angular': [r'ng-', r'angular\.js'],
            'Vue.js': [r'vue\.js', r'__vue__'],
            'jQuery': [r'jquery.*\.js', r'jquery\(', r'\$\.'],
            'Bootstrap': [r'bootstrap.*\.css', r'bootstrap.*\.js'],
            'Svelte': [r'svelte/internal'],
            'Ember.js': [r'ember\.js', r'data-ember']
        }

        detected_js = []
        for framework, patterns in js_frameworks.items():
            for pattern in patterns:
                if re.search(pattern, html):
                    detected_js.append(framework)
                    break

        result.append(f"\n⚛️ JavaScript Frameworks:")
        if detected_js:
            result.append(f"✅ Detected Frameworks:")
            for js in list(set(detected_js)):
                result.append(f"  • {js}")
        else:
            result.append(f"⚠️ No JavaScript frameworks detected")

        payment_processors = {
            'Stripe': [r'js\.stripe\.com', r'stripe\.js'],
            'PayPal': [r'paypal\.com', r'paypalobjects\.com'],
            'Square': [r'squarecdn\.com', r'squareup\.com'],
            'WooCommerce': [r'woocommerce', r'wc-api='],
            'Amazon Payments': [r'payments\.amazon', r'pay\.amazon\.com']
        }

        detected_payments = []
        for processor, patterns in payment_processors.items():
            for pattern in patterns:
                if re.search(pattern, html):
                    detected_payments.append(processor)
                    break

        result.append(f"\n💰 E-commerce & Payment:")
        if detected_payments:
            result.append(f"✅ Detected Payment Processors:")
            for payment in list(set(detected_payments)):
                result.append(f"  • {payment}")
        else:
            result.append(f"⚠️ No payment processors detected")

        cloud_signatures = {
            'AWS': [r'aws\.amazon\.com', r'amazonaws\.com'],
            'Cloudflare': [r'cloudflare\.com', r'cf-ray'],
            'Google Cloud': [r'googleapis\.com', r'gstatic\.com'],
            'Azure': [r'azure\.com', r'windows\.net'],
            'Firebase': [r'firebaseio\.com']
        }

        detected_cloud = []
        for provider, patterns in cloud_signatures.items():
            for pattern in patterns:
                if re.search(pattern, html):
                    detected_cloud.append(provider)
                    break

        result.append(f"\n☁️ Cloud Providers:")
        if detected_cloud:
            result.append(f"✅ Detected Cloud Providers:")
            for cloud in list(set(detected_cloud)):
                result.append(f"  • {cloud}")
        else:
            result.append(f"⚠️ No cloud providers detected")

        analytics_tools = {
            'Google Analytics': [r'ga\.js', r'google-analytics\.com', r'gtag\.js'],
            'Google Tag Manager': [r'googletagmanager\.com'],
            'Facebook Pixel': [r'facebook\.net', r'fbq\('],
            'Hotjar': [r'hotjar\.com'],
            'LinkedIn Insight': [r'linkedin\.com/insight']
        }

        detected_analytics = []
        for tool, patterns in analytics_tools.items():
            for pattern in patterns:
                if re.search(pattern, html):
                    detected_analytics.append(tool)
                    break

        result.append(f"\n📊 Analytics & Marketing:")
        if detected_analytics:
            result.append(f"✅ Detected Tools:")
            for analytic in list(set(detected_analytics)):
                result.append(f"  • {analytic}")
        else:
            result.append(f"⚠️ No analytics tools detected")

        duration = datetime.now() - start_time
        result.append(f"\n⏱️ Scan completed in {duration.total_seconds():.2f} seconds")

        return '\n'.join(result)

    except requests.exceptions.RequestException as e:
        return f"❌ Error: Failed to analyze {url}\n   Reason: {str(e)}"
    except Exception as e:
        return f"❌ Unexpected error: {str(e)}"

def perform_tech_detection(url):
    return detect_technologies(url)

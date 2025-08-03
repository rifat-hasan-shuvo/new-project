from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# Function for directory bruteforce
def perform_directory_bruteforce(website):
    directories = [
        "/admin", "/login", "/dashboard", "/uploads", "/images", "/js", "/css",
        "/includes", "/api", "/config", "/backup", "/server-status", "/test",
        "/private", "/dev", "/assets", "/cgi-bin", "/tmp", "/data", "/old"
    ]
    
    result = ""
    
    for dir in directories:
        url = website + dir
        print(f"🔍 Testing: {url}")

        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                result += f"[+] Found: {url}\n"
            else:
                result += f"[-] Not Found: {url}\n"
        except:
            result += f"[!] Error checking: {url}\n"
    
    if not result:
        result = "No hidden directories found."

    return result  # ❗ Return a string instead of a dictionary


# Function to perform the full scan
def perform_scan(website, scan_modes):
    result = ""
    
    # Perform directory brute-force scan
    dir_scan_result = perform_directory_bruteforce(website)
    
    result += dir_scan_result  # ✅ This works now because it's a string

    return result


# Index route
@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    
    if request.method == 'POST':
        website = request.form['website']
        if not website.startswith("http"):
            website = "http://" + website

        scan_modes = request.form.getlist('scan_modes')  # In case scan modes are used
        
        result = perform_scan(website, scan_modes)
    
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, request, Response, redirect, url_for, json, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from fpdf import FPDF
import os
import uuid
from datetime import datetime
import re
import time
import threading

# Import your scan modules
from scan_modules.port_scan import perform_port_scan
from scan_modules.ip_location_lookup import perform_ip_location_lookup
from scan_modules.subdomain_finder import perform_subdomain_finder
from scan_modules.directory_bruteforce import perform_directory_bruteforce
from scan_modules.tech_detection import perform_tech_detection
from scan_modules.ssl_check import perform_ssl_check
from scan_modules.http_header_check import perform_http_header_check
from scan_modules.xss_scan import perform_xss_scan
from scan_modules.sqli_test import perform_sqli_test
from scan_modules.login_bruteforce_check import perform_login_bruteforce_check
from scan_modules.dns_security_check import perform_dns_security_check
from scan_modules.server_fingerprinting import perform_server_fingerprinting
from scan_modules.ddos_check import perform_ddos_attack_check

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-123'
app.config['WTF_CSRF_SECRET_KEY'] = 'your-csrf-secret-key-456'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
login_manager.login_view = 'login'

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    purpose = db.Column(db.String(50), nullable=False)
    terms_accepted = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_picture = db.Column(db.Text, default='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAAABmJLR0QA/wD/AP+gvaeTAAABxElEQVRoge3ZvUoDQRSA4C9BI4gvIIiFj+AD2FjY+hwWPoCFjYWd2FhZWFj4AjYWFoKNYGEl2IhFQEBIsBAEwY+1iTGb7M7uzs6G3AOHZHeGc/6Z2Z3dDQKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCCTC3uAfOAPegA/gBjgEDoF1YKxHdWkzB1wBX8An8A7cAofAQi8L02YSuAG+gWfgAJhFGxoF9oFVYKgnFUoYBW6Bb7SBY2AMGAHWgKde1abNJPAIfAP7wLCyfwiY6UVROkyh5uEbsNTDijSZAz5Q87DS21J0WUPNw3GvC9FlDTUPZ70uRJd11Dxc9LoQXbZR8/Dc60J0OUHNw1evC9HlGDUP/8BwtRBY2FVPTwAAAABJRU5ErkJggg==')
    history_file = db.Column(db.String(100), nullable=False, default=lambda: f"history_{uuid.uuid4()}.json")
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

SCAN_MODES = [
    'Port Scan', 'IP Geolocation Lookup', 'Subdomain Finder', 'Directory Bruteforce',
    'Technology Detection', 'SSL Certificate Check', 'HTTP Header Check',
    'XSS Vulnerability Scan', 'SQL Injection Test', 'Login Bruteforce Check',
    'DNS Security Check', 'Server Fingerprinting', 'DDoS Attack Check'
]

ongoing_scans = {}
scan_stop_flags = {}

def load_history(user):
    if not user.history_file or not isinstance(user.history_file, str):
        user.history_file = f"history_{uuid.uuid4()}.json"
        db.session.commit()
    
    history_file = user.history_file
    
    if not os.path.exists(history_file):
        with open(history_file, 'w') as f:
            json.dump([], f)
    
    try:
        with open(history_file, 'r') as file:
            return json.load(file)[-5:]
    except (json.JSONDecodeError, FileNotFoundError):
        return []

def save_to_history(entry, user):
    history = load_history(user)
    history.append(entry)
    if len(history) > 5:
        history = history[-5:]
    with open(user.history_file, 'w') as file:
        json.dump(history, file, indent=4)

def clean_text(text):
    return re.sub(r'[^\x00-\x7F]+', '', text)

def generate_pdf(content, website, scan_type, timestamp):
    pdf = FPDF()
    pdf.add_page()
    pdf.add_font('DejaVu', '', 'DejaVuSans.ttf', uni=True)
    
    # Header
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, f'Security Scan Report: {website}', 0, 1)
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, f'Scan Type: {scan_type.title()} Scan', 0, 1)
    pdf.cell(0, 10, f'Date: {timestamp}', 0, 2)
    pdf.ln(10)
    
    # Content
    pdf.set_font('DejaVu', '', 10)
    cleaned_content = clean_text(content)
    
    # Split into sections
    sections = re.split(r'(=== .* ===)', cleaned_content)
    for section in sections:
        if section.strip():
            if section.startswith('==='):
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 10, section.strip('= '), 0, 1)
                pdf.set_font('DejaVu', '', 10)
            else:
                pdf.multi_cell(0, 5, section)
    
    return pdf.output(dest='S').encode('latin-1', 'replace')

def perform_scan(website, scan_modes, scan_id, user_id):
    with app.app_context():
        user = User.query.get(user_id)
        result = []
        scan_type = 'full' if 'full' in scan_modes else 'custom'
        selected_modes = SCAN_MODES if scan_type == 'full' else scan_modes
        
        try:
            for mode_index, mode in enumerate(selected_modes):
                if scan_stop_flags.get(scan_id):
                    break  # Exit loop if stopped
                
                mode_header = f"\n=== {mode} ===\n"
                result.append(mode_header)
                ongoing_scans[scan_id] = {
                    'status': f"🔄 Starting: {mode} ({mode_index+1}/{len(selected_modes)})",
                    'result': ''.join(result),
                    'website': website,
                    'scan_type': scan_type
                }
                time.sleep(0.5)
                
                try:
                    if mode == 'Port Scan':
                        mode_result = perform_port_scan(website)
                    elif mode == 'IP Geolocation Lookup':
                        mode_result = perform_ip_location_lookup(website)
                    elif mode == 'Subdomain Finder':
                        mode_result = perform_subdomain_finder(website)
                    elif mode == 'Directory Bruteforce':
                        mode_result = perform_directory_bruteforce(website)
                    elif mode == 'Technology Detection':
                        mode_result = perform_tech_detection(website)
                    elif mode == 'SSL Certificate Check':
                        mode_result = perform_ssl_check(website)
                    elif mode == 'HTTP Header Check':
                        mode_result = perform_http_header_check(website)
                    elif mode == 'XSS Vulnerability Scan':
                        mode_result = perform_xss_scan(website)
                    elif mode == 'SQL Injection Test':
                        mode_result = perform_sqli_test(website)
                    elif mode == 'Login Bruteforce Check':
                        mode_result = perform_login_bruteforce_check(website)
                    elif mode == 'DNS Security Check':
                        mode_result = perform_dns_security_check(website)
                    elif mode == 'Server Fingerprinting':
                        mode_result = perform_server_fingerprinting(website)
                    elif mode == 'DDoS Attack Check':
                        mode_result = perform_ddos_attack_check(website)
                    
                    lines = mode_result.split('\n')
                    for line in lines:
                        if scan_stop_flags.get(scan_id):
                            break  # Stop processing lines if stopped
                        if line.strip() and line not in result:
                            result.append(line + '\n')
                            ongoing_scans[scan_id] = {
                                'status': f"🔍 Scanning: {mode} ({mode_index+1}/{len(selected_modes)})",
                                'result': ''.join(result),
                                'website': website,
                                'scan_type': scan_type
                            }
                            time.sleep(0.2)
                    
                    result.append(f"\n✅ Completed: {mode}\n")
                    
                except Exception as e:
                    result.append(f"\n❌ Error in {mode}: {str(e)}\n")
                
                ongoing_scans[scan_id] = {
                    'status': f"✅ Finished: {mode} ({mode_index+1}/{len(selected_modes)})",
                    'result': ''.join(result),
                    'website': website,
                    'scan_type': scan_type
                }
                time.sleep(0.5)
            
            final_result = ''.join(result)
            save_to_history({
                'id': scan_id,
                'website': website,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'result': final_result,
                'scan_type': scan_type
            }, user)
            
            status_message = '⏹ Stopped by user' if scan_id in scan_stop_flags else '✅ Completed'
            ongoing_scans[scan_id] = {
                'status': status_message,
                'result': final_result,
                'website': website,
                'scan_type': scan_type
            }
            time.sleep(3)
        
        finally:
            scan_stop_flags.pop(scan_id, None)
            if scan_id in ongoing_scans:
                del ongoing_scans[scan_id]

@app.route('/')
@login_required
def index():
    return render_template('index.html',
                         scan_modes=SCAN_MODES,
                         history=load_history(current_user))

@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    scan_id = str(uuid.uuid4())
    website = request.form['website'].strip()
    scan_type = request.form.get('scan_type', 'full')
    scan_modes = request.form.getlist('scan_mode') if scan_type == 'custom' else ['full']
    
    if not website:
        return render_template('index.html',
                             error="Please enter a URL",
                             scan_modes=SCAN_MODES,
                             history=load_history(current_user))
    
    ongoing_scans[scan_id] = {'status': '🚀 Initializing scan...', 'result': '', 'website': website, 'scan_type': scan_type}
    thread = threading.Thread(target=perform_scan,
                            args=(website, scan_modes, scan_id, current_user.id))
    thread.start()
    
    return redirect(url_for('live_results', scan_id=scan_id))

# Modify the stop_scan route
@app.route('/stop_scan/<scan_id>', methods=['POST'])
@login_required
def stop_scan(scan_id):
    if scan_id in ongoing_scans:
        scan_stop_flags[scan_id] = True
        # Immediately update status and finalize results
        ongoing_scans[scan_id]['status'] = '⏹ Stopped by User'
        ongoing_scans[scan_id]['result'] += '\n\n[ Scan Aborted by User ]'
        return jsonify(success=True, status='stopped')
    return jsonify(success=False, error='Scan not found'), 404

@app.route('/live_results/<scan_id>')
@login_required
def live_results(scan_id):
    return render_template('live_results.html', scan_id=scan_id)

@app.route('/scan_progress/<scan_id>')
def scan_progress(scan_id):
    def generate():
        while True:
            data = ongoing_scans.get(scan_id, {'status': 'Completed', 'result': ''})
            yield f"data: {json.dumps(data)}\n\n"
            if scan_id not in ongoing_scans:
                break
            time.sleep(0.2)
    return Response(generate(), mimetype='text/event-stream')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid email or password")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        gender = request.form.get('gender')
        purpose = request.form.get('purpose')
        terms = request.form.get('terms')

        errors = []
        if User.query.filter_by(email=email).first():
            errors.append("Email already exists!")
        if password != confirm_password:
            errors.append("Passwords do not match!")
        if not terms:
            errors.append("You must accept the terms of service")

        if errors:
            return render_template('signup.html', error=" | ".join(errors))

        new_user = User(
            full_name=full_name,
            email=email,
            password=generate_password_hash(password),
            gender=gender,
            purpose=purpose,
            terms_accepted=True if terms else False,
            history_file=f"history_{uuid.uuid4()}.json"
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = current_user._get_current_object()
    logout_user()
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('login'))

@app.route('/save_pdf', methods=['POST'])
@login_required
def save_pdf():
    content = request.form.get('pdf_content')
    website = request.form.get('website', 'Unknown Website')
    scan_type = request.form.get('scan_type', 'full')
    timestamp = request.form.get('timestamp', 'Unknown Date')
    
    pdf = generate_pdf(content, website, scan_type, timestamp)
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-disposition": f"attachment; filename={website}_scan_results.pdf"}
    )

@app.route('/history')
@login_required
def history():
    return render_template('history.html', history=load_history(current_user))

@app.route('/history/<history_id>')
@login_required
def view_history(history_id):
    history = load_history(current_user)
    entry = next((h for h in history if h['id'] == history_id), None)
    if entry:
        return render_template('result.html',
                             result=entry['result'],
                             website=entry['website'],
                             timestamp=entry['timestamp'],
                             scan_type=entry.get('scan_type', 'full'))
    return redirect(url_for('history'))

@app.route('/clear_history', methods=['POST'])
@login_required
def clear_history():
    user = current_user._get_current_object()
    history_file = user.history_file
    if os.path.exists(history_file):
        os.remove(history_file)
    user.history_file = f"history_{uuid.uuid4()}.json"
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/update_profile_pic', methods=['POST'])
@login_required
def update_profile_pic():
    user = current_user._get_current_object()
    image_data = request.json.get('image')
    user.profile_picture = image_data
    db.session.commit()
    return jsonify(success=True)

@app.route('/delete_history_entry', methods=['POST'])
@login_required
def delete_history_entry():
    try:
        entry_id = request.form.get('entry_id')
        user = current_user._get_current_object()
        
        # Load current history
        history = load_history(user)
        
        # Filter out the deleted entry
        updated_history = [entry for entry in history if entry['id'] != entry_id]
        
        # Save updated history
        with open(user.history_file, 'w') as f:
            json.dump(updated_history, f, indent=4)
            
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"Error deleting history entry: {str(e)}")
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True) 
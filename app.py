from flask import Flask, request, render_template, jsonify, send_from_directory, redirect, url_for, send_file, session, make_response
from flask_mail import Mail, Message
from datetime import datetime
from flask_talisman import Talisman
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from flask_cors import CORS
from datetime import datetime
from werkzeug.utils import secure_filename
from network_pcap import NetworkAnalyzer 
from PIL import Image
import os
import numpy as np
import io
import re
import sqlite3
import subprocess
import magic 
import bcrypt
import requests
import base64
import random
import string
import time
import nmap
import sys
import traceback
import logging

app = Flask(__name__)
app.secret_key = '123456789'

# Global OTP store
otp_store = {}

app.static_folder = 'static'

if app.config['TESTING']:
    app.config['MAIL_SUPPRESS_SEND'] = True
    app.config['MAIL_DEFAULT_SENDER'] = 'testing@example.com'

@app.route('/static_files')
def list_static_files():
    import os
    static_path = os.path.join(app.root_path, 'static', 'images')
    files = os.listdir(static_path) if os.path.exists(static_path) else []
    return f"Static image files: {files}"

# Directory to save uploaded files
UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DATABASE = 'users.db'

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize the database
def init_db():
    """Initialize the database and create the necessary tables."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        )
    ''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        mac_address TEXT,
        os TEXT,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER,
        port INTEGER,
        state TEXT,
        reason TEXT,
        name TEXT,
        product TEXT,
        version TEXT,
        cpe TEXT,
        extra_info TEXT,
        script_results TEXT,
        FOREIGN KEY (host_id) REFERENCES hosts (id)
    )''')
    
    # Create scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            file_name TEXT,
            file_type TEXT,
            scan_status TEXT NOT NULL,
            scan_results TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create a temporary table for storing OTPs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            otp TEXT NOT NULL,
            created_at TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Ensure the `url` column exists
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN url TEXT;")
    except sqlite3.OperationalError:
        # The column already exists
        pass

    conn.commit()
    conn.close()

# Validate password strength
def is_valid_password(password):
    return bool(re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password))

# Hash password
def hash_password(password):
    """Hash a password for storing"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Check password
def check_password(stored_password, provided_password):
    """Verify the provided password against the stored hash"""
    if isinstance(stored_password, bytes):
        stored_password = stored_password.decode('utf-8')
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))

# Scan a file using ClamAV
def scan_file(file_path):
    try:
        result = subprocess.run(
            ['clamscan', file_path],
            capture_output=True, text=True
        )
        return result.stdout
    except Exception as e:
        return f"Error during scan: {e}"

# Home route
@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('main'))
    return redirect(url_for('index'))

# Index route
@app.route('/main')
def main():
        return render_template('main.html')

# Index route
@app.route('/index')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error="Username and password are required.")

        try:
            # Get the correct database path
            db_path = app.config.get('DATABASE', DATABASE)
            
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                
                # Debug logging
                print(f"Login attempt for user: {username}")
                print(f"User found in database: {user is not None}")
                
                if user:
                    stored_password = user[2]  # Assuming password is the third column
                    if check_password(stored_password, password):
                        # Generate OTP
                        otp = generate_otp()
                        otp_store[username] = otp
                        
                        # Store username in session
                        session['username'] = username
                        
                        # Debug logging
                        print(f"Password verified for user: {username}")
                        print(f"OTP generated: {otp}")
                        
                        # Send OTP if not in testing mode
                        if not app.config.get('TESTING', False):
                            if not send_otp(user[3], otp):
                                return render_template('login.html', error="Failed to send OTP.")
                        
                        return redirect(url_for('verify_otp'))
                    else:
                        print(f"Password verification failed for user: {username}")
                
                return render_template('login.html', error="Invalid username or password.")
                
        except Exception as e:
            print(f"Login error: {str(e)}")  # Debug logging
            return render_template('login.html', error=f"An error occurred: {str(e)}")
            
    return render_template('login.html')

# store_otp function
def store_otp(email, otp):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO password_reset (email, otp, created_at) VALUES (?, ?, ?)",
        (email, otp, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()

# OTP Verification route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        if username in otp_store and otp_store[username] == entered_otp:
            # OTP is valid, log the user in
            session.pop('otp', None)  # Remove OTP after successful login
            return redirect(url_for('index'))
        else:
            return render_template('verify_otp.html', error="Invalid OTP. Please try again.")

    return render_template('verify_otp.html')


# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('main'))

# Setup Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'bbmadhu9@gmail.com' 
app.config['MAIL_PASSWORD'] = 'upjd nqeb lphk yjbj' 
app.config['MAIL_DEFAULT_SENDER'] = ('Advance Malware Scanner' ,'bbmadhu9@gmail.com')

mail = Mail(app)

def send_email(to, subject, body):
    msg = Message(subject, sender='bbmadhu9@gmail.com', recipients=[to])
    msg.body = body
    mail.send(msg)
    

#contactUS route
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Collect data from the form
        name = request.form.get('name')
        email = request.form.get('email')
        gender = request.form.get('inlineRadioOptions')
        city = request.form.get('city')
        details = request.form.get('details')
        address = request.form.get('address')

        # Create the email message
        subject = "New Contact Form Submission"
        body = f"""
        Name: {name}
        Email: {email}
        Gender: {gender}
        City: {city}
        Details: {details}
        Address: {address}
        """
        
        subjectuser = "Recived Your Contact Form Sucessfully"
        bodyuser = f"""
        Dear {name},

Many thanks for your contact form submission.

Please be informed that we are currently processing your contact form submission. Our team will review your Query and we will get in touch with you if we have more questions about your contact form submission.

Best regards,
Madhu Balakrishnan Bashyam

This email is sent from an account we use for sending messages only. Do not reply to this email. For further queries, please contact Madhu Balakrishnan Bashyam at bbmadhu9@gmail.com
        """
        
        try:
            # Send the email
            msg = Message(subject, recipients=['bbmadhu9@gmail.com'], body=body)
            mail.send(msg)
            msg = Message(subjectuser, recipients=[email], body=bodyuser)
            mail.send(msg)
            return render_template('main.html', success="Message sent successfully.")
        except Exception as e:
            print(f"Error sending email: {e}")
            return render_template('contact.html', err="Failed to send the message. Please try again.")

    return render_template('contact.html')

#contactUS2 route
@app.route('/contactus', methods=['GET', 'POST'])
def contactus():
    if request.method == 'POST':
        # Collect data from the form
        names = request.form.get('name')
        emails = request.form.get('email')
        detail = request.form.get('details')

        # Create the email message
        subject = "New Contact Form Submission"
        body = f"""
        Name: {names}
        Email: {emails}
        Details: {detail}
        """
        
        subjectuser = "Recived Your Contact Form Sucessfully"
        bodyuser = f"""
        Dear {names},

Many thanks for your contact form submission.

Please be informed that we are currently processing your contact form submission. Our team will review your Query and we will get in touch with you if we have more questions about your contact form submission.

Best regards,
Madhu Balakrishnan Bashyam

This email is sent from an account we use for sending messages only. Do not reply to this email. For further queries, please contact Madhu Balakrishnan Bashyam at bbmadhu9@gmail.com
        """
        
        try:
            # Send the email
            msg = Message(subject, recipients=['bbmadhu9@gmail.com'], body=body)
            mail.send(msg)
            msg = Message(subjectuser, recipients=[emails], body=bodyuser)
            mail.send(msg)
            return render_template('index.html', success="Message sent successfully.")
        except Exception as e:
            print(f"Error sending email: {e}")
            return render_template('index.html', err="Failed to send the message. Please try again.")

    return render_template('index.html')

# Temporary storage for OTPs
otp_store = {}

# Temporary storage for Email
mail_store = {}

# Generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6)) 

# Send OTP to email
def send_otp(email, otp):
    try:
        msg = Message("Your OTP Code to Login", recipients=[email])
        msg.body = f"Your OTP code is: {otp}"
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
    
#sent OTP to email for forget password
def send_otp_forget(email, otp):
    try:
        msg = Message("Your OTP Code for Forget Password", recipients=[email])
        msg.body = f"Your OTP code is: {otp}"
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        if not username or not password or not email:
            return render_template('register.html', error="All fields are required.")

        if not is_valid_password(password):
            return render_template('register.html', error="Password must meet the strength criteria. Please try again. \n Minimum 8 Characters - Upper Case, Lower Case, Special Character, Digit")

        try:
            # Get the correct database path
            db_path = app.config.get('DATABASE', DATABASE)
            
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()

                # Check if username or email already exists
                cursor.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email))
                if cursor.fetchone():
                    return render_template('register.html', error="Username or email already exists.")

                # Hash password and store user
                hashed_password = hash_password(password)
                cursor.execute("""
                    INSERT INTO users (username, password, email) 
                    VALUES (?, ?, ?)
                """, (username, hashed_password, email))
                conn.commit()

                # Verify the user was created
                cursor.execute("SELECT * FROM users WHERE username=?", (username,))
                user = cursor.fetchone()
                if not user:
                    raise Exception("User creation failed")

                print(f"User created successfully: {username}")  # Debug logging
                return render_template('login.html', success="Registration successful. Please login.")

        except Exception as e:
            print(f"Registration error: {str(e)}")  # Debug logging
            return render_template('register.html', error=f"An error occurred: {str(e)}")

    return render_template('register.html')

#request to reset Password

@app.route('/request_reset', methods=['GET', 'POST'])
def request_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        mail_store["email"] = email 

        if not email:
            return render_template('request_reset.html', error="Email is required.")

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # Check if the email exists in the users table
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            if not cursor.fetchone():
                return render_template('request_reset.html', error="Email not found.")

            # Generate OTP
            import random
            otp = str(random.randint(100000, 999999))

            # Insert OTP into the database or update existing record
            from datetime import datetime
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("""
                INSERT INTO password_reset (email, otp, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET otp = ?, created_at = ?
            """, (email, otp, now, otp, now))
            conn.commit()

            # Send OTP to user's email
            if send_otp_forget(email, otp):
                return render_template('reset_password.html', success="OTP sent successfully.")
            else:
                return render_template('request_reset.html', error="Failed to send OTP. Please try again.")

            
        except Exception as e:
            print(f"Error in /request_reset: {str(e)}")
            return render_template('request_reset.html', error="An error occurred. Please try again.")
        finally:
            conn.close()

    return render_template('request_reset.html')

#reset Password

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = mail_store["email"]
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')

        if not email or not otp or not new_password:
            return render_template('reset_password.html', error="All fields are required.")
        
        if not is_valid_password(new_password):
            return render_template('reset_password.html', error="Password must meet the strength criteria.")

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # Validate OTP
            cursor.execute("SELECT created_at FROM password_reset WHERE email = ? AND otp = ?", (email, otp))
            record = cursor.fetchone()

            if not record:
                return render_template('reset_password.html', error="Invalid OTP or email.")
            
            # Check if OTP has expired
            from datetime import datetime, timedelta
            otp_created_at = datetime.strptime(record[0], '%Y-%m-%d %H:%M:%S')
            if datetime.now() > otp_created_at + timedelta(minutes=10):
                return render_template('reset_password.html', error="OTP has expired.")

            # Hash the new password
            hashed_password = hash_password(new_password)

            # Update the user's password
            cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
            conn.commit()

            # Delete the OTP record
            cursor.execute("DELETE FROM password_reset WHERE email = ?", (email,))
            conn.commit()

            return render_template('login.html', success="Password reset successfully. Please log in.")
        except Exception as e:
            return render_template('reset_password.html', error=f"Error: {str(e)}")
        finally:
            conn.close()

    return render_template('reset_password.html')




# VirusTotal API settings
VIRUSTOTAL_API_KEY = 'e122b3366821a70c09306e66e9ff5d19267550fb7944b7cd1500cd2167412a93'  # Replace with your actual API key
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls/'

def encode_url(url):
    """
    VirusTotal API expects the URL to be base64-encoded.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip()

def check_url_with_virustotal(url):
    """
    Check if a URL is malicious by querying VirusTotal's API.
    Returns detailed scan results or an error message.
    """
    # Encode the URL
    encoded_url = encode_url(url)
    
    # Set up headers with the API key for authentication
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    
    # Send a GET request to the VirusTotal API
    response = requests.get(VIRUSTOTAL_URL + encoded_url, headers=headers)
    
    # Check if the request was successful
    if response.status_code == 200:
        data = response.json()
        
        if 'data' in data:
            scan_data = data['data']['attributes']['last_analysis_results']
            malicious_count = sum(1 for result in scan_data.values() if result['category'] == 'malicious')
            total_count = len(scan_data)

            # Create a more detailed result to pass to the template
            detailed_results = {
                'total_scanners': total_count,
                'malicious_scanners': malicious_count,
                
            }

            return detailed_results
        else:
            return {"error": "Error: Unable to fetch scan data from VirusTotal."}
    else:
        return {"error": f"Error: Unable to contact VirusTotal API. Status code: {response.status_code}"}

# File upload and URL scan route
@app.route('/scan_url', methods=['GET', 'POST'])
def scan_url():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('scan_url.html')

    url = request.form.get('url')
    if not url:
        return render_template('scan_url.html', error="URL is required.")
    
    # Check if the URL is malicious using VirusTotal
    scan_result = check_url_with_virustotal(url)
    
    # Determine scan status
    if 'malicious_scanners: 0' in scan_result:
        url_scan_status = 'The uploaded URL is infected or suspicious.'
    else:
        url_scan_status = 'The uploaded URL appears safe.'

    # Handle the case where scan_result does not contain 'scan_details'
    if 'error' in scan_result:
        return render_template('scan_url.html', 
            url=url, 
            scan_result=None, 
            error=scan_result['error'])
    
    # Store the result in the database
    try:
        username = session['username']
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_id = cursor.fetchone()[0]

        cursor.execute('''
            INSERT INTO scans (user_id, url, scan_status, scan_results)
            VALUES (?, ?, ?, ?)
        ''', (user_id, url, str(url_scan_status), str(scan_result)))
        conn.commit()
        conn.close()

    except Exception as e:
        return render_template('scan_url.html', error=f"An error occurred while saving results: {str(e)}")

    return render_template('scan_url_result.html', url=url, scan_result=scan_result)

# Route to display scan results
@app.route('/scan_url_result')
def scan_url_result():
    url = request.args.get('url')
    status = request.args.get('status')
    results = request.args.get('results')

    return render_template('scan_url_result.html', url=url, scan_status=status, scan_results=results)
def perform_scan(url):
    # Replace this with actual vulnerability scanning logic
    return f"Scan for {url} completed successfully. No vulnerabilities found."


# File upload and scan route
@app.route('/scan_file', methods=['GET', 'POST'])
def scan_file_route():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('scan_file.html')
    
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('scan_file.html', error='No file part')

        file = request.files['file']
        if file.filename == '':
            return render_template('scan_file.html', error='No selected file')

        # Save file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        try:
            # Detect file type
            file_type = magic.from_file(file_path, mime=True)

            # Scan file with ClamAV
            scan_results = scan_file(file_path)

            # Determine scan status
            if 'Infected files: 0' in scan_results:
                scan_status = 'The uploaded file appears safe.'
            else:
                scan_status = 'The uploaded file is infected or suspicious.'

            # Store scan result in database
            if 'username' in session:
                username = session['username']
                conn = sqlite3.connect(DATABASE)
                cursor = conn.cursor()

                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                user_id = cursor.fetchone()[0]

                cursor.execute('''
                    INSERT INTO scans (user_id, file_name, file_type, scan_status, scan_results)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, file.filename, file_type, scan_status, scan_results))
                conn.commit()
                conn.close()

            # Redirect to the result page with the scan details
            return render_template('result.html', file_type=file_type, scan_status=scan_status, scan_results=scan_results)

        except Exception as e:
            return render_template('scan_file.html', 
                                error=f"An error occurred during scanning: {str(e)}")
        finally:
            # Clean up - remove the uploaded file
            if os.path.exists(file_path):
                os.remove(file_path)

# View scan history route
@app.route('/scan_history')
def scan_history():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = cursor.fetchone()[0]

    cursor.execute("SELECT * FROM scans WHERE user_id = ?", (user_id,))
    scans = cursor.fetchall()
    conn.close()

    return render_template('scan_history.html', scans=scans)

#perform nmap scan
@app.route('/nmap_scan', methods=['GET', 'POST'])
def nmap_scan():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('nmap_scan.html')
    
    target = request.form.get('target', '')
    scan_type = request.form.get('scan_type', '')
    nm = nmap.PortScanner()
    print(f"Received target: {target}")
    print(f"Received scan_type: {scan_type}")
    
    if not target: 
        return "Target is required."

    try:
        # Perform an advanced scan
        if scan_type == 'deep':
            scan_result = nm.scan(hosts=target, arguments='-A -sV --version-all --script vuln --script=banner')
        else:
            scan_result = nm.scan(hosts=target, arguments='-sV')
        scan_output = scan_result.get('scan', {}).get(target, {})
        
        # Host information
        hostnames = scan_output.get('hostnames', [])
        mac_address = scan_output.get('addresses', {}).get('mac', 'unknown')
        os_matches = scan_output.get('osmatch', [{}])
        os_info = ', '.join([f"{os['name']} (Accuracy: {os['accuracy']}%)" for os in os_matches if os.get('name')])

        # Insert host data into the database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO hosts (target, mac_address, os) VALUES (?, ?, ?)",
            (target, mac_address, os_info)
        )
        host_id = cursor.lastrowid

        # Services information
        if 'tcp' in scan_output:
            for port, details in scan_output['tcp'].items():
                script_results = details.get('script', {})
                script_text = ', '.join([f"{k}: {v}" for k, v in script_results.items()])
                cursor.execute(
                    '''INSERT INTO services 
                    (host_id, port, state, reason, name, product, version, cpe, extra_info, script_results) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (
                        host_id, port, details.get('state', 'unknown'),
                        details.get('reason', 'unknown'), details.get('name', 'unknown'),
                        details.get('product', 'unknown'), details.get('version', 'unknown'),
                        details.get('cpe', 'unknown'), details.get('extrainfo', 'unknown'),
                        script_text
                    )
                )
        conn.commit()
        conn.close()

        return redirect(url_for('nmap_results'))
    except Exception as e:
        return f"An error occurred: {e}"

@app.route('/nmap_results', methods=['GET'])
def nmap_results():
    target_query = request.args.get('target', '').strip()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    if target_query:
        cursor.execute('''
            SELECT h.id, h.target, h.mac_address, h.os, h.scan_time, 
                s.port, s.state, s.reason, s.name, s.product, 
                s.version, s.cpe, s.extra_info, s.script_results
            FROM hosts h
            LEFT JOIN services s ON h.id = s.host_id
            WHERE h.target LIKE ?
            ORDER BY h.scan_time DESC, h.id, s.port
        ''', (f'%{target_query}%',))
    else:
        cursor.execute('''
            SELECT h.id, h.target, h.mac_address, h.os, h.scan_time, 
                s.port, s.state, s.reason, s.name, s.product, 
                s.version, s.cpe, s.extra_info, s.script_results
            FROM hosts h
            LEFT JOIN services s ON h.id = s.host_id
            ORDER BY h.scan_time DESC, h.id, s.port
        ''')

    results = cursor.fetchall()
    conn.close()
    
    if not results:
        return "No results found."

    return render_template('nmap_results.html', results=results)


def generate_password(length=12):
    """Generates a secure random password."""
    if length < 4: 
        length = 4
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('password.html')
    data = request.get_json()
    length = data.get('length', 12)
    password = generate_password(length)
    return jsonify({'password': password})

# Function to calculate password strength
def check_password_strength(password):
    """
    Evaluate password strength based on multiple criteria
    """
    if len(password) < 8:
        return 'Weak'

    complexity_score = 0
    
    if re.search(r'[A-Z]', password):
        complexity_score += 1
    
    if re.search(r'[a-z]', password):
        complexity_score += 1
    
    if re.search(r'\d', password):
        complexity_score += 1
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        complexity_score += 1
    
    if complexity_score <= 1 and len(password) < 12:
        return 'Weak'
    elif complexity_score <= 2:
        return 'Medium'
    else:
        return 'Strong'

@app.route('/check_password', methods=['GET','POST'])
def password_strength():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('password_strength.html')
    data = request.json
    password = data.get('password', '')
    
    strength = check_password_strength(password)
    
    return jsonify({
        'strength': strength,
        'length': len(password)
    })

# Function to Encode and Decode Images
def encode_image(image_path, secret_message):
    
    # Convert message to binary
    message_bits = ''.join(format(ord(char), '08b') for char in secret_message)
    message_bits += '11111111'  # End of message marker
    
    # Open the image
    img = Image.open(image_path)
    pixels = np.array(img)
    
    # Flatten the image
    flat_pixels = pixels.flatten()
    
    # Embed message bits
    for i, bit in enumerate(message_bits):
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit)
    
    # Reshape back to original image shape
    modified_pixels = flat_pixels.reshape(pixels.shape)
    
    # Create modified image
    modified_img = Image.fromarray(modified_pixels.astype(np.uint8))
    
    # Save modified image
    output_path = os.path.join(UPLOAD_FOLDER, 'encoded_image.png')
    modified_img.save(output_path)
    
    return output_path

def decode_image(image_path):
    
    # Open the image
    img = Image.open(image_path)
    pixels = np.array(img)
    
    # Flatten the image
    flat_pixels = pixels.flatten()
    
    # Extract bits
    bits = [str(pixel & 1) for pixel in flat_pixels]
    
    # Convert bits to message
    message_bits = ''.join(bits)
    
    # Find message (until end marker)
    full_bytes = [message_bits[i:i+8] for i in range(0, len(message_bits), 8)]
    
    decoded_message = ''
    for byte in full_bytes:
        if byte == '11111111':  # End of message marker
            break
        decoded_message += chr(int(byte, 2))
    
    return decoded_message

@app.route('/encode', methods=['GET', 'POST'])
def encode():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('steganography.html')
    """
    Endpoint to encode a message into an image
    """
    # Check if the post request has the file part
    if 'image' not in request.files or 'message' not in request.form:
        return jsonify({'error': 'Missing image or message'}), 400
    
    image = request.files['image']
    secret_message = request.form['message']
    
    # Save the uploaded image
    input_path = os.path.join(UPLOAD_FOLDER, 'input_image.png')
    image.save(input_path)
    
    try:
        # Encode the message
        output_path = encode_image(input_path, secret_message)
        
        # Return the encoded image
        return send_file(output_path, mimetype='image/png')
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    finally:
        # Clean up - remove the uploaded file
        if os.path.exists(input_path):
            os.remove(input_path)

@app.route('/decode', methods=['GET','POST'])
def decode():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('steganography.html')
    """
    Endpoint to decode a message from an image
    """
    # Check if the post request has the file part
    if 'image' not in request.files:
        return jsonify({'error': 'Missing image'}), 400
    
    image = request.files['image']
    
    # Save the uploaded image
    input_path = os.path.join(UPLOAD_FOLDER, 'encoded_image.png')
    image.save(input_path)
    
    try:
        # Decode the message
        message = decode_image(input_path)
        
        return jsonify({'message': message})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    finally:
        # Clean up - remove the uploaded file
        if os.path.exists(input_path):
            os.remove(input_path)

# PCAP Analysis
@app.route('/analyze_pcap', methods=['GET','POST'])
def analyze_pcap():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('pcap.html')
    
    try:
        # Detailed logging for debugging
        logging.debug(f"Request files: {request.files}")
        logging.debug(f"Request form: {request.form}")
        
        # Check if file is present in the request
        if 'pcap_file' not in request.files:
            logging.error("No file part in request")
            return jsonify({
                'error': 'No file part in request',
                'status': 'error'
            }), 400
        
        file = request.files['pcap_file']
        
        # Check if filename is empty
        if file.filename == '':
            logging.error("No selected file")
            return jsonify({
                'error': 'No selected file',
                'status': 'error'
            }), 400
        
        
        # Secure the filename to prevent path traversal attacks
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
        logging.info(f"Saving file: {filepath}")
            
        # Save the file
        file.save(filepath)
            
        try:
            # Dynamically import NetworkAnalyzer to handle potential import errors
            from network_pcap import NetworkAnalyzer
                
            # Initialize NetworkAnalyzer and analyze the file
            analyzer = NetworkAnalyzer()
            analysis_results = analyzer.analyze_pcap(filepath)
                
            # Optional: Remove the file after analysis to save space
            os.remove(filepath)
                
            logging.info("PCAP file analyzed successfully")
            return jsonify({
                'status': 'success',
                'analysis': analysis_results
            })
            
        except ImportError as ie:
            logging.error(f"Import error: {ie}")
            traceback.print_exc()
            return jsonify({
                'error': f'Import error: {str(ie)}',
                'status': 'error'
            }), 500
            
        except Exception as e:
            # Handle any errors during file processing
            logging.error(f"Analysis error: {e}")
            traceback.print_exc()
                
            if os.path.exists(filepath):
                os.remove(filepath)
                
            return jsonify({
                'error': str(e),
                'status': 'error'
            }), 500
        
        # If file type is not allowed
        logging.warning(f"Disallowed file type: {file.filename}")
        return jsonify({
            'error': 'File type not allowed. Only .pcap and .pcapng files are supported.',
            'status': 'error'
        }), 400
    
    except Exception as e:
        # Catch-all for any unexpected errors
        logging.critical(f"Unexpected error: {e}")
        traceback.print_exc()
        return jsonify({
            'error': 'An unexpected error occurred',
            'status': 'error'
        }), 500

# File Encryption/Decryption Route
@app.route('/encrypt_decrypt', methods=['GET','POST'])
def process_file():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('file_en_de.html')

if __name__ == '__main__':
    init_db() 
    app.run(debug=True, host='0.0.0.0', port=80)

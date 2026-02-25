from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import base64
import re
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import json

app = Flask(__name__)
CORS(app)

def check_xss_vulnerability(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        xss_vulnerable = False
        vulnerable_forms = []

        for form in forms:
            inputs = form.find_all('input')
            for input_field in inputs:
                if input_field.get('type') in ['text', 'search', 'url', 'tel', 'email']:
                    xss_payload = '<script>alert("XSS")</script>'
                    # Check if the form is vulnerable to XSS
                    if xss_payload in str(form):
                        xss_vulnerable = True
                        vulnerable_forms.append(str(form))

        return {
            'vulnerable': xss_vulnerable,
            'forms': vulnerable_forms
        }
    except Exception as e:
        return {'error': str(e)}

def check_sql_injection(url):
    try:
        response = requests.get(url)
        sql_patterns = [
            r'SQL syntax',
            r'mysql_fetch_array',
            r'ORA-',
            r'PostgreSQL',
            r'SQLite',
            r'SQL Server'
        ]
        
        vulnerable = False
        found_patterns = []
        
        for pattern in sql_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                vulnerable = True
                found_patterns.append(pattern)

        return {
            'vulnerable': vulnerable,
            'patterns': found_patterns
        }
    except Exception as e:
        return {'error': str(e)}

def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not Set'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set')
        }
        return security_headers
    except Exception as e:
        return {'error': str(e)}

def check_ssl_certificate(url):
    try:
        hostname = url.split('://')[1].split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    'valid': True,
                    'expires': cert['notAfter'],
                    'issuer': dict(x[0] for x in cert['issuer'])
                }
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def decode_base64(text):
    try:
        decoded = base64.b64decode(text).decode('utf-8')
        return {'success': True, 'result': decoded}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def caesar_cipher(text, shift):
    try:
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return {'success': True, 'result': result}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def decode_hex(text):
    try:
        # Remove spaces and convert to bytes
        text = text.replace(" ", "")
        decoded = bytes.fromhex(text).decode('utf-8')
        return {'success': True, 'result': decoded}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def decode_binary(text):
    try:
        # Remove spaces and convert to bytes
        text = text.replace(" ", "")
        decoded = ''.join(chr(int(text[i:i+8], 2)) for i in range(0, len(text), 8))
        return {'success': True, 'result': decoded}
    except Exception as e:
        return {'success': False, 'error': str(e)}

@app.route('/scan', methods=['POST'])
def scan_website():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    results = {
        'xss': check_xss_vulnerability(url),
        'sql_injection': check_sql_injection(url),
        'security_headers': check_security_headers(url),
        'ssl': check_ssl_certificate(url)
    }
    
    return jsonify(results)

@app.route('/decode', methods=['POST'])
def decode_text():
    data = request.get_json()
    text = data.get('text')
    encoding_type = data.get('type')
    shift = data.get('shift', 0)
    
    if not text or not encoding_type:
        return jsonify({'error': 'Text and encoding type are required'}), 400
    
    result = None
    if encoding_type == 'base64':
        result = decode_base64(text)
    elif encoding_type == 'caesar':
        result = caesar_cipher(text, int(shift))
    elif encoding_type == 'hex':
        result = decode_hex(text)
    elif encoding_type == 'binary':
        result = decode_binary(text)
    else:
        return jsonify({'error': 'Invalid encoding type'}), 400
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000) 
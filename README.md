Web Vulnerability Scanner & ENCODER

========================

A modern web application for scanning websites for common vulnerabilities and decoding various types of encoded text.

Features
--------
1. Vulnerability Scanning:
   - XSS (Cross-Site Scripting) vulnerability detection
   - SQL Injection vulnerability detection
   - Security headers analysis
   - SSL certificate verification

2. Encoding/Decoding Tools:
   - Base64 decoding
   - URL encoding decoding
   - Caesar cipher (with adjustable shift)
   - Hex decoding
   - Binary decoding
   - ROT13 decoding

Requirements
-----------
Python 3.7 or higher
pip (Python package installer)

Dependencies
-----------
- Flask==3.0.0
- requests==2.31.0
- beautifulsoup4==4.12.2
- python-nmap==0.7.1
- flask-cors==4.0.0

Installation
-----------
1. Clone the repository:
   git clone [repository-url]

2. Navigate to the project directory:
   cd web-vulnerability-scanner

3. Install the required packages:
   pip install -r requirements.txt

Usage
-----
1. Start the Python backend server:
   python scanner.py

2. Open index.html in your web browser

3. To scan a website:
   - Enter the URL in the input field
   - Click the "Scan" button
   - View the results in the cards below

4. To decode text:
   - Enter the encoded text in the textarea
   - Select the encoding type from the dropdown
   - For Caesar cipher, adjust the shift value (-25 to 25)
   - Click the "Decode" button
   - View the decoded result

Project Structure
----------------
- scanner.py: Backend server with vulnerability scanning and encoding/decoding functions
- index.html: Frontend interface
- styles.css: Styling and layout
- script.js: Frontend functionality
- requirements.txt: Python dependencies

Security Notes
-------------
- This tool is for educational and testing purposes only
- Always obtain proper authorization before scanning websites
- Some websites may block automated scanning attempts
- Use responsibly and in accordance with applicable laws and regulations

Contributing
-----------
Contributions are welcome! Please feel free to submit a Pull Request.

License
-------
This project is licensed under the MIT License - see the LICENSE file for details.

Author
------
[Your Name]

Version
-------
1.0.0

Last Updated
-----------
2024

Support
-------
For support, please open an issue in the repository or contact [your-email].

Disclaimer
----------
This tool is provided as-is without any warranties. Users are responsible for ensuring they have proper authorization before scanning any websites.

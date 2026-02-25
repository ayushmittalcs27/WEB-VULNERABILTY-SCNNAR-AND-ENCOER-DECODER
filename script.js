document.addEventListener('DOMContentLoaded', () => {
    const API_URL = 'http://localhost:5000';
    
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const encodedText = document.getElementById('encodedText');
    const encodingType = document.getElementById('encodingType');
    const shiftValue = document.getElementById('shiftValue');
    const caesarShift = document.getElementById('caesarShift');
    const decodeBtn = document.getElementById('decodeBtn');

    // Show/hide Caesar shift input based on encoding type
    encodingType.addEventListener('change', () => {
        caesarShift.classList.toggle('hidden', encodingType.value !== 'caesar');
    });

    // Website Scanner
    scanBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        if (!url) {
            alert('Please enter a valid URL');
            return;
        }

        try {
            scanBtn.disabled = true;
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

            const response = await fetch(`${API_URL}/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url }),
            });

            const data = await response.json();

            // Update XSS results
            const xssResult = document.getElementById('xssResult');
            if (data.xss.vulnerable) {
                xssResult.innerHTML = `<span class="vulnerable">Vulnerable to XSS</span><br>Found ${data.xss.forms.length} vulnerable forms`;
            } else {
                xssResult.innerHTML = '<span class="safe">No XSS vulnerabilities detected</span>';
            }

            // Update SQL Injection results
            const sqlResult = document.getElementById('sqlResult');
            if (data.sql_injection.vulnerable) {
                sqlResult.innerHTML = `<span class="vulnerable">Vulnerable to SQL Injection</span><br>Found patterns: ${data.sql_injection.patterns.join(', ')}`;
            } else {
                sqlResult.innerHTML = '<span class="safe">No SQL Injection vulnerabilities detected</span>';
            }

            // Update Security Headers results
            const headersResult = document.getElementById('headersResult');
            let headersHtml = '';
            for (const [header, value] of Object.entries(data.security_headers)) {
                headersHtml += `${header}: ${value}<br>`;
            }
            headersResult.innerHTML = headersHtml;

            // Update SSL Certificate results
            const sslResult = document.getElementById('sslResult');
            if (data.ssl.valid) {
                sslResult.innerHTML = `<span class="safe">Valid SSL Certificate</span><br>Expires: ${data.ssl.expires}<br>Issuer: ${Object.values(data.ssl.issuer).join(', ')}`;
            } else {
                sslResult.innerHTML = `<span class="warning">Invalid SSL Certificate</span><br>${data.ssl.error}`;
            }

        } catch (error) {
            console.error('Error scanning website:', error);
            alert('Error scanning website. Please try again.');
        } finally {
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="fas fa-search"></i> Scan';
        }
    });

    // Text Decoder
    decodeBtn.addEventListener('click', async () => {
        const text = encodedText.value.trim();
        if (!text) {
            alert('Please enter text to decode');
            return;
        }

        try {
            decodeBtn.disabled = true;
            decodeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Decoding...';

            const payload = {
                text,
                type: encodingType.value,
            };

            if (encodingType.value === 'caesar') {
                payload.shift = parseInt(shiftValue.value);
            }

            const response = await fetch(`${API_URL}/decode`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
            });

            const data = await response.json();
            const decodedResult = document.getElementById('decodedResult');

            if (data.success) {
                decodedResult.innerHTML = `<pre>${data.result}</pre>`;
            } else {
                decodedResult.innerHTML = `<span class="vulnerable">Error: ${data.error}</span>`;
            }

        } catch (error) {
            console.error('Error decoding text:', error);
            alert('Error decoding text. Please try again.');
        } finally {
            decodeBtn.disabled = false;
            decodeBtn.innerHTML = '<i class="fas fa-key"></i> Decode';
        }
    });
}); 
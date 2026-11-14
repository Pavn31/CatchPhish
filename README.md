🛡️ CatchPhish

Detect phishing. Stay protected.

CatchPhish is a security-first phishing and scam analysis platform that helps people understand suspicious links, messages, screenshots, and QR codes before they interact with them.

<p align="center">
  <a href="https://catchphish-front.onrender.com/"><strong>🚀 Open CatchPhish</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/Pavn31/CatchPhish">View source</a>
</p>
<p align="center">
  <img src="frontend/assets/Icon.png" width="96" alt="CatchPhish logo">
</p>

Think before you click. Paste suspicious content, upload a screenshot, or scan a QR image to get a clear risk assessment and practical safety guidance.

✨ What CatchPhish can do

Capability	Description
🔗 URL intelligence	Inspects redirects, punycode, encoded paths, risky TLDs, shorteners, downloads, and suspicious URL patterns.
💬 Message analysis	Detects phishing, WhatsApp scams, SMS fraud, phone pressure, brand impersonation, and multilingual scam signals.
🖼️ Screenshot analysis	Uses OCR to extract suspicious text from uploaded screenshots without storing the image.
📱 QR analysis	Decodes QR destinations and checks for payment, login, and scam-related warning signs.
🧪 Web attack detection	Flags common SQL injection and cross-site scripting payloads.
📊 Risk scoring	Converts detected signals into an easy-to-understand severity score and explanation.
🧭 Actionable guidance	Explains what was detected, the potential impact, and what to do next.
🔐 Private workspace	Supports authenticated sessions and scan history persistence when configured.

🧠 How it works

Paste content or upload an image
            ↓
   CatchPhish extracts signals
            ↓
  Rules + URL intelligence scan
            ↓
 Risk score, indicators, and guidance

Images are processed in memory for analysis and are not stored by the image-analysis endpoint.

🧰 Built with

* Frontend: HTML, CSS, vanilla JavaScript
* Backend: Python, FastAPI
* Image processing: Pillow, OpenCV, Tesseract OCR
* Authentication: FastAPI sessions with protected password handling
* Persistence: SQLite with optional Supabase integration
* Threat intelligence: URLScan.io integration
* Deployment: Render

🚀 Run locally

1. Clone the repository

git clone https://github.com/Pavn31/CatchPhish.git
cd CatchPhish

2. Install backend dependencies

python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt

3. Start the API

uvicorn backend.main:app --reload --port 8000

4. Serve the frontend

In a second terminal:

python3 -m http.server 5500 --directory frontend

Then open http://127.0.0.1:5500.

For optional integrations, configure the required values in backend/.env. Never commit API keys, session secrets, or other credentials.

🔌 API endpoints

Method	Endpoint	Purpose
POST	/api/analyze	Analyze a URL, message, email, or payload.
POST	/api/analyze/image	Analyze a screenshot or QR image.
GET	/api/health	Check API availability.
GET	/api/urlscan/{scan_id}	Retrieve a URLScan result.

🧪 Run tests

python -m pytest -q backend/test_security_features.py

🌍 Live deployment

Service	Link
Live website	catchphish-front.onrender.com
Frontend	catchphish-front.onrender.com
Backend API	catchphish-bxab.onrender.com

👥 Project team

<table>
  <tr>
    <td align="center"><a href="https://github.com/Pavn31"><img src="https://github.com/Pavn31.png" width="80" alt="Pavn31"><br><strong>Pavn31</strong></a></td>
    <td align="center"><a href="https://github.com/Seema-patil24"><img src="https://github.com/Seema-patil24.png" width="80" alt="Seema-patil24"><br><strong>Seema-patil24</strong></a></td>
    <td align="center"><a href="https://github.com/Shetty22"><img src="https://github.com/Shetty22.png" width="80" alt="Shetty22"><br><strong>Shetty22</strong></a></td>
    <td align="center"><a href="https://github.com/skk-07"><img src="https://github.com/skk-07.png" width="80" alt="skk-07"><br><strong>skk-07</strong></a></td>
  </tr>
</table>

🤝 Contributing

Ideas, bug reports, and improvements are welcome. Open an issue or submit a pull request with a clear description of the change.

<p align="center">
  <strong>Built with care by the CatchPhish team.</strong><br>
  <sub>Stay alert. Verify first. Click second.</sub>
</p>
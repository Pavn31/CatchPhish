 <p align="center">
  <img src="frontend/assets/Icon.png" width="100" alt="CatchPhish Icon" />
</p>

<h1 align="center">CatchPhish</h1>

<p align="center">
  <strong>Detect threats. Stay aware. Browse safely.</strong>
  <br />
  A minimal phishing detection tool for suspicious URLs and messages.
</p>

<p align="center">
  <a href="https://catchphish.pavn31.dpdns.org/">
    <img src="https://img.shields.io/badge/LIVE%20DEMO-8B5CF6?style=flat-square&logo=vercel&logoColor=white" alt="Live Demo" />
  </a>
  <a href="https://github.com/Pavn31/CatchPhish">
    <img src="https://img.shields.io/badge/GITHUB-18181B?style=flat-square&logo=github&logoColor=white" alt="GitHub" />
  </a>
  <img src="https://img.shields.io/badge/STATUS-Live-22C55E?style=flat-square" alt="Project Status" />
</p>

---

## About

CatchPhish is a web-based phishing detection application that analyzes suspicious URLs and messages to help users identify potential online threats.

It evaluates suspicious indicators and generates a risk score, verdict, and analysis summary to support safer digital experiences.

## Features

- **URL Analysis** — Detect suspicious URL patterns.
- **Message Analysis** — Analyze potentially malicious emails, SMS messages, and text.
- **Risk Scoring** — Generate a score and verdict based on detected indicators.
- **Threat Indicators** — Display signals identified during analysis.
- **User Authentication** — Sign-up and login functionality.
- **Dark Interface** — A clean, minimal security dashboard.

## Tech Stack

| Component | Technology |
|:--|:--|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python, FastAPI |
| Database | SQLite |
| Authentication | Session-based |
| Deployment | Vercel |

## Live Demo

<p align="center">
  <a href="https://catchphish.pavn31.dpdns.org/">
    <strong>↗ Open CatchPhish</strong>
  </a>
</p>

Test the application with a URL or message you want to analyze. Do not submit passwords, authentication codes, or other sensitive information.

## Team

<p align="center">
  <a href="https://github.com/Pavn31">
    <img src="https://github.com/Pavn31.png" width="80" alt="Pavn31" />
    <br /><strong>Pavn31</strong>
  </a>
  <br />Project Contributor
</p>

<p align="center">
  <a href="https://github.com/Seema-patil24">
    <img src="https://github.com/Seema-patil24.png" width="80" alt="Seema Patil" />
    <br /><strong>Seema Patil</strong>
  </a>
  &nbsp;&nbsp;&nbsp;
  <a href="https://github.com/Shetty22">
    <img src="https://github.com/Shetty22.png" width="80" alt="Shetty22" />
    <br /><strong>Shetty22</strong>
  </a>
  &nbsp;&nbsp;&nbsp;
  <a href="https://github.com/skk-07">
    <img src="https://github.com/skk-07.png" width="80" alt="skk-07" />
    <br /><strong>skk-07</strong>
  </a>
</p>

### Contributions

Our team works collaboratively on application development, phishing detection logic, interface design, testing, and documentation.

## Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/Pavn31/CatchPhish.git
cd CatchPhish
```

### 2. Set up the backend

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment.

**Linux / macOS**

```bash
source .venv/bin/activate
```

**Windows**

```powershell
.venv\Scripts\activate
```

Install dependencies and start the API:

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Backend URL: `http://127.0.0.1:8000`

API documentation: `http://127.0.0.1:8000/docs`

### 3. Launch the frontend

Open `frontend/index.html` using a local development server, such as VS Code Live Server.

Ensure the frontend's API configuration points to the backend URL.

## Security Notice

- Detection results are indicative, not a guarantee that a URL or message is safe.
- Avoid opening suspicious links or entering credentials on unverified websites.
- Never commit passwords, secret keys, or private user data to the repository.

## License

No license has been specified. All rights are reserved by default until a license is added.

---

<p align="center">
  <img src="frontend/assets/Icon.png" width="36" alt="CatchPhish" />
  <br /><br />
  <strong>CatchPhish</strong>
  <br />
  <sub>Built for a safer digital world.</sub>
  <br /><br />
  <a href="https://catchphish.pavn31.dpdns.org/">Website</a>
  ·
  <a href="https://github.com/Pavn31/CatchPhish">Repository</a>
</p>
# CatchPhish

<p align="center">
  <img src="https://img.shields.io/badge/CatchPhish-Phishing%20Detection-8b5cf6?style=for-the-badge&logo=shield&logoColor=white" alt="CatchPhish"/>
  <img src="https://img.shields.io/badge/Status-Live-22c55e?style=for-the-badge" alt="Live"/>
</p>

<p align="center">
  <strong>Detect threats. Stay aware. Browse safely.</strong>
  <br/>
  A web-based phishing detection tool designed to help identify suspicious URLs and messages.
  <br/><br/>
  <a href="https://catchphish.pavn31.dpdns.org/"><strong>Visit Live Website →</strong></a>
</p>

---

## About

**CatchPhish** is a phishing detection web application that analyzes URLs and suspicious messages to help users recognize potential online threats.

It evaluates suspicious indicators and provides a risk score, verdict, and analysis summary to support safer browsing decisions.

## Features

- **URL Analysis** — Analyze URLs for suspicious patterns.
- **Message Analysis** — Check suspicious messages for potential phishing indicators.
- **Risk Scoring** — Get a risk score and verdict based on detected indicators.
- **Threat Indicators** — Understand the signals that contribute to the analysis.
- **User Authentication** — Sign-up and login functionality.
- **Web Interface** — A simple interface for analyzing potential threats.

> CatchPhish provides heuristic-based analysis. Results are indicative and should not be treated as a guarantee that a URL or message is safe.

## Tech Stack

| Component | Technology |
|:--|:--|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python, FastAPI |
| Database | SQLite |
| Authentication | Session-based authentication |
| Deployment | Vercel |

## Live Demo

**Website:** https://catchphish.pavn31.dpdns.org/

Open the live application and test it with a URL or message you want to analyze. Avoid submitting sensitive or private information.

## Team

Meet the people behind CatchPhish.

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/Pavn31">
        <img src="https://github.com/Pavn31.png" width="90" alt="Pavn31's GitHub avatar"/>
        <br/><strong>Pavn31</strong>
      </a>
      <br/>Project Contributor
    </td>
    <td align="center">
      <a href="https://github.com/Seema-patil24">
        <img src="https://github.com/Seema-patil24.png" width="90" alt="Seema-patil24's GitHub avatar"/>
        <br/><strong>Seema Patil</strong>
      </a>
      <br/>Project Contributor
    </td>
    <td align="center">
      <a href="https://github.com/Shetty22">
        <img src="https://github.com/Shetty22.png" width="90" alt="Shetty22's GitHub avatar"/>
        <br/><strong>Shetty22</strong>
      </a>
      <br/>Project Contributor
    </td>
    <td align="center">
      <a href="https://github.com/skk-07">
        <img src="https://github.com/skk-07.png" width="90" alt="skk-07's GitHub avatar"/>
        <br/><strong>skk-07</strong>
      </a>
      <br/>Project Contributor
    </td>
  </tr>
</table>

### Contributions

Our team collaborates on developing, improving, and maintaining CatchPhish. Contributions may include application development, detection logic, interface improvements, testing, and documentation.

## Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/Pavn31/CatchPhish.git
cd CatchPhish
```

### 2. Start the backend

```bash
cd backend
python -m venv .venv
```

Activate the environment:

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

The backend API should be available at `http://127.0.0.1:8000`.

API documentation: `http://127.0.0.1:8000/docs`

### 3. Open the frontend

Open `frontend/index.html` using a local development server, such as VS Code Live Server.

Make sure the frontend API configuration points to your local backend.

## Security Notice

- Do not rely exclusively on automated phishing detection.
- Never enter passwords, banking details, or other sensitive information into suspicious websites.
- Do not commit secrets, credentials, or private user data to the repository.

## License

No license has been specified yet. All rights are reserved by default unless a license is added to this repository.

---

<p align="center">
  <strong>CatchPhish</strong>
  <br/>
  Built to promote safer digital experiences.
  <br/><br/>
  <a href="https://github.com/Pavn31/CatchPhish">GitHub Repository</a>
  ·
  <a href="https://catchphish.pavn31.dpdns.org/">Live Demo</a>
</p>
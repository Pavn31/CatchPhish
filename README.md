# ◈ CatchPhish

<p align="center">
  <strong>Phishing Detection · Digital Safety</strong>
  <br />
  Identify suspicious URLs and messages before they become a threat.
</p>

<p align="center">
  <a href="https://catchphish.pavn31.dpdns.org/">↗ Live Demo</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/Pavn31/CatchPhish">⌘ Repository</a>
</p>

---

## Overview

CatchPhish is a web-based phishing detection tool that analyzes URLs and suspicious messages to identify potential online threats.

It provides a risk score, verdict, and analysis summary to help users make more informed decisions online.

## Features

- **URL Analysis** — Identify suspicious URL patterns.
- **Message Analysis** — Examine potentially fraudulent messages.
- **Risk Scoring** — View an estimated risk score and verdict.
- **Threat Indicators** — Understand the signals detected during analysis.
- **Authentication** — User sign-up and login functionality.
- **Minimal Interface** — Simple, accessible web experience.

## Tech Stack

| Layer | Technology |
|:--|:--|
| Frontend | HTML · CSS · JavaScript |
| Backend | Python · FastAPI |
| Database | SQLite |
| Authentication | Session-based |
| Deployment | Vercel |

## Live Application

**[catchphish.pavn31.dpdns.org ↗](https://catchphish.pavn31.dpdns.org/)**

Try analyzing a suspicious URL or message. Never submit passwords, authentication codes, or private information.

## Team

| Member | GitHub |
|:--|:--|
| Pavn31 | [@Pavn31 ↗](https://github.com/Pavn31) |
| Seema Patil | [@Seema-patil24 ↗](https://github.com/Seema-patil24) |
| Shetty22 | [@Shetty22 ↗](https://github.com/Shetty22) |
| skk-07 | [@skk-07 ↗](https://github.com/skk-07) |

### Contributions

Our team collaborates on application development, detection logic, interface design, testing, and documentation.

## Run Locally

### 1. Clone

```bash
git clone https://github.com/Pavn31/CatchPhish.git
cd CatchPhish
```

### 2. Configure the backend

```bash
cd backend
python -m venv .venv
```

Activate the environment.

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

API: `http://127.0.0.1:8000`

API documentation: `http://127.0.0.1:8000/docs`

### 3. Launch the frontend

Open `frontend/index.html` using a local development server, such as VS Code Live Server.

Ensure the frontend API configuration points to your running backend.

## Security

- Detection results are estimates, not guarantees that a URL or message is safe.
- Never enter sensitive credentials on unverified websites.
- Keep API secrets and private data out of the repository.

## License

No license has been specified. All rights are reserved by default until a license is added.

---

<p align="center">
  <sub>CatchPhish · Built for a safer digital world.</sub>
  <br /><br />
  <a href="https://catchphish.pavn31.dpdns.org/">Website</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/Pavn31/CatchPhish">Source Code</a>
</p>

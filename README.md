
# CatchPhish

A rule-based phishing detection web application built with Python, FastAPI, HTML, CSS, and JavaScript.

## Features

- Analyze suspicious messages and URLs
- Calculate a risk score from 0–100
- Display detected indicators and severity
- Responsive cybersecurity terminal interface

## Requirements

- Python 3.12+
- pip
- Git
- VS Code with Live Server (recommended)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

## Run the backend

From the project root:

```bash
uvicorn backend.main:app --reload
```

API documentation: http://127.0.0.1:8000/docs

## Run the frontend

Open `frontend/index.html` using VS Code Live Server.

## Disclaimer

CatchPhish uses heuristic rules. A low risk score does not guarantee that content is safe.

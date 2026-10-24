import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.sessions import SessionMiddleware

# ---------------------------- Configuration ----------------------------

load_dotenv(Path(__file__).with_name(".env"))

IS_PRODUCTION = os.getenv("ENVIRONMENT", "production").lower() == "production"
FRONTEND_ORIGIN = "https://catchphish-front.onrender.com"
FRONTEND_URLS = [
    FRONTEND_ORIGIN,
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:5501",
    "http://localhost:5501",
]
FRONTEND_URLS.extend(
    item.strip().rstrip("/")
    for item in os.getenv("FRONTEND_URLS", "").split(",")
    if item.strip()
)
extra_frontend = os.getenv("FRONTEND_URL", "").strip().rstrip("/")
if extra_frontend:
    FRONTEND_URLS.append(extra_frontend)

SESSION_SECRET = os.getenv("SESSION_SECRET", "")
if not SESSION_SECRET:
    if IS_PRODUCTION:
        # Configure SESSION_SECRET in Render environment variables for persistent sessions.
        SESSION_SECRET = secrets.token_urlsafe(48)
    else:
        SESSION_SECRET = secrets.token_urlsafe(48)

DATABASE_PATH = Path(
    os.getenv("DATABASE_PATH", str(Path(__file__).with_name("catchphish.db")))
)
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="CatchPhish API",
    description="Email/password authentication and phishing risk analysis",
    version="3.1.1",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(dict.fromkeys(FRONTEND_URLS)),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="none" if IS_PRODUCTION else "lax",
    https_only=IS_PRODUCTION,
    max_age=60 * 60 * 24 * 7,
)

# ---------------------------- Database ----------------------------

def get_db():
    connection = sqlite3.connect(DATABASE_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


initialize_database()

# ---------------------------- Password Security ----------------------------

def hash_password(password: str, salt_hex: str | None = None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 310_000
    )
    return password_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    candidate_hash, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(candidate_hash, stored_hash)


def public_user(row):
    return {
        "id": str(row["id"]),
        "name": row["name"],
        "email": row["email"],
        "provider": "email",
    }

# ---------------------------- Request Models ----------------------------

class SignupRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value):
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Please enter your name.")
        return value

    @field_validator("email")
    @classmethod
    def clean_email(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("Please enter a valid email address.")
        return value


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def clean_email(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("Please enter a valid email address.")
        return value


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, max_length=10000)

# ---------------------------- Phishing Analysis ----------------------------

def add_indicator(indicators, name, description, severity, points):
    indicators.append({
        "name": name,
        "description": description,
        "severity": severity,
        "points": points,
    })


def extract_urls(text):
    pattern = r"(?i)\b(?:https?://|www\.)[^\s<>\"']+"
    urls = []
    for item in re.findall(pattern, text):
        cleaned = item.rstrip(".,!?;:)]}")
        if cleaned and cleaned not in urls:
            urls.append(cleaned)

    # Recognize bare domains, while avoiding email addresses.
    domain_pattern = (
        r"(?i)(?<![@\w.-])"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}"
        r"(?::\d{1,5})?"
        r"(?:/[^\s<>\"']*)?"
    )
    for item in re.findall(domain_pattern, text):
        cleaned = item.rstrip(".,!?;:)]}")
        if cleaned and cleaned not in urls:
            urls.append(cleaned)
    return urls[:30]


def inspect_url(raw_url, indicators):
    candidate = raw_url
    if not re.match(r"(?i)^https?://", candidate):
        candidate = "http://" + candidate
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
    except ValueError:
        parsed, hostname = None, None

    if not hostname:
        add_indicator(indicators, "Malformed URL", "The URL could not be parsed reliably.", "HIGH", 25)
        return

    hostname = hostname.lower().rstrip(".")
    if parsed and parsed.username is not None:
        add_indicator(indicators, "URL contains user information", "Text before the @ symbol can disguise the actual destination.", "HIGH", 25)

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        add_indicator(indicators, "IP address used as hostname", "The link uses a raw IP address instead of a conventional domain.", "MEDIUM", 20)
    if hostname.startswith("xn--") or ".xn--" in hostname:
        add_indicator(indicators, "Punycode domain", "The domain uses encoded international characters that may disguise its appearance.", "HIGH", 25)
    if hostname.count(".") >= 4:
        add_indicator(indicators, "Unusually nested subdomains", "Multiple subdomains can make the actual destination harder to recognize.", "MEDIUM", 12)
    if len(hostname) > 50:
        add_indicator(indicators, "Unusually long hostname", "The hostname is unusually long and deserves closer inspection.", "LOW", 8)
    if parsed and parsed.scheme.lower() == "http":
        add_indicator(indicators, "Unencrypted HTTP link", "The URL does not use HTTPS. This alone does not prove phishing.", "LOW", 5)

    shorteners = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "ow.ly", "buff.ly"}
    if hostname in shorteners:
        add_indicator(indicators, "URL shortener", "The destination is hidden behind a URL-shortening service.", "MEDIUM", 15)

    suspicious_terms = {"login", "verify", "secure", "account", "update", "password", "wallet", "signin", "auth", "confirm"}
    if set(re.split(r"[.-]", hostname)) & suspicious_terms:
        add_indicator(indicators, "Sensitive-action wording in domain", "The hostname contains terms commonly associated with account access or verification.", "MEDIUM", 12)

    if parsed:
        query_and_path = (parsed.path + "?" + parsed.query).lower()
        if len(parsed.query) > 150:
            add_indicator(indicators, "Long URL query string", "A long query string may contain tracking or redirect parameters.", "LOW", 5)
        if re.search(r"(?:redirect|return_url|continue|next|url)=", query_and_path):
            add_indicator(indicators, "Potential redirect parameter", "The URL contains a parameter that may control a redirect destination.", "MEDIUM", 10)


def analyze_content(content):
    text = content.strip()
    lowered = text.lower()
    indicators = []
    keyword_rules = [
        ("Urgent account threat", r"\b(?:account.{0,30}(?:suspend|locked|blocked|disabled)|(?:suspend|lock|block|disable).{0,30}account)\b", "The message threatens an account restriction to pressure the recipient.", "HIGH", 20),
        ("Credential request", r"\b(?:enter|submit|confirm|verify|provide|share).{0,40}(?:password|passcode|login credentials|pin|otp|one[- ]time code)\b", "The message asks for sensitive authentication information.", "HIGH", 25),
        ("Financial or payment pressure", r"\b(?:urgent payment|wire transfer|payment required|unpaid invoice|failed payment|bank account blocked)\b", "The content uses financial urgency that can appear in phishing attempts.", "MEDIUM", 15),
        ("Prize or reward lure", r"\b(?:you have won|you've won|claim your prize|free gift|selected winner|claim reward)\b", "The message uses a prize or reward to encourage interaction.", "MEDIUM", 15),
        ("Urgency language", r"\b(?:act now|immediately|urgent|within 24 hours|expires today|final warning|immediate action|required action)\b", "Urgent wording may be used to prevent careful verification.", "MEDIUM", 12),
        ("Suspicious verification request", r"\b(?:verify your identity|verify your account|confirm your identity|unusual activity detected|security alert|account verification)\b", "The message requests verification or claims suspicious account activity.", "MEDIUM", 12),
        ("Suspicious attachment", r"\b(?:open the attachment|enable macros|download the attached file|attached invoice)\b", "The message encourages opening an attachment that should be verified first.", "MEDIUM", 12),
        ("One-time code request", r"\b(?:send|share|reply with|tell us).{0,25}(?:otp|one[- ]time password|verification code|security code)\b", "The message asks the recipient to share a verification code.", "HIGH", 25),
    ]
    for name, pattern, description, severity, points in keyword_rules:
        if re.search(pattern, lowered, re.DOTALL):
            add_indicator(indicators, name, description, severity, points)

    urls = extract_urls(text)
    if not urls and re.search(r"(?i)\b(?:https?://|www\.)", text):
        add_indicator(indicators, "Unrecognized URL structure", "A URL-like string was found but could not be extracted reliably.", "LOW", 5)
    for url in urls:
        inspect_url(url, indicators)
    if len(urls) >= 4:
        add_indicator(indicators, "Multiple links", "The content contains several URLs, which may warrant extra scrutiny.", "LOW", 8)

    unique_indicators = []
    seen = set()
    for indicator in indicators:
        if indicator["name"] not in seen:
            seen.add(indicator["name"])
            unique_indicators.append(indicator)
    score = min(100, sum(item["points"] for item in unique_indicators))
    if score >= 75:
        verdict = "High risk"
        summary = "Multiple or serious phishing indicators were found. Do not follow links or provide sensitive information without independent verification."
    elif score >= 45:
        verdict = "Suspicious content"
        summary = "Several risk indicators were found. Verify the sender and destination using a trusted, independent channel."
    elif score >= 20:
        verdict = "Potential risk"
        summary = "Some suspicious patterns were found. Review the findings carefully before interacting with the content."
    else:
        verdict = "Low detected risk"
        summary = "Few known phishing patterns were detected. This does not establish that the content or destination is safe."
    return {"risk_score": score, "verdict": verdict, "summary": summary, "indicators": unique_indicators}

# ---------------------------- API Routes ----------------------------

@app.get("/")
def root():
    return {"name": "CatchPhish", "status": "online", "docs": "/docs"}


@app.get("/api/health")
def health():
    return {"status": "healthy"}


@app.post("/api/analyze")
def analyze(payload: AnalyzeRequest):
    content = payload.content.strip()
    if not content:
        raise HTTPException(status_code=422, detail="Please provide text or a URL to analyze.")
    try:
        return analyze_content(content)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="An internal analysis error occurred.") from exc


@app.post("/api/auth/signup", status_code=201)
def signup(payload: SignupRequest, request: Request):
    name = payload.name.strip()
    email = payload.email.strip().lower()
    password_hash, password_salt = hash_password(payload.password)
    try:
        with get_db() as connection:
            cursor = connection.execute(
                "INSERT INTO users (name, email, password_hash, password_salt) VALUES (?, ?, ?, ?)",
                (name, email, password_hash, password_salt),
            )
            row = connection.execute(
                "SELECT id, name, email FROM users WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="An account with this email already exists. Please log in.")
    user = {"id": str(row["id"]), "name": row["name"], "email": row["email"], "provider": "email"}
    request.session.clear()
    request.session["user"] = user
    return {"message": "Account created successfully.", "user": user}


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request):
    email = payload.email.strip().lower()
    with get_db() as connection:
        row = connection.execute(
            "SELECT id, name, email, password_hash, password_salt FROM users WHERE email = ? COLLATE NOCASE",
            (email,),
        ).fetchone()
    if not row or not verify_password(payload.password, row["password_hash"], row["password_salt"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    user = public_user(row)
    request.session.clear()
    request.session["user"] = user
    return {"message": "Login successful.", "user": user}


@app.get("/api/auth/me")
def current_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not signed in.")
    return {"user": user}


@app.post("/api/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True, "message": "Logged out successfully."}

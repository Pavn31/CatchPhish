
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
import sqlite3
import warnings

from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit, unquote

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.sessions import SessionMiddleware


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv(Path(__file__).with_name(".env"))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("catchphish")

IS_PRODUCTION = os.getenv("ENVIRONMENT", "production").lower() == "production"

FRONTEND_ORIGIN = "https://catchphish-front.onrender.com"

FRONTEND_URLS = [
    FRONTEND_ORIGIN,
]

if not IS_PRODUCTION:
    FRONTEND_URLS.extend([
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5501",
    ])

FRONTEND_URLS.extend(
    item.strip().rstrip("/")
    for item in os.getenv("FRONTEND_URLS", "").split(",")
    if item.strip()
)

extra_frontend = os.getenv("FRONTEND_URL", "").strip().rstrip("/")

if extra_frontend:
    FRONTEND_URLS.append(extra_frontend)

FRONTEND_URLS = list(dict.fromkeys(FRONTEND_URLS))

SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()

if not SESSION_SECRET:
    if IS_PRODUCTION:
        warnings.warn(
            "SESSION_SECRET is not configured. Sessions will not survive "
            "application restarts. Set a permanent secret in Render.",
            RuntimeWarning,
        )

    SESSION_SECRET = secrets.token_urlsafe(48)

DATABASE_PATH = Path(
    os.getenv(
        "DATABASE_PATH",
        str(Path(__file__).with_name("catchphish.db")),
    )
)

DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

MAX_CONTENT_LENGTH = 10_000
MAX_URLS = 30
PASSWORD_ITERATIONS = 600_000


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="CatchPhish API",
    description="Phishing, scam and suspicious URL risk analysis",
    version="4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_URLS,
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


# ============================================================
# DATABASE
# ============================================================

def get_db():
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=20,
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 20000")

    return connection


def initialize_database():
    with get_db() as connection:
        connection.execute("PRAGMA journal_mode = WAL")

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


# ============================================================
# PASSWORD SECURITY
# ============================================================

def hash_password(password: str, salt_hex: str | None = None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )

    return password_hash.hex(), salt.hex()


def verify_password(
    password: str,
    stored_hash: str,
    salt_hex: str,
) -> bool:
    candidate_hash, _ = hash_password(password, salt_hex)

    return hmac.compare_digest(candidate_hash, stored_hash)


def public_user(row):
    return {
        "id": str(row["id"]),
        "name": row["name"],
        "email": row["email"],
        "provider": "email",
    }


# ============================================================
# REQUEST MODELS
# ============================================================

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


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

        if not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Please enter a valid email address.")

        return value


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def clean_email(cls, value):
        value = value.strip().lower()

        if not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Please enter a valid email address.")

        return value


class AnalyzeRequest(BaseModel):
    content: str = Field(
        min_length=1,
        max_length=MAX_CONTENT_LENGTH,
    )


# ============================================================
# DETECTION CONFIGURATION
# ============================================================

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "rb.gy",
    "ow.ly",
    "buff.ly",
    "lnkd.in",
    "soo.gd",
}

# Known domains are used only to detect obvious brand/domain mismatches.
# This is not a complete list of official domains.
BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "telegram": ["telegram.org"],
    "sbi": ["sbi.co.in"],
    "icici": ["icicibank.com"],
    "hdfc": ["hdfcbank.com"],
    "axis": ["axisbank.com"],
    "irctc": ["irctc.co.in"],
}


# Each rule has a category, severity, points and explanation.
# Scores are heuristic risk indicators, not probabilities.

CONTENT_RULES = [
    {
        "name": "Credential request",
        "category": "credentials",
        "pattern": (
            r"\b(?:enter|submit|provide|share|send|confirm|verify)"
            r".{0,50}\b(?:password|passcode|login credentials|pin)\b"
        ),
        "severity": "HIGH",
        "points": 28,
        "description": "The message requests sensitive login information.",
    },
    {
        "name": "OTP theft attempt",
        "category": "credentials",
        "pattern": (
            r"\b(?:share|send|reply with|tell us|provide|enter)"
            r".{0,45}\b(?:otp|one[- ]time password|verification code|security code)\b"
        ),
        "severity": "CRITICAL",
        "points": 35,
        "description": "The message asks for a one-time password or verification code.",
    },
    {
        "name": "Account suspension threat",
        "category": "account_threat",
        "pattern": (
            r"\b(?:account.{0,40}(?:suspend|locked|blocked|disabled)"
            r"|(?:suspend|lock|block|disable).{0,40}account)\b"
        ),
        "severity": "HIGH",
        "points": 20,
        "description": "The message threatens account restrictions to pressure the recipient.",
    },
    {
        "name": "KYC verification pressure",
        "category": "financial",
        "pattern": (
            r"\b(?:kyc|know your customer).{0,60}"
            r"(?:expire|expired|update|verify|block|suspend|complete|required)\b"
            r"|\b(?:update|complete|verify).{0,40}\bkyc\b"
        ),
        "severity": "HIGH",
        "points": 25,
        "description": "The message uses KYC verification or expiry pressure.",
    },
    {
        "name": "Banking or payment threat",
        "category": "financial",
        "pattern": (
            r"\b(?:bank account|account|card|upi).{0,45}"
            r"(?:blocked|suspended|frozen|deactivated|expired)\b"
        ),
        "severity": "HIGH",
        "points": 22,
        "description": "The message connects a banking or payment account with a threat.",
    },
    {
        "name": "Urgent financial transfer",
        "category": "financial",
        "pattern": (
            r"\b(?:urgent payment|wire transfer|immediate transfer|"
            r"send money immediately|payment required|unpaid invoice|"
            r"failed payment|transfer funds now)\b"
        ),
        "severity": "HIGH",
        "points": 20,
        "description": "The content pressures the recipient to make a payment or transfer.",
    },
    {
        "name": "Digital arrest scam language",
        "category": "digital_arrest",
        "pattern": (
            r"\b(?:digital arrest|online arrest|"
            r"you are under surveillance|"
            r"video call.{0,30}(?:police|cbi|crime branch)|"
            r"stay on (?:the )?video call.{0,30}(?:police|officer))\b"
        ),
        "severity": "CRITICAL",
        "points": 38,
        "description": "The content contains language associated with digital-arrest impersonation scams.",
    },
    {
        "name": "Law-enforcement impersonation",
        "category": "impersonation",
        "pattern": (
            r"\b(?:cbi|cyber crime|police|enforcement directorate|"
            r"customs officer|income tax officer).{0,65}"
            r"(?:arrest|case registered|warrant|investigation|"
            r"money laundering|criminal activity)\b"
        ),
        "severity": "HIGH",
        "points": 25,
        "description": "The message may be impersonating a law-enforcement or government authority.",
    },
    {
        "name": "Threat of arrest or legal action",
        "category": "digital_arrest",
        "pattern": (
            r"\b(?:arrest warrant|immediate arrest|"
            r"arrested if you|legal action.{0,30}payment|"
            r"pay.{0,30}avoid arrest|criminal case.{0,30}payment)\b"
        ),
        "severity": "HIGH",
        "points": 25,
        "description": "The content uses arrest or legal consequences to pressure the recipient.",
    },
    {
        "name": "Remote access application request",
        "category": "remote_access",
        "pattern": (
            r"\b(?:install|download|open).{0,55}"
            r"(?:anydesk|teamviewer|quick.?support|"
            r"remote desktop|screen.?sharing app)\b"
        ),
        "severity": "CRITICAL",
        "points": 35,
        "description": "The message asks the recipient to install or use remote-access software.",
    },
    {
        "name": "Screen sharing request",
        "category": "remote_access",
        "pattern": (
            r"\b(?:share|show|mirror|allow access to).{0,35}"
            r"(?:your screen|mobile screen|phone screen)\b"
        ),
        "severity": "HIGH",
        "points": 22,
        "description": "The message requests access to the recipient's screen.",
    },
    {
        "name": "Suspicious APK installation",
        "category": "malicious_app",
        "pattern": (
            r"\b(?:install|download|open|enable).{0,55}"
            r"(?:apk|unknown app|application from whatsapp|"
            r"application from telegram|outside play store)\b"
        ),
        "severity": "HIGH",
        "points": 25,
        "description": "The message encourages installation of an application from an unverified source.",
    },
    {
        "name": "Unknown application permission request",
        "category": "malicious_app",
        "pattern": (
            r"\b(?:enable|grant|allow).{0,45}"
            r"(?:accessibility permission|screen recording|"
            r"sms permission|notification access|device administrator)\b"
        ),
        "severity": "HIGH",
        "points": 25,
        "description": "The content requests powerful device permissions that could be abused.",
    },
    {
        "name": "Prize or reward lure",
        "category": "social_engineering",
        "pattern": (
            r"\b(?:you have won|you've won|claim your prize|"
            r"free gift|selected winner|claim reward|"
            r"lottery winner|cash prize)\b"
        ),
        "severity": "MEDIUM",
        "points": 15,
        "description": "The content uses a prize or reward to encourage interaction.",
    },
    {
        "name": "Urgency language",
        "category": "urgency",
        "pattern": (
            r"\b(?:act now|immediately|urgent|within 24 hours|"
            r"expires today|final warning|immediate action|required action|"
            r"last chance|account will be closed)\b"
        ),
        "severity": "MEDIUM",
        "points": 12,
        "description": "Urgent wording may be used to prevent careful verification.",
    },
    {
        "name": "Suspicious verification request",
        "category": "verification",
        "pattern": (
            r"\b(?:verify your identity|verify your account|"
            r"confirm your identity|unusual activity detected|"
            r"security alert|account verification)\b"
        ),
        "severity": "MEDIUM",
        "points": 12,
        "description": "The message requests identity verification or claims suspicious account activity.",
    },
    {
        "name": "Suspicious attachment",
        "category": "attachment",
        "pattern": (
            r"\b(?:open the attachment|enable macros|"
            r"download the attached file|attached invoice|"
            r"run the attached file)\b"
        ),
        "severity": "MEDIUM",
        "points": 14,
        "description": "The message encourages opening or executing an attachment.",
    },
]


# ============================================================
# INDICATOR HELPERS
# ============================================================

def add_indicator(
    indicators,
    name,
    description,
    severity,
    points,
    category,
):
    indicators.append({
        "name": name,
        "description": description,
        "severity": severity,
        "points": points,
        "category": category,
    })


# ============================================================
# URL EXTRACTION
# ============================================================

URL_PATTERN = re.compile(
    r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
)

BARE_DOMAIN_PATTERN = re.compile(
    r"""(?i)(?<![@\w.-])"""
    r"""(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"""
    r"""[a-z]{2,63}"""
    r"""(?::\d{1,5})?"""
    r"""(?:/[^\s<>"']*)?"""
)


def clean_url_candidate(value):
    return value.rstrip(".,!?;:)]}>")


def extract_urls(text):
    urls = []
    seen = set()

    for pattern in (URL_PATTERN, BARE_DOMAIN_PATTERN):
        for match in pattern.findall(text):
            candidate = clean_url_candidate(match)

            if candidate and candidate.lower() not in seen:
                seen.add(candidate.lower())
                urls.append(candidate)

            if len(urls) >= MAX_URLS:
                return urls

    return urls


# ============================================================
# DOMAIN HELPERS
# ============================================================

def normalize_hostname(hostname):
    hostname = hostname.lower().rstrip(".")

    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname


def get_domain_labels(hostname):
    return [
        label
        for label in hostname.lower().split(".")
        if label
    ]


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def inspect_brand_impersonation(hostname, indicators):
    labels = get_domain_labels(hostname)

    for brand, official_domains in BRAND_DOMAINS.items():
        if brand not in labels:
            continue

        legitimate = any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in official_domains
        )

        if not legitimate:
            add_indicator(
                indicators,
                "Possible brand impersonation",
                f"The hostname contains the brand name '{brand}' but does not match its configured official domain.",
                "HIGH",
                28,
                "brand_impersonation",
            )
            return


# ============================================================
# URL ANALYSIS
# ============================================================

def inspect_url(raw_url, indicators):
    candidate = raw_url.strip()

    if not re.match(r"(?i)^https?://", candidate):
        candidate = "https://" + candidate

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        add_indicator(
            indicators,
            "Malformed URL",
            "The URL contains invalid formatting or an invalid port.",
            "HIGH",
            25,
            "url_structure",
        )
        return

    if not hostname:
        add_indicator(
            indicators,
            "Malformed URL",
            "The URL does not contain a valid hostname.",
            "HIGH",
            25,
            "url_structure",
        )
        return

    hostname = normalize_hostname(hostname)

    if parsed.username is not None or parsed.password is not None:
        add_indicator(
            indicators,
            "URL contains embedded credentials",
            "Text before the @ symbol can disguise the actual destination.",
            "HIGH",
            30,
            "url_structure",
        )

    if is_ip_address(hostname):
        add_indicator(
            indicators,
            "IP address used as hostname",
            "The link uses a raw IP address instead of a conventional domain.",
            "HIGH",
            22,
            "url_structure",
        )

    if hostname.startswith("xn--") or ".xn--" in hostname:
        add_indicator(
            indicators,
            "Punycode domain",
            "The hostname uses encoded international characters that may disguise its appearance.",
            "HIGH",
            25,
            "url_structure",
        )

    labels = get_domain_labels(hostname)

    if len(labels) >= 5:
        add_indicator(
            indicators,
            "Unusually nested subdomains",
            "The hostname contains many subdomain levels, which can make the destination harder to recognize.",
            "MEDIUM",
            12,
            "url_structure",
        )

    if len(hostname) > 55:
        add_indicator(
            indicators,
            "Unusually long hostname",
            "The hostname is unusually long and deserves closer inspection.",
            "LOW",
            8,
            "url_structure",
        )

    if parsed.scheme.lower() == "http":
        add_indicator(
            indicators,
            "Unencrypted HTTP link",
            "The URL does not use HTTPS. This alone does not prove phishing.",
            "LOW",
            5,
            "transport",
        )

    if hostname in SHORTENERS:
        add_indicator(
            indicators,
            "URL shortener",
            "The destination is hidden behind a URL-shortening service.",
            "MEDIUM",
            15,
            "url_obfuscation",
        )

    suspicious_terms = {
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "wallet",
        "signin",
        "auth",
        "confirm",
        "support",
        "banking",
    }

    if set(labels) & suspicious_terms:
        add_indicator(
            indicators,
            "Sensitive-action wording in domain",
            "The hostname contains terms commonly associated with account access or verification.",
            "MEDIUM",
            12,
            "url_language",
        )

    inspect_brand_impersonation(hostname, indicators)

    if port is not None and port not in {80, 443}:
        add_indicator(
            indicators,
            "Non-standard URL port",
            "The URL uses a non-standard web port. Verify the destination before opening it.",
            "LOW",
            8,
            "url_structure",
        )

    decoded_path = unquote(parsed.path).lower()
    query_and_path = decoded_path + "?" + parsed.query.lower()

    if len(parsed.query) > 180:
        add_indicator(
            indicators,
            "Long URL query string",
            "The URL contains a lengthy query string that may hide redirect or tracking information.",
            "LOW",
            6,
            "url_obfuscation",
        )

    if re.search(
        r"(?:redirect|return_url|continue|next|destination|target|url)=",
        query_and_path,
    ):
        add_indicator(
            indicators,
            "Potential redirect parameter",
            "The URL contains a parameter that may control a redirect destination.",
            "MEDIUM",
            12,
            "url_obfuscation",
        )

    if re.search(
        r"\.(?:apk|exe|msi|bat|cmd|scr|ps1|vbs)(?:$|[?#])",
        query_and_path,
    ):
        add_indicator(
            indicators,
            "Executable or application download link",
            "The URL appears to point to an executable or application package.",
            "HIGH",
            25,
            "malicious_download",
        )

    if re.search(r"%[0-9a-f]{2}", parsed.path, re.IGNORECASE):
        encoded_count = len(
            re.findall(r"%[0-9a-f]{2}", parsed.path, re.IGNORECASE)
        )

        if encoded_count >= 5:
            add_indicator(
                indicators,
                "Heavily encoded URL path",
                "The URL path contains extensive percent encoding that makes its contents harder to inspect.",
                "MEDIUM",
                12,
                "url_obfuscation",
            )


# ============================================================
# CONTEXT ANALYSIS
# ============================================================

def inspect_content_rules(text, indicators):
    lowered = text.lower()

    for rule in CONTENT_RULES:
        if re.search(rule["pattern"], lowered, re.IGNORECASE | re.DOTALL):
            add_indicator(
                indicators,
                rule["name"],
                rule["description"],
                rule["severity"],
                rule["points"],
                rule["category"],
            )


def inspect_context_combinations(indicators):
    categories = {
        item["category"]
        for item in indicators
    }

    combinations = [
        (
            {"credentials", "urgency"},
            "Credential request combined with urgency",
            "The content combines a request for sensitive information with time pressure.",
            12,
        ),
        (
            {"financial", "urgency"},
            "Financial pressure combined with urgency",
            "The content combines payment-related language with urgency.",
            12,
        ),
        (
            {"digital_arrest", "financial"},
            "Arrest threat combined with financial pressure",
            "The content combines legal or arrest threats with payment-related pressure.",
            20,
        ),
        (
            {"remote_access", "digital_arrest"},
            "Remote access combined with digital-arrest language",
            "The content combines remote-access requests with digital-arrest scam indicators.",
            18,
        ),
        (
            {"malicious_app", "credentials"},
            "Application installation combined with credential risk",
            "The content combines application installation instructions with credential-related warnings.",
            12,
        ),
        (
            {"brand_impersonation", "credentials"},
            "Brand impersonation combined with credential request",
            "The URL appears to misuse a known brand name while the content requests sensitive information.",
            18,
        ),
    ]

    for required, name, description, points in combinations:
        if required.issubset(categories):
            add_indicator(
                indicators,
                name,
                description,
                "CRITICAL",
                points,
                "context_combination",
            )


# ============================================================
# RISK SCORING
# ============================================================

def calculate_risk_score(indicators):
    if not indicators:
        return 0

    # Keep the strongest signal from each category to avoid
    # repeatedly counting similar keyword matches.
    category_scores = defaultdict(int)

    for item in indicators:
        category = item["category"]

        category_scores[category] = max(
            category_scores[category],
            item["points"],
        )

    score = sum(category_scores.values())

    # Context combinations are separate evidence of risk.
    combination_points = sum(
        item["points"]
        for item in indicators
        if item["category"] == "context_combination"
    )

    score += combination_points

    return min(100, score)


def classify_risk(score, indicators):
    has_critical = any(
        item["severity"] == "CRITICAL"
        for item in indicators
    )

    if score >= 75 or (has_critical and score >= 55):
        return (
            "CRITICAL",
            "Critical risk",
            "Strong indicators of a potentially harmful message or destination were detected. Do not interact with the content.",
        )

    if score >= 50:
        return (
            "HIGH",
            "High risk",
            "Multiple or serious warning indicators were detected. Do not follow the links or share sensitive information.",
        )

    if score >= 25:
        return (
            "MEDIUM",
            "Suspicious content",
            "Some suspicious patterns were detected. Verify the sender and destination independently before taking action.",
        )

    if score >= 10:
        return (
            "LOW",
            "Potential risk",
            "A small number of warning indicators were detected. Review the findings before interacting.",
        )

    return (
        "LOW",
        "Low detected risk",
        "Few known warning patterns were detected. This does not guarantee that the content or destination is safe.",
    )


# ============================================================
# MAIN ANALYSIS ENGINE
# ============================================================

def analyze_content(content: str):
    text = content.strip()

    if not text:
        raise ValueError("Content cannot be empty.")

    indicators = []

    inspect_content_rules(text, indicators)

    urls = extract_urls(text)

    for url in urls:
        inspect_url(url, indicators)

    if len(urls) >= 4:
        add_indicator(
            indicators,
            "Multiple links detected",
            "The content contains several URLs. Verify each destination independently.",
            "LOW",
            8,
            "multiple_links",
        )

    if not urls and re.search(
        r"(?i)\b(?:https?://|www\.)",
        text,
    ):
        add_indicator(
            indicators,
            "Unrecognized URL structure",
            "A URL-like string was found but could not be extracted reliably.",
            "LOW",
            5,
            "url_structure",
        )

    inspect_context_combinations(indicators)

    # Remove duplicate indicator names.
    unique_indicators = []
    seen = set()

    for item in indicators:
        key = item["name"]

        if key not in seen:
            seen.add(key)
            unique_indicators.append(item)

    score = calculate_risk_score(unique_indicators)

    risk_level, verdict, summary = classify_risk(
        score,
        unique_indicators,
    )

    unique_indicators.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(item["severity"], 0),
            -item["points"],
        )
    )

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "summary": summary,
        "indicators": unique_indicators,
        "analyzed_urls": urls,
        "indicator_count": len(unique_indicators),
        "analysis_version": "4.0.0",
        "score_explanation": (
            "The score is a heuristic assessment based on detected indicators "
            "and contextual combinations. It is not a probability or a guarantee "
            "that content is malicious or safe."
        ),
    }


# ============================================================
# API ROUTES
# ============================================================

@app.get("/")
def root():
    return {
        "name": "CatchPhish",
        "status": "online",
        "version": "4.0.0",
        "docs": "/docs",
    }


@app.get("/api/health")
def health():
    try:
        with get_db() as connection:
            connection.execute("SELECT 1")

        return {
            "status": "healthy",
            "database": "connected",
            "version": "4.0.0",
        }

    except sqlite3.Error:
        logger.exception("Database health check failed")

        raise HTTPException(
            status_code=503,
            detail="Database unavailable.",
        )


@app.post("/api/analyze")
def analyze(payload: AnalyzeRequest):
    content = payload.content.strip()

    if not content:
        raise HTTPException(
            status_code=422,
            detail="Please provide text or a URL to analyze.",
        )

    try:
        return analyze_content(content)

    except Exception:
        logger.exception("Phishing analysis failed")

        raise HTTPException(
            status_code=500,
            detail="An internal analysis error occurred.",
        )


# ============================================================
# AUTHENTICATION
# ============================================================

@app.post("/api/auth/signup", status_code=201)
def signup(payload: SignupRequest, request: Request):
    name = payload.name.strip()
    email = payload.email.strip().lower()

    password_hash, password_salt = hash_password(
        payload.password
    )

    try:
        with get_db() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (
                    name,
                    email,
                    password_hash,
                    password_salt
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    name,
                    email,
                    password_hash,
                    password_salt,
                ),
            )

            row = connection.execute(
                """
                SELECT id, name, email
                FROM users
                WHERE id = ?
                """,
                (cursor.lastrowid,),
            ).fetchone()

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists. Please log in.",
        )

    user = public_user(row)

    request.session.clear()
    request.session["user"] = user

    return {
        "message": "Account created successfully.",
        "user": user,
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request):
    email = payload.email.strip().lower()

    with get_db() as connection:
        row = connection.execute(
            """
            SELECT id, name, email, password_hash, password_salt
            FROM users
            WHERE email = ? COLLATE NOCASE
            """,
            (email,),
        ).fetchone()

    if not row or not verify_password(
        payload.password,
        row["password_hash"],
        row["password_salt"],
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    user = public_user(row)

    request.session.clear()
    request.session["user"] = user

    return {
        "message": "Login successful.",
        "user": user,
    }


@app.get("/api/auth/me")
def current_user(request: Request):
    user = request.session.get("user")

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Not signed in.",
        )

    return {
        "user": user,
    }


@app.post("/api/auth/logout")
def logout(request: Request):
    request.session.clear()

    return {
        "ok": True,
        "message": "Logged out successfully.",
    }

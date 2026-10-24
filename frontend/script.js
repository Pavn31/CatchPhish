
"use strict";

const API_BASE_URL = "https://catch-phish-theta.vercel.app";
const API_URL = `${API_BASE_URL}/api/analyze`;

const MAX_LENGTH = 10000;

let isAnalyzing = false;
let authMode = "login";

// DOM ELEMENTS
const authScreen = document.getElementById("auth-screen");
const appShell = document.getElementById("app-shell");
const authForm = document.getElementById("auth-form");
const authTitle = document.getElementById("auth-title");
const authSubtitle = document.getElementById("auth-subtitle");
const authName = document.getElementById("auth-name");
const authEmail = document.getElementById("auth-email");
const authPassword = document.getElementById("auth-password");
const authConfirm = document.getElementById("auth-confirm");
const nameField = document.getElementById("name-field");
const confirmField = document.getElementById("confirm-field");
const authMessage = document.getElementById("auth-message");
const authSubmitLabel = document.getElementById("auth-submit-label");
const loginTab = document.getElementById("login-tab");
const signupTab = document.getElementById("signup-tab");
const switchPrompt = document.getElementById("switch-prompt");
const switchMode = document.getElementById("switch-mode");
const forgotPassword = document.getElementById("forgot-password");
const togglePassword = document.getElementById("toggle-password");
const rememberMe = document.getElementById("remember-me");

const userAvatar = document.getElementById("user-avatar");
const userDisplay = document.getElementById("user-display");
const logoutBtn = document.getElementById("logout-btn");

const form = document.getElementById("analyze-form");
const input = document.getElementById("suspect-input");
const analyzeBtn = document.getElementById("analyze-btn");
const clearBtn = document.getElementById("clear-btn");
const charCount = document.getElementById("char-count");
const errorMessage = document.getElementById("error-message");

const resultsPlaceholder = document.getElementById("results-placeholder");
const resultsContent = document.getElementById("results-content");
const riskScore = document.getElementById("risk-score");
const scoreBar = document.getElementById("score-bar");
const scoreTrack = document.getElementById("score-track");
const riskLabel = document.getElementById("risk-label");
const resultStatus = document.getElementById("result-status");
const resultTitle = document.getElementById("result-title");
const resultDescription = document.getElementById("result-description");
const indicatorCount = document.getElementById("indicator-count");
const indicatorSummary = document.getElementById("indicator-summary");
const indicatorsList = document.getElementById("indicators-list");
const impactDescription = document.getElementById("impact-description");
const impactSummary = document.getElementById("impact-summary");
const impactTags = document.getElementById("impact-tags");
const impactLevel = document.getElementById("impact-level");
const reportTimestamp = document.getElementById("report-timestamp");

// STORAGE KEYS
const ACCOUNT_KEY = "catchphish_demo_account";
const SESSION_KEY = "catchphish_session";

// AUTHENTICATION
function showAuthMessage(message, type = "error") {
    if (!authMessage) return;

    authMessage.textContent = message;
    authMessage.hidden = false;
    authMessage.className = `auth-message ${type}`;
}

function clearAuthMessage() {
    if (!authMessage) return;

    authMessage.textContent = "";
    authMessage.hidden = true;
}

function getSavedAccount() {
    try {
        const account = localStorage.getItem(ACCOUNT_KEY);
        return account ? JSON.parse(account) : null;
    } catch {
        return null;
    }
}

function getSession() {
    try {
        const persistent = localStorage.getItem(SESSION_KEY);
        if (persistent) return JSON.parse(persistent);

        const temporary = sessionStorage.getItem(SESSION_KEY);
        return temporary ? JSON.parse(temporary) : null;
    } catch {
        return null;
    }
}

function saveSession(account, persistent = false) {
    const session = {
        name: account.name || account.email,
        email: account.email
    };

    localStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(SESSION_KEY);

    const storage = persistent ? localStorage : sessionStorage;
    storage.setItem(SESSION_KEY, JSON.stringify(session));
}

function showDashboard(session) {
    if (!session) return;

    if (authScreen) authScreen.hidden = true;
    if (appShell) appShell.hidden = false;

    if (userDisplay) {
        userDisplay.textContent = session.name || session.email || "User";
    }

    if (userAvatar) {
        const name = session.name || session.email || "U";
        userAvatar.textContent = name.trim().charAt(0).toUpperCase();
    }

    clearAuthMessage();
}

function showLoginScreen() {
    if (appShell) appShell.hidden = true;
    if (authScreen) authScreen.hidden = false;

    setAuthMode("login");
}

function setAuthMode(mode) {
    authMode = mode;
    clearAuthMessage();

    const isSignup = mode === "signup";

    if (authTitle) {
        authTitle.textContent = isSignup
            ? "Create your account"
            : "Welcome back";
    }

    if (authSubtitle) {
        authSubtitle.textContent = isSignup
            ? "Create an account to start checking suspicious messages."
            : "Sign in to continue to CatchPhish.";
    }

    if (nameField) nameField.hidden = !isSignup;
    if (confirmField) confirmField.hidden = !isSignup;

    if (authName) authName.required = isSignup;
    if (authConfirm) authConfirm.required = isSignup;

    if (loginTab) {
        loginTab.classList.toggle("active", !isSignup);
        loginTab.setAttribute("aria-selected", String(!isSignup));
    }

    if (signupTab) {
        signupTab.classList.toggle("active", isSignup);
        signupTab.setAttribute("aria-selected", String(isSignup));
    }

    if (authSubmitLabel) {
        authSubmitLabel.textContent = isSignup
            ? "Create account"
            : "Sign in";
    }

    if (switchPrompt) {
        switchPrompt.textContent = isSignup
            ? "Already have an account?"
            : "Don't have an account?";
    }

    if (switchMode) {
        switchMode.textContent = isSignup ? "Sign in" : "Create account";
    }

    if (forgotPassword) forgotPassword.hidden = isSignup;

    if (authPassword) {
        authPassword.autocomplete = isSignup
            ? "new-password"
            : "current-password";
    }
}

// LOGIN / SIGNUP EVENTS
if (loginTab) {
    loginTab.addEventListener("click", () => setAuthMode("login"));
}

if (signupTab) {
    signupTab.addEventListener("click", () => setAuthMode("signup"));
}

if (switchMode) {
    switchMode.addEventListener("click", () => {
        setAuthMode(authMode === "login" ? "signup" : "login");
    });
}

if (togglePassword && authPassword) {
    togglePassword.addEventListener("click", () => {
        const showPassword = authPassword.type === "password";
        authPassword.type = showPassword ? "text" : "password";

        togglePassword.setAttribute(
            "aria-label",
            showPassword ? "Hide password" : "Show password"
        );

        togglePassword.textContent = showPassword ? "Hide" : "Show";
    });
}

if (authForm) {
    authForm.addEventListener("submit", (event) => {
        event.preventDefault();
        clearAuthMessage();

        const email = authEmail.value.trim().toLowerCase();
        const password = authPassword.value;

        if (!email || !password) {
            showAuthMessage("Enter your email and password.");
            return;
        }

        if (authMode === "signup") {
            const name = authName.value.trim();
            const confirmPassword = authConfirm.value;

            if (!name) {
                showAuthMessage("Enter your name.");
                authName.focus();
                return;
            }

            if (password.length < 8) {
                showAuthMessage(
                    "Your password must contain at least 8 characters."
                );
                authPassword.focus();
                return;
            }

            if (password !== confirmPassword) {
                showAuthMessage("Passwords do not match.");
                authConfirm.focus();
                return;
            }

            const existingAccount = getSavedAccount();

            if (existingAccount && existingAccount.email === email) {
                showAuthMessage(
                    "An account with this email already exists. Sign in instead."
                );
                return;
            }

            // Demo-only storage. Use a secure backend for real accounts.
            const account = { name, email, password };

            try {
                localStorage.setItem(
                    ACCOUNT_KEY,
                    JSON.stringify(account)
                );
            } catch {
                showAuthMessage(
                    "Could not save the demo account in this browser."
                );
                return;
            }

            saveSession(account, Boolean(rememberMe?.checked));
            showDashboard(account);
            return;
        }

        const account = getSavedAccount();

        if (!account) {
            showAuthMessage(
                "No demo account found. Create an account first."
            );
            return;
        }

        if (account.email !== email || account.password !== password) {
            showAuthMessage("Incorrect email or password.");
            return;
        }

        saveSession(account, Boolean(rememberMe?.checked));
        showDashboard(account);
    });
}

if (forgotPassword) {
    forgotPassword.addEventListener("click", (event) => {
        event.preventDefault();

        showAuthMessage(
            "Password reset emails are not configured in this demo.",
            "info"
        );
    });
}

// LOGOUT
if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
        localStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(SESSION_KEY);

        if (input) input.value = "";

        updateCharacterCount();
        clearError();
        resetResults();
        setMobileNavOpen(false);
        showLoginScreen();
    });
}

// GENERAL HELPERS
function firstDefined(object, keys, fallback = undefined) {
    if (!object || typeof object !== "object") return fallback;

    for (const key of keys) {
        if (
            Object.prototype.hasOwnProperty.call(object, key) &&
            object[key] !== null &&
            object[key] !== undefined
        ) {
            return object[key];
        }
    }

    return fallback;
}

function toText(value, fallback = "") {
    if (typeof value === "string") return value;

    if (typeof value === "number" || typeof value === "boolean") {
        return String(value);
    }

    return fallback;
}

function normalizeScore(value) {
    if (typeof value === "string") {
        value = Number(value.replace("%", "").trim());
    }

    if (typeof value !== "number" || !Number.isFinite(value)) return 0;

    return Math.max(0, Math.min(100, Math.round(value)));
}

function normalizeSeverity(value) {
    const severity = toText(value, "info").toLowerCase();

    if (severity.includes("critical")) return "critical";
    if (severity.includes("high") || severity.includes("danger")) return "high";
    if (severity.includes("medium") || severity.includes("moderate")) return "medium";
    if (severity.includes("low")) return "low";

    return "info";
}

function normalizeRisk(score, suppliedLevel) {
    const level = toText(suppliedLevel, "").toLowerCase();

    if (level.includes("critical") || level.includes("malicious")) {
        return {
            key: "critical",
            label: "CRITICAL",
            title: "High-confidence threat",
            status: "DANGEROUS",
            statusClass: "dangerous",
            description:
                "The analysis indicates a potentially serious threat. Avoid interacting with the content until it has been independently verified."
        };
    }

    if (
        level.includes("phishing") ||
        level.includes("danger") ||
        level.includes("high") ||
        level.includes("unsafe")
    ) {
        return {
            key: "high",
            label: "HIGH RISK",
            title: "Potential threat detected",
            status: "DANGEROUS",
            statusClass: "dangerous",
            description:
                "Suspicious signals were reported. Do not open links or provide credentials until the content has been verified."
        };
    }

    if (
        level.includes("medium") ||
        level.includes("moderate") ||
        level.includes("suspicious")
    ) {
        return {
            key: "medium",
            label: "MODERATE",
            title: "Suspicious signals detected",
            status: "SUSPICIOUS",
            statusClass: "suspicious",
            description:
                "The analysis identified signals that warrant further inspection. Treat the content cautiously."
        };
    }

    if (
        level.includes("low") ||
        level.includes("safe") ||
        level.includes("benign") ||
        level.includes("clean")
    ) {
        return {
            key: "low",
            label: "LOW RISK",
            title: "No major threat reported",
            status: "LOW RISK",
            statusClass: "safe",
            description:
                "The analysis reported a low risk level. This does not guarantee that the content is safe."
        };
    }

    if (score >= 75) {
        return {
            key: "critical",
            label: "CRITICAL",
            title: "High-risk content",
            status: "DANGEROUS",
            statusClass: "dangerous",
            description:
                "The reported score is critically high. Avoid interacting with this content."
        };
    }

    if (score >= 45) {
        return {
            key: "high",
            label: "HIGH RISK",
            title: "Potential threat detected",
            status: "DANGEROUS",
            statusClass: "dangerous",
            description:
                "The reported score is high. Verify the source before interacting with this content."
        };
    }

    if (score >= 20) {
        return {
            key: "medium",
            label: "MODERATE",
            title: "Review recommended",
            status: "SUSPICIOUS",
            statusClass: "suspicious",
            description:
                "The reported score suggests caution. Inspect the findings before trusting this content."
        };
    }

    return {
        key: "low",
        label: "LOW RISK",
        title: "Low-risk assessment",
        status: "LOW RISK",
        statusClass: "safe",
        description:
            "The reported score is low. Automated analysis cannot guarantee that content is safe."
    };
}

// INPUT AND ERROR HANDLING
function updateCharacterCount() {
    if (!input || !charCount) return;

    const length = input.value.length;

    charCount.textContent =
        `${length.toLocaleString()} / ${MAX_LENGTH.toLocaleString()}`;

    charCount.classList.toggle("near-limit", length >= MAX_LENGTH * 0.8);
    charCount.classList.toggle("at-limit", length >= MAX_LENGTH);
}

function showError(message) {
    if (!errorMessage) return;

    errorMessage.textContent = message;
    errorMessage.hidden = false;
}

function clearError() {
    if (!errorMessage) return;

    errorMessage.textContent = "";
    errorMessage.hidden = true;
}

function setLoading(loading) {
    isAnalyzing = loading;

    if (analyzeBtn) analyzeBtn.disabled = loading;
    if (clearBtn) clearBtn.disabled = loading;

    const label = analyzeBtn?.querySelector(".button-label");
    const arrow = analyzeBtn?.querySelector(".button-arrow");

    if (label) {
        label.textContent = loading ? "Analyzing..." : "Analyze threat";
    }

    if (arrow) arrow.hidden = loading;

    if (input) input.setAttribute("aria-busy", String(loading));
}

function resetResults() {
    if (resultsPlaceholder) resultsPlaceholder.hidden = false;
    if (resultsContent) resultsContent.hidden = true;
}

// NORMALIZE API RESPONSE
function normalizeResponse(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) {
        throw new Error("The API returned an invalid response.");
    }

    const nested =
        data.result && typeof data.result === "object"
            ? data.result
            : data;

    const score = normalizeScore(
        firstDefined(
            nested,
            ["risk_score", "threat_score", "score", "probability", "confidence"],
            0
        )
    );

    const suppliedLevel = firstDefined(
        nested,
        [
            "risk_level",
            "threat_level",
            "risk",
            "severity",
            "verdict",
            "classification",
            "label"
        ],
        ""
    );

    const risk = normalizeRisk(score, suppliedLevel);

    let rawIndicators = firstDefined(
        nested,
        ["indicators", "findings", "detections", "threats", "reasons"],
        []
    );

    if (!Array.isArray(rawIndicators)) {
        rawIndicators = rawIndicators ? [rawIndicators] : [];
    }

    const indicators = rawIndicators
        .map((item) => {
            if (typeof item === "string") {
                return {
                    title: item,
                    description: "Reported by the analysis API.",
                    severity: "info"
                };
            }

            if (!item || typeof item !== "object") return null;

            return {
                title: toText(
                    firstDefined(item, [
                        "title",
                        "name",
                        "indicator",
                        "type",
                        "rule",
                        "message"
                    ]),
                    "Unnamed indicator"
                ),
                description: toText(
                    firstDefined(item, [
                        "description",
                        "details",
                        "explanation",
                        "message",
                        "evidence"
                    ]),
                    "No additional details provided."
                ),
                severity: normalizeSeverity(
                    firstDefined(item, ["severity", "risk_level", "level"], "info")
                )
            };
        })
        .filter(Boolean);

    const suppliedTitle = firstDefined(nested, ["title", "summary_title"]);

    const suppliedDescription = firstDefined(
        nested,
        ["description", "summary", "explanation", "message"]
    );

    const suppliedImpact = firstDefined(
        nested,
        ["impact", "impact_description", "potential_impact"]
    );

    const rawTags = firstDefined(
        nested,
        ["impact_tags", "categories", "attack_types", "affected_assets"],
        []
    );

    let tags = [];

    if (Array.isArray(rawTags)) {
        tags = rawTags
            .map((tag) => {
                if (typeof tag === "string") return tag;

                if (tag && typeof tag === "object") {
                    return toText(
                        firstDefined(tag, ["name", "label", "type"]),
                        ""
                    );
                }

                return "";
            })
            .filter(Boolean);
    }

    return {
        score,
        risk,
        indicators,
        title: toText(suppliedTitle, risk.title),
        description: toText(suppliedDescription, risk.description),
        impact: toText(
            suppliedImpact,
            indicators.length
                ? "Review the detected indicators to understand the possible consequences."
                : "No specific impact details were supplied by the analysis API."
        ),
        tags,
        rawLevel: toText(suppliedLevel, risk.label)
    };
}

// RENDER INDICATORS
function renderIndicators(indicators) {
    if (!indicatorsList) return;

    indicatorsList.replaceChildren();

    if (!indicators.length) {
        const empty = document.createElement("div");
        empty.className = "empty-indicators";
        empty.textContent = "No indicators were reported by the API.";
        indicatorsList.appendChild(empty);
        return;
    }

    indicators.forEach((indicator, index) => {
        const item = document.createElement("div");
        item.className = "indicator-item";

        const marker = document.createElement("span");
        marker.className = "indicator-marker";
        marker.textContent = String(index + 1).padStart(2, "0");

        const content = document.createElement("div");
        content.className = "indicator-item-content";

        const title = document.createElement("p");
        title.className = "indicator-item-title";
        title.textContent = indicator.title;

        const description = document.createElement("p");
        description.className = "indicator-item-description";
        description.textContent = indicator.description;

        const severity = document.createElement("span");
        severity.className = `indicator-severity ${indicator.severity}`;
        severity.textContent = indicator.severity;

        content.append(title, description);
        item.append(marker, content, severity);
        indicatorsList.appendChild(item);
    });
}

// RENDER IMPACT TAGS
function renderImpactTags(tags) {
    if (!impactTags) return;

    impactTags.replaceChildren();

    if (!tags.length) {
        const tag = document.createElement("span");
        tag.className = "impact-tag";
        tag.textContent = "No categories provided";
        impactTags.appendChild(tag);
        return;
    }

    tags.forEach((value) => {
        const tag = document.createElement("span");
        tag.className = "impact-tag";
        tag.textContent = value;
        impactTags.appendChild(tag);
    });
}

// RENDER RESULTS
function renderResults(result) {
    if (resultsPlaceholder) resultsPlaceholder.hidden = true;
    if (resultsContent) resultsContent.hidden = false;

    if (riskScore) riskScore.textContent = String(result.score);

    if (riskLabel) {
        riskLabel.textContent = result.risk.label;
        riskLabel.className = `risk-badge risk-${result.risk.key}`;
    }

    if (scoreBar) {
        scoreBar.style.width = `${result.score}%`;
        scoreBar.className = `score-bar ${result.risk.key}`;
    }

    if (scoreTrack) {
        scoreTrack.setAttribute("aria-valuenow", String(result.score));
        scoreTrack.setAttribute(
            "aria-valuetext",
            `${result.score} out of 100`
        );
    }

    if (resultStatus) {
        resultStatus.textContent = result.risk.status;
        resultStatus.className = `verdict-status ${result.risk.statusClass}`;
    }

    if (resultTitle) resultTitle.textContent = result.title;
    if (resultDescription) resultDescription.textContent = result.description;
    if (impactDescription) impactDescription.textContent = result.impact;
    if (impactSummary) impactSummary.textContent = result.impact;

    if (indicatorCount) {
        indicatorCount.textContent = String(result.indicators.length);
    }

    if (indicatorSummary) {
        indicatorSummary.textContent =
            `${result.indicators.length} finding${result.indicators.length === 1 ? "" : "s"}`;
    }

    if (impactLevel) impactLevel.textContent = result.risk.label;

    renderIndicators(result.indicators);
    renderImpactTags(result.tags);

    if (reportTimestamp) {
        reportTimestamp.textContent = new Date().toLocaleString();
    }

    const resultsSection = document.getElementById("results");

    if (resultsSection) {
        resultsSection.scrollIntoView({
            behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
                ? "auto"
                : "smooth",
            block: "start"
        });
    }
}

// BACKEND API REQUEST
async function analyzeContent(content) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json"
            },
            body: JSON.stringify({ content }),
            signal: controller.signal
        });

        const responseText = await response.text();
        let data = {};

        if (responseText) {
            try {
                data = JSON.parse(responseText);
            } catch {
                throw new Error(
                    `The API returned a non-JSON response (HTTP ${response.status}).`
                );
            }
        }

        if (!response.ok) {
            const detail = firstDefined(data, ["detail", "message", "error"]);

            const message =
                typeof detail === "string"
                    ? detail
                    : `Request failed with HTTP ${response.status}.`;

            throw new Error(message);
        }

        return normalizeResponse(data);
    } catch (error) {
        if (error.name === "AbortError") {
            throw new Error(
                "The request timed out. Check whether the backend is running."
            );
        }

        if (error instanceof TypeError) {
            throw new Error(
                "Cannot connect to the CatchPhish API. Please try again later."
            );
        }

        throw error;
    } finally {
        clearTimeout(timeoutId);
    }
}

// ANALYZER FORM EVENTS
if (input) {
    input.addEventListener("input", () => {
        updateCharacterCount();
        clearError();
    });
}

if (form) {
    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        if (isAnalyzing) return;

        const content = input.value.trim();
        clearError();

        if (!content) {
            showError(
                "Enter a URL, email, SMS, or message before starting the analysis."
            );
            input.focus();
            return;
        }

        if (content.length > MAX_LENGTH) {
            showError(
                `Input exceeds the ${MAX_LENGTH.toLocaleString()} character limit.`
            );
            return;
        }

        setLoading(true);

        try {
            const result = await analyzeContent(content);
            renderResults(result);
        } catch (error) {
            showError(error.message || "Analysis failed. Please try again.");
        } finally {
            setLoading(false);
        }
    });
}

if (clearBtn) {
    clearBtn.addEventListener("click", () => {
        if (isAnalyzing) return;

        input.value = "";
        updateCharacterCount();
        clearError();
        input.focus();
    });
}

// MOBILE NAVIGATION
const mobileMenuToggle = document.getElementById("mobile-menu-toggle");
const appSidebar = document.getElementById("app-sidebar");

function setMobileNavOpen(isOpen) {
    document.body.classList.toggle("mobile-nav-open", isOpen);

    if (mobileMenuToggle) {
        mobileMenuToggle.setAttribute("aria-expanded", String(isOpen));

        mobileMenuToggle.setAttribute(
            "aria-label",
            isOpen ? "Close navigation menu" : "Open navigation menu"
        );

        const label = mobileMenuToggle.querySelector(".menu-label");

        if (label) {
            label.textContent = isOpen ? "Close menu" : "Menu";
        }
    }
}

if (mobileMenuToggle) {
    mobileMenuToggle.addEventListener("click", () => {
        const isOpen = document.body.classList.contains("mobile-nav-open");
        setMobileNavOpen(!isOpen);
    });
}

if (appSidebar) {
    appSidebar.addEventListener("click", (event) => {
        const navItem = event.target.closest(
            ".nav-item, a, button:not(#mobile-menu-toggle)"
        );

        if (
            navItem &&
            window.matchMedia("(max-width: 700px)").matches
        ) {
            setMobileNavOpen(false);
        }
    });
}

// Close the mobile menu when clicking outside it.
document.addEventListener("click", (event) => {
    if (!document.body.classList.contains("mobile-nav-open")) return;
    if (appSidebar?.contains(event.target)) return;
    if (mobileMenuToggle?.contains(event.target)) return;

    setMobileNavOpen(false);
});

// Close the mobile menu with Escape.
document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
        setMobileNavOpen(false);
    }
});

// Reset the mobile menu when returning to desktop width.
window.addEventListener("resize", () => {
    if (window.matchMedia("(min-width: 701px)").matches) {
        setMobileNavOpen(false);
    }
});

// INITIALIZE
function initializeApp() {
    updateCharacterCount();
    clearError();
    setAuthMode("login");

    const session = getSession();

    if (session && session.email) {
        showDashboard(session);
    } else {
        showLoginScreen();
    }

    setMobileNavOpen(false);
}

initializeApp();

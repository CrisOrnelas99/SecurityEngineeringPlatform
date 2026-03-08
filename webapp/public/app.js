// Static detection scenario catalog displayed in the Cybersecurity Lab UI.
const detectionScenarios = [
  {
    id: "DET-01",
    title: "Failed Login Burst",
    definition: "Detects a rapid cluster of failed login attempts from the same source, which is a common brute-force pattern.",
    how: [
      "Trigger path (:8080): use Session Access and submit 5+ failed attempts for one username.",
      "Endpoint path (:8080): POST /api/auth/login.",
      "Verification path (:8081): check Active Alerts / Incident Timeline for FAILED_LOGIN_BURST."
    ],
    windowsCommand: "1..5 | % { try { Invoke-RestMethod -Method Post -Uri \"$base/api/auth/login\" -WebSession $s -Headers @{\"x-csrf-token\"=$csrf;\"content-type\"=\"application/json\"} -Body '{\"username\":\"analystlab\",\"password\":\"wrongpass12345\"}' -ErrorAction Stop | Out-Null } catch {} }",
    kaliCommand: "BASE=\"http://localhost:8080\"; COOKIE=\"cookies.txt\"; CSRF=$(curl -s -c \"$COOKIE\" \"$BASE/api/csrf-token\" | jq -r '.csrfToken'); echo \"$CSRF\"; for i in $(seq 1 5); do curl -s -b \"$COOKIE\" -c \"$COOKIE\" -X POST \"$BASE/api/auth/login\" -H \"x-csrf-token: $CSRF\" -H \"content-type: application/json\" -d '{\"username\":\"analystlab\",\"password\":\"wrongpass12345\"}' >/dev/null; done"
  },
  {
    id: "DET-02",
    title: "Account Enumeration",
    definition: "Detects one source trying many usernames in a short window, which often indicates account discovery activity.",
    how: [
      "Trigger path (:8080): use Session Access and submit failed logins for 5+ different usernames quickly.",
      "Endpoint path (:8080): POST /api/auth/login.",
      "Verification path (:8081): confirm ACCOUNT_ENUMERATION in timeline/alerts."
    ],
    windowsCommand: "\"enum001\",\"enum002\",\"enum003\",\"enum004\",\"enum005\" | % { $u=$_; try { Invoke-RestMethod -Method Post -Uri \"$base/api/auth/login\" -WebSession $s -Headers @{\"x-csrf-token\"=$csrf;\"content-type\"=\"application/json\"} -Body (@{username=$u;password='wrongpass12345'} | ConvertTo-Json) -ErrorAction Stop | Out-Null } catch {} }",
    kaliCommand: "BASE=\"http://localhost:8080\"; COOKIE=\"cookies.txt\"; CSRF=$(curl -s -c \"$COOKIE\" \"$BASE/api/csrf-token\" | jq -r '.csrfToken'); echo \"$CSRF\"; for u in enum001 enum002 enum003 enum004 enum005; do curl -s -b \"$COOKIE\" -c \"$COOKIE\" -X POST \"$BASE/api/auth/login\" -H \"x-csrf-token: $CSRF\" -H \"content-type: application/json\" -d \"{\\\"username\\\":\\\"$u\\\",\\\"password\\\":\\\"wrongpass12345\\\"}\" >/dev/null; done"
  },
  {
    id: "DET-03",
    title: "Honeypot Trigger",
    definition: "Detects access to decoy endpoints that legitimate users should never call, signaling suspicious probing.",
    how: [
      "Trigger endpoint (:8080): GET /internal-debug.",
      "Manual path (:8080): open http://localhost:8080/internal-debug in browser.",
      "Optional dashboard-app honeypot path (:8081): open http://localhost:8081/internal-debug-dashboard.",
      "Verification path (:8081): confirm HONEYPOT_TRIGGER in timeline/alerts."
    ],
    windowsCommand: "curl.exe -i \"http://localhost:8080/internal-debug\"",
    kaliCommand: "curl -i \"http://localhost:8080/internal-debug\""
  },
  {
    id: "DET-04",
    title: "Path Traversal Attempt",
    definition: "Detects traversal payloads that attempt to escape intended directories and read unauthorized files.",
    how: [
      "Trigger endpoint (:8080): GET /admin-backup?path=../etc/passwd.",
      "Manual path (:8080): open http://localhost:8080/admin-backup?path=../etc/passwd.",
      "Verification path (:8081): confirm PATH_TRAVERSAL_ATTEMPT in timeline/alerts."
    ],
    windowsCommand: "curl.exe -i \"http://localhost:8080/admin-backup?path=../etc/passwd\"",
    kaliCommand: "curl -i \"http://localhost:8080/admin-backup?path=../etc/passwd\""
  },
  {
    id: "DET-05",
    title: "Privilege Escalation Attempt",
    definition: "Detects a lower-privileged identity attempting an admin-only action, indicating authorization abuse.",
    how: [
      "Trigger path (:8080): log in as analyst (non-admin), then attempt admin-only user-management access.",
      "Endpoint path (:8080): GET /api/auth/users using an analyst bearer token.",
      "Expected behavior: HTTP 403. Verification path (:8081): confirm PRIV_ESC_ATTEMPT in timeline/alerts."
    ],
    windowsCommand: "$base='http://localhost:8080'; $u='goose2'; $p='pass12345678'; $s=New-Object Microsoft.PowerShell.Commands.WebRequestSession; $csrf=(Invoke-RestMethod -Method Get -Uri \"$base/api/csrf-token\" -WebSession $s).csrfToken; $login=Invoke-RestMethod -Method Post -Uri \"$base/api/auth/login\" -WebSession $s -Headers @{\"x-csrf-token\"=$csrf;\"content-type\"=\"application/json\"} -Body (\"{\\\"username\\\":\\\"$u\\\",\\\"password\\\":\\\"$p\\\"}\"); curl.exe -i \"$base/api/auth/users\" -H (\"Authorization: Bearer \" + $login.accessToken)",
    kaliCommand: "BASE=\"http://localhost:8080\"; USER=\"goose2\"; PASS=\"pass12345678\"; CSRF=$(curl -s -c cookies.txt \"$BASE/api/csrf-token\" | jq -r '.csrfToken'); TOKEN=$(curl -s -b cookies.txt -c cookies.txt -H \"Content-Type: application/json\" -H \"X-CSRF-Token: $CSRF\" -d \"{\\\"username\\\":\\\"$USER\\\",\\\"password\\\":\\\"$PASS\\\"}\" \"$BASE/api/auth/login\" | jq -r '.accessToken'); curl -i -b cookies.txt -H \"Authorization: Bearer $TOKEN\" \"$BASE/api/auth/users\""
  },
  {
    id: "DET-06",
    title: "Excessive API Calls / Request Frequency",
    definition: "Detects abnormal request volume that can indicate automated abuse, scraping, or service degradation attempts.",
    how: [
      "Trigger path (:8080): repeatedly call /api/health from one source.",
      "Manual path (:8080): open /api/health in browser and refresh rapidly many times (target ~40-50 requests in about one minute).",
      "Verification path (:8081): confirm EXCESSIVE_API_CALLS (and at higher volume ABNORMAL_REQUEST_FREQUENCY)."
    ],
    windowsCommand: "1..50 | % { try { Invoke-WebRequest -UseBasicParsing -Uri \"http://localhost:8080/api/health\" | Out-Null } catch {} }",
    kaliCommand: "for i in $(seq 1 50); do curl -s \"http://localhost:8080/api/health\" >/dev/null; done"
  }
];

// Security feature/library catalog rendered in the lab knowledge panel.
const securityFeatures = [
  {
    name: "Helmet",
    definition: "Helmet is Express middleware that sets hardened HTTP response headers so browsers enforce safer defaults.",
    layer: "HTTP hardening",
    protects: "Adds secure browser-facing response headers by default.",
    inApp: "Used as baseline header protection for app responses."
  },
  {
    name: "CSRF Protection",
    definition: "CSRF protection uses per-session anti-forgery tokens so state-changing requests must come from trusted app flows.",
    layer: "State-change request integrity",
    protects: "Requires valid anti-CSRF token on sensitive operations.",
    inApp: "Used for auth and protected API request flows."
  },
  {
    name: "CORS Policy",
    definition: "CORS policy defines which browser origins can send credentialed requests, preventing unauthorized frontends from calling sensitive APIs.",
    layer: "Cross-origin controls",
    protects: "Restricts which origins can make credentialed browser requests.",
    inApp: "Configured to allow trusted frontend origin(s)."
  },
  {
    name: "JWT Authentication",
    definition: "JWT authentication uses signed access tokens to verify identity and role claims on each protected API call.",
    layer: "Identity and session",
    protects: "Ensures protected APIs require valid signed access tokens.",
    inApp: "Used for authenticated route access and session refresh workflow."
  },
  {
    name: "Access and Refresh Token Model",
    definition: "The app uses short-lived access tokens plus longer-lived refresh tokens to balance security and usability.",
    layer: "Session architecture",
    protects: "Reduces exposure window for stolen access tokens while allowing controlled session renewal.",
    inApp: "Access JWTs are used on API calls; refresh tokens are rotated and validated for renewals."
  },
  {
    name: "Nginx Reverse Proxy",
    definition: "Nginx is the edge reverse proxy that receives client traffic before forwarding to internal services.",
    layer: "Edge gateway",
    protects: "Creates a controlled public entry point and hides internal service ports.",
    inApp: "Both protected app (:8080) and dashboard (:8081) are fronted by Nginx-based WAF proxies."
  },
  {
    name: "ModSecurity WAF Engine",
    definition: "ModSecurity is the inspection engine that evaluates requests against security rules.",
    layer: "Runtime request inspection",
    protects: "Detects and blocks malicious request patterns before they hit application logic.",
    inApp: "Enabled in front of exposed endpoints with rule tuning for this environment."
  },
  {
    name: "OWASP Core Rule Set (CRS)",
    definition: "OWASP CRS is a maintained rule pack used by the WAF to detect common web attack techniques.",
    layer: "Threat signature coverage",
    protects: "Adds broad baseline detection/blocking for injection, traversal, protocol abuse, and related patterns.",
    inApp: "Loaded with ModSecurity and adjusted with project-specific overrides where needed."
  },
  {
    name: "libsodium",
    definition: "libsodium is a modern cryptography library with safer APIs and strong defaults.",
    layer: "Cryptographic implementation",
    protects: "Reduces crypto misuse risk by providing vetted, higher-level primitives.",
    inApp: "security_core uses libsodium for password hashing and verification operations."
  },
  {
    name: "OpenSSL",
    definition: "OpenSSL is a widely used cryptographic library for hashing, MACs, ciphers, and secure comparisons.",
    layer: "Cryptographic implementation",
    protects: "Provides robust low-level crypto primitives used by security functions.",
    inApp: "security_core uses OpenSSL for HMAC workflows and constant-time comparison."
  },
  {
    name: "HMAC (SHA-256)",
    definition: "HMAC combines a secret key and data to produce an integrity/authenticity tag.",
    layer: "Data integrity and authenticity",
    protects: "Detects tampering and validates that data came from a party holding the shared secret.",
    inApp: "Implemented in security_core via OpenSSL HMAC APIs."
  },
  {
    name: "Password Hashing (via C++ security_core)",
    definition: "Passwords are one-way hashed so plaintext credentials are never stored or retrievable from data storage.",
    layer: "Credential protection",
    protects: "Reduces impact of credential database exposure.",
    inApp: "User passwords are hashed and verified only through the C++ security_core helper service."
  },
  {
    name: "Refresh Token Revocation",
    definition: "Refresh token revocation allows active sessions to be invalidated server-side after logout, resets, or suspicious activity.",
    layer: "Session lifecycle security",
    protects: "Prevents continued use of revoked refresh tokens.",
    inApp: "Refresh tokens are stored, rotated, and revoked on logout/password reset."
  },
  {
    name: "Secure Cookie Policy",
    definition: "Security-sensitive cookies are configured with strict attributes to reduce client-side abuse.",
    layer: "Browser session hardening",
    protects: "Reduces CSRF/session misuse risk through stricter browser cookie handling.",
    inApp: "CSRF cookie is issued with HttpOnly, SameSite=Strict, and Secure in production mode."
  },
  {
    name: "RBAC",
    definition: "RBAC enforces role-based permissions so only approved user roles can access privileged functions.",
    layer: "Authorization",
    protects: "Prevents non-admin users from accessing admin functionality.",
    inApp: "Applied on admin-only routes such as user management."
  },
  {
    name: "Rate Limiting",
    definition: "Rate limiting enforces per-window request thresholds to slow brute-force attempts and API abuse.",
    layer: "Abuse prevention",
    protects: "Slows brute-force and burst traffic patterns.",
    inApp: "Applied globally and on high-risk auth/API routes."
  },
  {
    name: "Login Backoff + Account Lock Controls",
    definition: "Login backoff and lock controls add progressive delay and lock conditions after repeated failed authentication attempts.",
    layer: "Account takeover resistance",
    protects: "Reduces brute-force and credential stuffing success.",
    inApp: "Login protection middleware tracks failures and enforces lock/backoff states."
  },
  {
    name: "Input Validation",
    definition: "Input validation enforces expected schema and value constraints before requests reach sensitive business logic.",
    layer: "Request sanitization",
    protects: "Rejects malformed or unexpected request payloads.",
    inApp: "Used on auth and user-management related payloads."
  },
  {
    name: "Schema Validation (Zod)",
    definition: "Zod enforces strict request schemas (types, ranges, allowed values, and patterns) before handlers run.",
    layer: "Application input hardening",
    protects: "Blocks malformed and injection-style payloads from reaching protected route logic.",
    inApp: "Applied through validateBody middleware on login, user-management, password, and payment simulation routes."
  },
  {
    name: "Parameterized SQL Queries",
    definition: "Parameterized queries separate SQL code from user-controlled values instead of string-building queries.",
    layer: "Data access security",
    protects: "Reduces SQL injection risk in database operations.",
    inApp: "User and token store operations use better-sqlite3 prepared statements with bound parameters."
  },
  {
    name: "Request Body Size Limits",
    definition: "Body-size limits cap incoming JSON payload size to prevent oversized request abuse.",
    layer: "Input/resource protection",
    protects: "Reduces payload-based denial-of-service pressure and parser abuse.",
    inApp: "Express JSON parsing is limited to 512KB request bodies."
  },
  {
    name: "JWT Signature and Expiry Verification",
    definition: "Every protected token is cryptographically verified and checked for validity window before access is granted.",
    layer: "Token integrity",
    protects: "Blocks forged, tampered, expired, or otherwise invalid bearer tokens.",
    inApp: "authenticateToken and refresh flows verify JWTs with server secrets and enforce expiration."
  },
  {
    name: "Timing-safe Secret Comparison",
    definition: "Timing-safe comparisons reduce side-channel leakage when comparing sensitive values.",
    layer: "Cryptographic hygiene",
    protects: "Mitigates timing attacks against password hash verification paths.",
    inApp: "security_core uses constant-time comparison behavior for cryptographic verification paths."
  },
  {
    name: "Honeypot Endpoints",
    definition: "Honeypot endpoints are decoy routes designed to expose reconnaissance and exploit probing quickly.",
    layer: "Early threat detection",
    protects: "Improves visibility into reconnaissance and exploit attempts.",
    inApp: "Sensitive-looking routes (for example /internal-debug) emit dedicated security events."
  },
  {
    name: "Threat Detection Engine",
    definition: "The detection engine correlates audit events into detections, risk scoring, and analyst-visible timeline entries.",
    layer: "Detection and response",
    protects: "Correlates suspicious behavior into risk-scored alerts.",
    inApp: "Consumes security telemetry and powers dashboard alerts/timeline."
  },
  {
    name: "Automated Response (Blocklist/Lock Actions)",
    definition: "Automated response applies containment actions, such as IP blocking or account controls, based on detection outcomes.",
    layer: "Containment",
    protects: "Reduces attacker dwell time after high-confidence detections.",
    inApp: "Engine can block abusive IPs and enforce user lock controls with timeline evidence."
  },
  {
    name: "Structured Audit Logging",
    definition: "Structured audit logging records consistent machine-readable events for requests, security actions, and operational changes.",
    layer: "Observability and forensics",
    protects: "Enables incident reconstruction and detection correlation.",
    inApp: "Web app emits JSON audit events consumed by the engine service."
  },
  {
    name: "Docker Service Isolation",
    definition: "Docker service isolation keeps components in separate containers with controlled networking and minimized external exposure.",
    layer: "Runtime isolation",
    protects: "Limits direct access to internal components and reduces attack surface.",
    inApp: "Internal services use docker networks/expose, while public entry points are WAF ports."
  },
  {
    name: "Security-focused CI Checks",
    definition: "Security-focused CI checks enforce build validation and secret scanning before code changes are accepted.",
    layer: "Supply chain and SDLC security",
    protects: "Reduces risk of shipping obvious vulnerabilities or exposed secrets.",
    inApp: "GitHub Actions validate builds and run Gitleaks scanning."
  }
];

// OWASP Top 10 reference mapping shown in the learning section.
const owaspTop10 = [
  { id: "A01:2021", title: "Broken Access Control", definition: "Authorization checks fail to consistently enforce who can perform which actions.", inApp: "Role checks and protected endpoint enforcement." },
  { id: "A02:2021", title: "Cryptographic Failures", definition: "Sensitive data is exposed due to weak encryption, poor key handling, or unsafe secret practices.", inApp: "Signed tokens and protected credential workflows." },
  { id: "A03:2021", title: "Injection", definition: "Untrusted input is interpreted as code or commands by downstream systems.", inApp: "Validation plus edge filtering for suspicious payloads." },
  { id: "A04:2021", title: "Insecure Design", definition: "Architecture or workflow design lacks abuse-resistant controls from the start.", inApp: "Abuse-aware flows with lockout/rate-limit/detection controls." },
  { id: "A05:2021", title: "Security Misconfiguration", definition: "Insecure defaults or weak runtime settings expose unnecessary attack paths.", inApp: "Hardened headers, controlled origins, and secured defaults." },
  { id: "A06:2021", title: "Vulnerable Components", definition: "Outdated or risky dependencies introduce known exploitable weaknesses.", inApp: "Dependency-managed stack with update/scan workflow." },
  { id: "A07:2021", title: "Identification & Auth Failures", definition: "Authentication/session controls are weak, allowing account takeover or impersonation.", inApp: "Token auth flow, lockout/backoff, and admin restrictions." },
  { id: "A08:2021", title: "Software & Data Integrity Failures", definition: "Untrusted software, updates, or data are accepted without integrity verification.", inApp: "Signed token verification and controlled API flows." },
  { id: "A09:2021", title: "Security Logging & Monitoring Failures", definition: "Insufficient telemetry prevents timely detection, investigation, and response.", inApp: "Alerting, timeline, risk scoring, and audit telemetry." },
  { id: "A10:2021", title: "Server-Side Request Forgery (SSRF)", definition: "Server-Side Request Forgery lets an attacker force the server to send requests on the attacker's behalf, which can expose internal services, cloud metadata, or trusted network paths that should never be reachable from outside.", inApp: "No exposed arbitrary URL-fetch feature in normal app flow." }
];

// High-level architecture text shown in the architecture diagram panel.
const architectureDiagram = `Security Engineering Platform Architecture

External Client Layer
  Browser / Analyst Workstation
    -> WAF (Protected App Entry) :8080
    -> WAF (Dashboard Entry) :8081

Edge Security Layer
  WAF Proxies (Nginx + ModSecurity + OWASP CRS)
    -> Inspect and filter inbound HTTP traffic
    -> Enforce edge policy before application processing
    -> Forward sanitized traffic to internal services only

Application Layer
  Protected Web App API (Node.js / Express) :3000 [internal]
    -> AuthN/AuthZ: JWT + RBAC + CSRF + CORS
    -> Request controls: validation, rate limit, login protection
    -> App telemetry: structured audit events to log stream
    -> Data handling: user/session/settings workflows

Detection and Response Layer
  Threat Detection Engine (FastAPI + correlation) :8000
    -> Ingest audit log events from web app
    -> Generate detections, risk score, timeline artifacts
    -> Execute response actions (IP block, account controls)
    -> Expose telemetry API for dashboard consumption

Security Services Layer
  security_core (C++)
    -> Password hashing/verification support
    -> Crypto utility workflows used by app/engine

Data and Artifacts Layer
  webapp/data (users, settings, token records)
  webapp/logs/app.log (security telemetry source)
  engine/data (alerts, timeline, risk artifacts)

Operational Flows
  1) Request flow: Client -> WAF -> Web App
  2) Detection flow: Web App audit log -> Detection Engine correlation
  3) Visibility flow: Dashboard -> Detection API + protected app auth/admin endpoints
  4) Response loop: Detection outcomes -> containment actions -> timeline evidence`;

// Build a generic card element used by all section renderers.
function createCard(className, html) {
  const card = document.createElement("article");
  card.className = className;
  card.innerHTML = html;
  return card;
}

// Render detection scenario cards.
function renderDetections(items) {
  const container = document.getElementById("attackGrid");
  container.innerHTML = "";
  const orderedItems = [...items].sort((a, b) => String(a.title || "").localeCompare(String(b.title || "")));
  for (const item of orderedItems) {
    const howList = item.how.map((step) => `<li>${step}</li>`).join("");
    container.appendChild(createCard("attack-card", `
      <div class="pill">${item.id}</div>
      <h3>${item.title}</h3>
      <p class="small"><strong>Definition:</strong> ${item.definition}</p>
      <p class="small"><strong>Lab steps:</strong></p>
      <ol class="small">${howList}</ol>
      <details class="script-alt">
        <summary class="small"><strong>Optional scripted alternative</strong></summary>
        <p class="small"><strong>Windows PowerShell:</strong></p>
        <pre class="code-block">${item.windowsCommand || "n/a"}</pre>
        <p class="small"><strong>Kali Linux:</strong></p>
        <pre class="code-block">${item.kaliCommand || "n/a"}</pre>
      </details>
    `));
  }
}

// Render security feature/library cards.
function renderLibraries(items) {
  const container = document.getElementById("libraryGrid");
  container.innerHTML = "";
  const orderedItems = [...items].sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
  for (const item of orderedItems) {
    container.appendChild(createCard("library-card", `
      <h3>${item.name}</h3>
      <p class="small"><strong>Definition:</strong> ${item.definition}</p>
      <p class="small"><strong>Layer:</strong> ${item.layer}</p>
      <p class="small"><strong>What it protects:</strong> ${item.protects}</p>
      <p class="small"><strong>How it is used in this app:</strong> ${item.inApp}</p>
    `));
  }
}

// Render OWASP mapping cards.
function renderOwasp(items) {
  const container = document.getElementById("owaspGrid");
  container.innerHTML = "";
  for (const item of items) {
    container.appendChild(createCard("owasp-card", `
      <div class="mitre-id">${item.id}</div>
      <h3>${item.title}</h3>
      <p class="small"><strong>Definition:</strong> ${item.definition}</p>
      <p class="small"><strong>How this app addresses it:</strong> ${item.inApp}</p>
    `));
  }
}

// Normalize free-text search input for case-insensitive matching.
function normalize(value) {
  return String(value || "").toLowerCase();
}

// Filter all sections by user search query.1
function filterData(query) {
  if (!query) {
    return {
      detections: detectionScenarios,
      libraries: securityFeatures,
      owasp: owaspTop10
    };
  }

  const detections = detectionScenarios.filter((item) =>
    normalize(item.id).includes(query)
    || normalize(item.title).includes(query)
    || normalize(item.definition).includes(query)
    || normalize(item.how.join(" ")).includes(query)
    || normalize(item.windowsCommand).includes(query)
    || normalize(item.kaliCommand).includes(query)
  );

  const libraries = securityFeatures.filter((item) =>
    normalize(item.name).includes(query)
    || normalize(item.definition).includes(query)
    || normalize(item.layer).includes(query)
    || normalize(item.protects).includes(query)
    || normalize(item.inApp).includes(query)
  );

  const owasp = owaspTop10.filter((item) =>
    normalize(item.id).includes(query)
    || normalize(item.title).includes(query)
    || normalize(item.definition).includes(query)
    || normalize(item.inApp).includes(query)
  );

  return { detections, libraries, owasp };
}

// Expand/collapse a section header and keep button state in sync.
function toggleSection(toggleButton) {
  const controlsId = toggleButton.getAttribute("aria-controls");
  if (!controlsId) {
    return;
  }
  const body = document.getElementById(controlsId);
  if (!body) {
    return;
  }

  const section = toggleButton.closest(".collapsible");
  const isOpen = toggleButton.getAttribute("aria-expanded") === "true";
  const nextOpen = !isOpen;

  toggleButton.setAttribute("aria-expanded", String(nextOpen));
  body.hidden = !nextOpen;
  if (section) {
    section.classList.toggle("is-open", nextOpen);
  }
  const indicator = toggleButton.querySelector(".toggle-indicator");
  if (indicator) {
    indicator.textContent = nextOpen ? "-" : "+";
  }
}

// Programmatically open/close a section (used by search + nav links).
function setSectionOpen(bodyId, shouldOpen) {
  const body = document.getElementById(bodyId);
  if (!body) {
    return;
  }
  const section = body.closest(".collapsible");
  const toggleButton = section?.querySelector("button[data-toggle-section]");
  if (!toggleButton) {
    return;
  }
  const lockType = String(toggleButton.getAttribute("data-lock") || "none");
  if (!hasRequiredAccess(lockType)) {
    showLockHint(toggleButton);
    return;
  }

  toggleButton.setAttribute("aria-expanded", String(shouldOpen));
  body.hidden = !shouldOpen;
  section.classList.toggle("is-open", shouldOpen);
  const indicator = toggleButton.querySelector(".toggle-indicator");
  if (indicator) {
    indicator.textContent = shouldOpen ? "-" : "+";
  }
}

// Client-side auth/session storage key and frequently used DOM references.
const AUTH_STORAGE_KEY = "protected_app_auth_state";
const sessionAccessCard = document.getElementById("sessionAccessCard");
const sessionAccessContent = document.getElementById("sessionAccessContent");
const sectionToggles = Array.from(document.querySelectorAll("button[data-toggle-section]"));
const lockHint = document.getElementById("lockHint");
const authForm = document.getElementById("authForm");
const authCredentials = document.getElementById("authCredentials");
const authUsernameInput = document.getElementById("authUsername");
const authPasswordInput = document.getElementById("authPassword");
const authLoginBtn = document.getElementById("authLoginBtn");
const authLogoutBtn = document.getElementById("authLogoutBtn");
const authInfo = document.getElementById("authInfo");
const authStatus = document.getElementById("authStatus");
const sessionAccessCollapseDelayMs = 320;
let sessionAccessCollapseTimer = null;

// In-memory auth session model synchronized with localStorage.
let authState = loadAuthState();

// Read saved auth state from localStorage.
function loadAuthState() {
  try {
    const raw = localStorage.getItem(AUTH_STORAGE_KEY);
    if (!raw) {
      return { accessToken: "", refreshToken: "", user: null };
    }
    const parsed = JSON.parse(raw);
    return {
      accessToken: String(parsed?.accessToken || ""),
      refreshToken: String(parsed?.refreshToken || ""),
      user: parsed?.user || null
    };
  } catch {
    return { accessToken: "", refreshToken: "", user: null };
  }
}

// Persist current auth state to localStorage.
function saveAuthState() {
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(authState));
}

// Clear auth state and persist logged-out values.
function clearAuthState() {
  authState = { accessToken: "", refreshToken: "", user: null };
  saveAuthState();
}

// Shared session-expiry handler used when token validation fails.
function invalidateSession(message = "Session expired. Please log in again.") {
  clearAuthState();
  setAuthInfoText();
  setAuthStatusText(message);
  hideLockHint();
}

// Disable/enable auth buttons while requests are in flight.
function setAuthUiLoading(isLoading) {
  if (authLoginBtn) {
    authLoginBtn.disabled = isLoading;
  }
  if (authLogoutBtn) {
    authLogoutBtn.disabled = isLoading;
  }
}

// Role-aware lock check for protected UI sections.
function hasRequiredAccess(lockType) {
  const user = authState?.user;
  if (!lockType || lockType === "none") {
    return true;
  }
  if (lockType === "user") {
    return Boolean(authState?.accessToken && user);
  }
  if (lockType === "admin") {
    return Boolean(authState?.accessToken && user && String(user.role) === "admin");
  }
  return true;
}

// User-facing lock hint message based on lock requirement.
function lockMessage(lockType) {
  if (lockType === "admin") {
    return "Admin login required";
  }
  return "Login required";
}

// Refresh lock styles/states on all collapsible section buttons.
function updateSectionLocks() {
  for (const toggle of sectionToggles) {
    const lockType = String(toggle.getAttribute("data-lock") || "none");
    const isAllowed = hasRequiredAccess(lockType);
    toggle.classList.toggle("locked", !isAllowed);
    toggle.setAttribute("aria-disabled", String(!isAllowed));
  }
}

// Hide floating lock hint bubble.
function hideLockHint() {
  if (!lockHint) {
    return;
  }
  lockHint.classList.remove("user-lock", "admin-lock");
  lockHint.hidden = true;
}

// Show floating lock hint near the clicked locked section toggle.
function showLockHint(toggle) {
  if (!lockHint) {
    return;
  }
  const lockType = String(toggle.getAttribute("data-lock") || "user");
  if (hasRequiredAccess(lockType)) {
    hideLockHint();
    return;
  }

  lockHint.classList.remove("user-lock", "admin-lock");
  lockHint.classList.add(lockType === "admin" ? "admin-lock" : "user-lock");
  lockHint.textContent = lockMessage(lockType);
  const rect = toggle.getBoundingClientRect();
  const top = rect.top + window.scrollY - 32;
  const left = rect.right + window.scrollX - 170;
  lockHint.style.top = `${Math.max(8, top)}px`;
  lockHint.style.left = `${Math.max(8, left)}px`;
  lockHint.hidden = false;
}

// Open/close session-access card content panel.
function setSessionAccessOpen(isOpen) {
  if (!sessionAccessContent) {
    return;
  }
  sessionAccessContent.classList.toggle("is-open", isOpen);
}

// Hover handlers for session-access expandable card.
if (sessionAccessCard) {
  sessionAccessCard.addEventListener("mouseenter", () => {
    if (sessionAccessCollapseTimer) {
      clearTimeout(sessionAccessCollapseTimer);
      sessionAccessCollapseTimer = null;
    }
    setSessionAccessOpen(true);
  });

  sessionAccessCard.addEventListener("mouseleave", () => {
    if (sessionAccessCollapseTimer) {
      clearTimeout(sessionAccessCollapseTimer);
    }
    sessionAccessCollapseTimer = setTimeout(() => {
      setSessionAccessOpen(false);
      sessionAccessCollapseTimer = null;
    }, sessionAccessCollapseDelayMs);
  });
}

// Update auth status text and role-specific card styling.
function setAuthInfoText() {
  if (!authInfo) {
    return;
  }
  const hasSession = Boolean(authState?.accessToken);
  const isLoggedIn = hasSession;
  if (authCredentials) {
    authCredentials.hidden = isLoggedIn;
  }
  if (authLoginBtn) {
    authLoginBtn.hidden = isLoggedIn;
  }
  if (authLogoutBtn) {
    authLogoutBtn.hidden = !isLoggedIn;
  }
  if (sessionAccessCard) {
    sessionAccessCard.classList.remove("state-user", "state-admin");
  }
  if (hasSession && authState?.user?.username) {
    authInfo.textContent = `Logged in as ${authState.user.username} (${authState.user.role || "user"}).`;
    if (sessionAccessCard) {
      if (String(authState.user.role) === "admin") {
        sessionAccessCard.classList.add("state-admin");
      } else {
        sessionAccessCard.classList.add("state-user");
      }
    }
    updateSectionLocks();
    return;
  }
  if (hasSession) {
    authInfo.textContent = "Session active.";
    updateSectionLocks();
    return;
  }
  authInfo.textContent = "Not logged in.";
  updateSectionLocks();
}

// Update inline auth status message.
function setAuthStatusText(message) {
  if (authStatus) {
    authStatus.textContent = String(message || "");
  }
}

// Request CSRF token before state-changing API operations.
async function fetchCsrfToken() {
  const response = await fetch("/api/csrf-token", {
    method: "GET",
    credentials: "include"
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload?.csrfToken) {
    throw new Error(payload?.error || "Could not fetch CSRF token");
  }
  return payload.csrfToken;
}

// CSRF-protected POST helper with token-expiry handling.
async function postWithCsrf(path, body, accessToken = "") {
  const csrfToken = await fetchCsrfToken();
  const response = await fetch(path, {
    method: "POST",
    credentials: "include",
    headers: {
      "content-type": "application/json",
      "x-csrf-token": csrfToken,
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {})
    },
    body: JSON.stringify(body || {})
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const errorText = String(payload?.error || "").toLowerCase();
    const isInvalidToken = response.status === 401
      || response.status === 403
      || errorText.includes("invalid access token")
      || errorText.includes("invalid token")
      || errorText.includes("jwt");
    if (isInvalidToken) {
      invalidateSession();
      throw new Error("Session expired");
    }
    throw new Error(payload?.error || `Request failed for ${path}`);
  }
  return payload;
}

// Validate persisted session token and refresh displayed identity.
async function validateStoredSession() {
  if (!authState.accessToken) {
    setAuthInfoText();
    return;
  }
  try {
    const response = await fetch("/api/auth/me", {
      method: "GET",
      credentials: "include",
      headers: { authorization: `Bearer ${authState.accessToken}` }
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const errorText = String(payload?.error || "").toLowerCase();
      const isInvalidToken = response.status === 401
        || response.status === 403
        || errorText.includes("invalid access token")
        || errorText.includes("invalid token")
        || errorText.includes("jwt");
      if (isInvalidToken) {
        invalidateSession();
        return;
      }
      throw new Error(payload?.error || "Session not valid");
    }
    authState.user = {
      id: payload.id,
      username: payload.username,
      role: payload.role
    };
    saveAuthState();
    setAuthInfoText();
  } catch {
    invalidateSession();
  }
}

// Login form submit wiring.
if (authForm) {
  authForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = String(authUsernameInput?.value || "").trim();
    const password = String(authPasswordInput?.value || "");
    if (!username || !password) {
      setAuthStatusText("Enter username and password.");
      return;
    }

    setAuthUiLoading(true);
    setAuthStatusText("Logging in...");
    try {
      const payload = await postWithCsrf("/api/auth/login", { username, password });
      authState = {
        accessToken: String(payload?.accessToken || ""),
        refreshToken: String(payload?.refreshToken || ""),
        user: payload?.user || null
      };
      saveAuthState();
      if (authPasswordInput) {
        authPasswordInput.value = "";
      }
      setAuthInfoText();
      setAuthStatusText("Login successful.");
      hideLockHint();
    } catch (error) {
      setAuthStatusText(`Login failed: ${error.message}`);
    } finally {
      setAuthUiLoading(false);
    }
  });
}

// Logout button wiring.
if (authLogoutBtn) {
  authLogoutBtn.addEventListener("click", async () => {
    if (!authState.accessToken) {
      setAuthStatusText("Already logged out.");
      return;
    }
    setAuthUiLoading(true);
    setAuthStatusText("Logging out...");
    try {
      await postWithCsrf(
        "/api/auth/logout",
        { refreshToken: authState.refreshToken || "" },
        authState.accessToken
      );
    } catch {
      // Clear local state even if logout request fails.
    } finally {
      clearAuthState();
      setAuthInfoText();
      setAuthStatusText("Logged out.");
      setAuthUiLoading(false);
      hideLockHint();
    }
  });
}

// Global click handling for nav shortcuts and collapsible sections.
document.addEventListener("click", (event) => {
  hideLockHint();

  const navLink = event.target.closest(".links a[data-open-body]");
  if (navLink) {
    const bodyId = navLink.getAttribute("data-open-body");
    if (bodyId) {
      setSectionOpen(bodyId, true);
    }
  }

  const sectionToggle = event.target.closest("button[data-toggle-section]");
  if (sectionToggle) {
    const lockType = String(sectionToggle.getAttribute("data-lock") || "none");
    if (!hasRequiredAccess(lockType)) {
      showLockHint(sectionToggle);
      return;
    }
    toggleSection(sectionToggle);
  }
});

// Search form submit: filter and rerender all visible data cards.
document.getElementById("searchForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const query = normalize(document.getElementById("searchInput").value.trim());
  const filtered = filterData(query);
  renderDetections(filtered.detections);
  renderLibraries(filtered.libraries);
  renderOwasp(filtered.owasp);

  if (query.length > 0) {
    setSectionOpen("detectionsBody", filtered.detections.length > 0);
    setSectionOpen("librariesBody", filtered.libraries.length > 0);
    setSectionOpen("owaspBody", filtered.owasp.length > 0);
  }
});

// Initial render and auth/session bootstrapping.
renderDetections(detectionScenarios);
renderLibraries(securityFeatures);
renderOwasp(owaspTop10);
setAuthInfoText();
updateSectionLocks();
void validateStoredSession();
setInterval(() => {
  if (authState.accessToken) {
    void validateStoredSession();
  }
}, 30000);

// Re-validate session when tab regains visibility.
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && authState.accessToken) {
    void validateStoredSession();
  }
});

// Populate architecture text block on page load.
const architectureDiagramBox = document.getElementById("architectureDiagram");
if (architectureDiagramBox) {
  architectureDiagramBox.textContent = architectureDiagram;
}

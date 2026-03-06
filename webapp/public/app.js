const detectionScenarios = [
  {
    id: "DET-01",
    title: "Failed Login Burst",
    reference: "Detector: FAILED_LOGIN_BURST | MITRE T1110",
    exploitPath: "POST /api/auth/login with repeated bad credentials from one source.",
    how: [
      "Send repeated invalid password attempts for one username.",
      "Keep source IP consistent.",
      "Observe throttling and login-denied behavior."
    ],
    detects: "LOGIN_FAIL, LOGIN_RATE_LIMIT, LOGIN_THROTTLED, FAILED_LOGIN_BURST.",
    defends: "loginRateLimiter + adaptive backoff in loginProtection.js + account lock checks.",
    windowsCommand: "1..5 | % { try { Invoke-RestMethod -Method Post -Uri \"$base/api/auth/login\" -WebSession $s -Headers @{\"x-csrf-token\"=$csrf;\"content-type\"=\"application/json\"} -Body '{\"username\":\"analystlab\",\"password\":\"wrongpass12345\"}' -ErrorAction Stop | Out-Null } catch {} }",
    kaliCommand: "for i in $(seq 1 5); do curl -s -b \"$cookie\" -c \"$cookie\" -X POST \"$base/api/auth/login\" -H \"x-csrf-token: $csrf\" -H \"content-type: application/json\" -d '{\"username\":\"analystlab\",\"password\":\"wrongpass12345\"}' >/dev/null; done"
  },
  {
    id: "DET-02",
    title: "Account Enumeration",
    reference: "Detector: ACCOUNT_ENUMERATION | MITRE T1110",
    exploitPath: "POST /api/auth/login across many usernames with invalid passwords.",
    how: [
      "Use one IP and rotate username values quickly.",
      "Send invalid passwords for each attempt.",
      "Check alerts for distinct-user probing behavior."
    ],
    detects: "ACCOUNT_ENUMERATION from repeated distinct username failures.",
    defends: "Login rate limits, adaptive backoff, and threat-engine correlation by source IP and username spread.",
    windowsCommand: "\"enum001\",\"enum002\",\"enum003\",\"enum004\",\"enum005\" | % { $u=$_; try { Invoke-RestMethod -Method Post -Uri \"$base/api/auth/login\" -WebSession $s -Headers @{\"x-csrf-token\"=$csrf;\"content-type\"=\"application/json\"} -Body (@{username=$u;password='wrongpass12345'} | ConvertTo-Json) -ErrorAction Stop | Out-Null } catch {} }",
    kaliCommand: "for u in enum001 enum002 enum003 enum004 enum005; do curl -s -b \"$cookie\" -c \"$cookie\" -X POST \"$base/api/auth/login\" -H \"x-csrf-token: $csrf\" -H \"content-type: application/json\" -d \"{\\\"username\\\":\\\"$u\\\",\\\"password\\\":\\\"wrongpass12345\\\"}\" >/dev/null; done"
  },
  {
    id: "DET-03",
    title: "Honeypot Trigger",
    reference: "Detector: HONEYPOT_TRIGGER | MITRE T1190",
    exploitPath: "GET fake sensitive routes intentionally exposed as decoys.",
    how: [
      "Request /internal-debug, /.env, or /admin-backup.",
      "Repeat from same source to simulate recon.",
      "Confirm decoy endpoint event generation."
    ],
    detects: "HONEYPOT_TRIGGER with request metadata.",
    defends: "Honeypot routes always return 404 and generate high-signal audit events.",
    windowsCommand: "curl.exe -i \"http://localhost:8080/internal-debug\"",
    kaliCommand: "curl -i \"http://localhost:8080/internal-debug\""
  },
  {
    id: "DET-04",
    title: "Path Traversal Attempt",
    reference: "Detector: PATH_TRAVERSAL_ATTEMPT | MITRE T1083",
    exploitPath: "Inject traversal payloads like ../ into route/query parameters.",
    how: [
      "Send traversal payloads against suspicious paths.",
      "Watch for WAF/CRS blocking.",
      "Correlate event in detector timeline."
    ],
    detects: "WAF anomaly + PATH_TRAVERSAL_ATTEMPT classification.",
    defends: "ModSecurity + OWASP CRS in front of app, plus constrained route behavior.",
    windowsCommand: "curl.exe -i \"http://localhost:8080/admin-backup?path=../etc/passwd\"",
    kaliCommand: "curl -i \"http://localhost:8080/admin-backup?path=../etc/passwd\""
  },
  {
    id: "DET-05",
    title: "Privilege Escalation Attempt",
    reference: "Detector: PRIV_ESC_ATTEMPT | MITRE T1068",
    exploitPath: "Use non-admin token against admin-only routes.",
    how: [
      "Authenticate as analyst.",
      "Request admin-only endpoints such as /api/auth/users.",
      "Validate server-side 403 and detection events."
    ],
    detects: "AUTHZ_DENIED and PRIV_ESC_ATTEMPT correlation.",
    defends: "authenticateToken + authorize('admin') RBAC checks on sensitive routes.",
    windowsCommand: "curl.exe -i \"http://localhost:8080/api/auth/users\" -H \"Authorization: Bearer <analyst_token>\"",
    kaliCommand: "curl -i \"http://localhost:8080/api/auth/users\" -H \"Authorization: Bearer <analyst_token>\""
  },
  {
    id: "DET-06",
    title: "Excessive API Calls / Request Frequency",
    reference: "Detector: EXCESSIVE_API_CALLS, ABNORMAL_REQUEST_FREQUENCY | MITRE T1498",
    exploitPath: "High-frequency traffic floods to normal API endpoints.",
    how: [
      "Burst calls to /api/health or login endpoints.",
      "Observe 429 responses and potential blocklist actions.",
      "Review detector summary for abuse frequency alerts."
    ],
    detects: "RATE_LIMIT, EXCESSIVE_API_CALLS, ABNORMAL_REQUEST_FREQUENCY.",
    defends: "Global and per-route express-rate-limit + blocklistGuard for blocked source IPs.",
    windowsCommand: "1..170 | % { try { Invoke-WebRequest -UseBasicParsing -Uri \"http://localhost:8080/api/health\" | Out-Null } catch {} }",
    kaliCommand: "for i in $(seq 1 170); do curl -s \"http://localhost:8080/api/health\" >/dev/null; done"
  },
  {
    id: "DET-07",
    title: "Full Detector Validation Script",
    reference: "Covers all implemented detector classes in one run",
    exploitPath: "Scripted sequence against auth, honeypot, traversal, authz, and request-rate paths.",
    how: [
      "Run the platform script from project root.",
      "Review ALERT_TYPES output at the end.",
      "Confirm all expected detector names are present."
    ],
    detects: "FAILED_LOGIN_BURST, ACCOUNT_ENUMERATION, HONEYPOT_TRIGGER, PATH_TRAVERSAL_ATTEMPT, PRIV_ESC_ATTEMPT, EXCESSIVE_API_CALLS, ABNORMAL_REQUEST_FREQUENCY.",
    defends: "Demonstrates end-to-end logging, correlation, risk scoring, and automated controls.",
    windowsCommand: "powershell -ExecutionPolicy Bypass -File scripts/trigger_all_alerts.ps1",
    kaliCommand: "bash scripts/trigger_all_alerts_kali.sh"
  }
];

const securityLibraries = [
  {
    name: "helmet",
    layer: "HTTP security headers",
    protects: "Applies hardened browser-facing defaults to reduce common misconfiguration abuse.",
    references: "OWASP A05",
    implementation: "app.use(helmet()) in webapp/src/server.js."
  },
  {
    name: "csurf",
    layer: "CSRF token enforcement",
    protects: "Blocks state-changing requests without valid token/cookie pairing.",
    references: "OWASP A01/A05",
    implementation: "CSRF protection on /api/auth and /api in webapp/src/server.js."
  },
  {
    name: "cors",
    layer: "Cross-origin policy",
    protects: "Restricts browser-origin access to trusted front-end origin instead of allowing arbitrary sites.",
    references: "OWASP A05",
    implementation: "app.use(cors({ origin, credentials:true })) in webapp/src/server.js."
  },
  {
    name: "cookie-parser",
    layer: "Cookie handling for CSRF/session flow",
    protects: "Supports secure cookie parsing used by CSRF token validation and trusted request flow.",
    references: "OWASP A01/A05",
    implementation: "app.use(cookieParser(...)) in webapp/src/server.js with strict CSRF cookie settings."
  },
  {
    name: "express-rate-limit",
    layer: "Abuse throttling",
    protects: "Controls brute-force and flood speed on global and auth endpoints.",
    references: "MITRE T1110, T1498 | OWASP A04",
    implementation: "Global limiter in server.js and login/refresh limiters in authRoutes.js."
  },
  {
    name: "zod",
    layer: "Input validation",
    protects: "Rejects malformed payloads before route logic executes.",
    references: "OWASP A03",
    implementation: "Schemas in webapp/src/middleware/validation.js."
  },
  {
    name: "jsonwebtoken",
    layer: "Token integrity",
    protects: "Ensures signed access/refresh tokens are verified server-side.",
    references: "OWASP A07",
    implementation: "JWT sign/verify in authRoutes.js and middleware/auth.js."
  },
  {
    name: "Auth + RBAC middleware",
    layer: "Authorization enforcement",
    protects: "Prevents privilege escalation by requiring valid token + role checks on protected routes.",
    references: "OWASP A01 | MITRE T1068",
    implementation: "authenticateToken (auth.js) + authorize('admin') (rbac.js) on sensitive endpoints."
  },
  {
    name: "ModSecurity + OWASP CRS",
    layer: "Edge WAF",
    protects: "Filters exploit payloads before requests reach application routes.",
    references: "MITRE T1190 | OWASP A03/A05",
    implementation: "WAF reverse proxy in front of webapp via docker-compose."
  }
];

const owaspTop10 = [
  {
    id: "A01:2021",
    title: "Broken Access Control",
    explanation: "Unauthorized actions/data access due to missing or weak authorization checks.",
    appMapping: "RBAC middleware, token auth, and locked-account checks."
  },
  {
    id: "A02:2021",
    title: "Cryptographic Failures",
    explanation: "Sensitive data compromise from weak encryption/hashing or key management.",
    appMapping: "Password hashing through security core and signed JWT handling."
  },
  {
    id: "A03:2021",
    title: "Injection",
    explanation: "Untrusted input interpreted as executable/query syntax.",
    appMapping: "Validation layers plus WAF filtering and constrained upload logic."
  },
  {
    id: "A04:2021",
    title: "Insecure Design",
    explanation: "System-level design gaps that permit abuse paths.",
    appMapping: "Abuse-aware design: rate limits, lockout/backoff, threat telemetry hooks."
  },
  {
    id: "A05:2021",
    title: "Security Misconfiguration",
    explanation: "Unsafe defaults and exposed internal behavior.",
    appMapping: "Helmet, controlled CORS, CSRF config, and honeypot routes."
  },
  {
    id: "A06:2021",
    title: "Vulnerable and Outdated Components",
    explanation: "Exploitability through known dependency vulnerabilities.",
    appMapping: "Pinned dependencies with recommended CI vulnerability scanning."
  },
  {
    id: "A07:2021",
    title: "Identification and Authentication Failures",
    explanation: "Weak auth/session controls enabling account compromise.",
    appMapping: "JWT auth, throttled login, refresh token lifecycle, lock handling."
  },
  {
    id: "A08:2021",
    title: "Software and Data Integrity Failures",
    explanation: "Untrusted data/code accepted without integrity validation.",
    appMapping: "Token signature checks and strict server-side validation flow."
  },
  {
    id: "A09:2021",
    title: "Security Logging and Monitoring Failures",
    explanation: "Insufficient security telemetry for detection and response.",
    appMapping: "Structured audit logs, timeline output, and risk-scored alerts."
  },
  {
    id: "A10:2021",
    title: "SSRF",
    explanation: "Server coerced into outbound requests to attacker-selected targets.",
    appMapping: "No direct user-driven URL fetch endpoints currently exposed."
  }
];

function createCard(className, html) {
  const card = document.createElement("article");
  card.className = className;
  card.innerHTML = html;
  return card;
}

function renderDetections(items) {
  const container = document.getElementById("attackGrid");
  container.innerHTML = "";
  for (const item of items) {
    const howList = item.how.map((step) => `<li>${step}</li>`).join("");
    container.appendChild(createCard("attack-card", `
      <div class="pill">${item.id}</div>
      <h3>${item.title}</h3>
      <p class="small"><strong>Reference:</strong> ${item.reference}</p>
      <p class="small"><strong>Exploit path:</strong> ${item.exploitPath}</p>
      <p class="small"><strong>Lab steps:</strong></p>
      <ol class="small">${howList}</ol>
      <p class="small"><strong>Detection output:</strong> ${item.detects}</p>
      <p class="small"><strong>Defenses:</strong> ${item.defends}</p>
      <p class="small"><strong>Windows PowerShell:</strong></p>
      <pre class="code-block">${item.windowsCommand || "n/a"}</pre>
      <p class="small"><strong>Kali Linux (WSL):</strong></p>
      <pre class="code-block">${item.kaliCommand || "n/a"}</pre>
    `));
  }
}

function renderLibraries(items) {
  const container = document.getElementById("libraryGrid");
  container.innerHTML = "";
  for (const item of items) {
    container.appendChild(createCard("library-card", `
      <h3>${item.name}</h3>
      <p class="small"><strong>Layer:</strong> ${item.layer}</p>
      <p class="small"><strong>Protects:</strong> ${item.protects}</p>
      <p class="small"><strong>References:</strong> ${item.references}</p>
      <p class="small"><strong>Project mapping:</strong> ${item.implementation}</p>
    `));
  }
}

function renderOwasp(items) {
  const container = document.getElementById("owaspGrid");
  container.innerHTML = "";
  for (const item of items) {
    container.appendChild(createCard("owasp-card", `
      <div class="mitre-id">${item.id}</div>
      <h3>${item.title}</h3>
      <p class="small"><strong>Meaning:</strong> ${item.explanation}</p>
      <p class="small"><strong>App mapping:</strong> ${item.appMapping}</p>
    `));
  }
}

function normalize(value) {
  return String(value || "").toLowerCase();
}

function filterData(query) {
  if (!query) {
    return {
      detections: detectionScenarios,
      libraries: securityLibraries,
      owasp: owaspTop10
    };
  }

  const detections = detectionScenarios.filter((item) =>
    normalize(item.id).includes(query)
    || normalize(item.title).includes(query)
    || normalize(item.reference).includes(query)
    || normalize(item.exploitPath).includes(query)
    || normalize(item.detects).includes(query)
    || normalize(item.defends).includes(query)
  );

  const libraries = securityLibraries.filter((item) =>
    normalize(item.name).includes(query)
    || normalize(item.layer).includes(query)
    || normalize(item.protects).includes(query)
    || normalize(item.references).includes(query)
    || normalize(item.implementation).includes(query)
  );

  const owasp = owaspTop10.filter((item) =>
    normalize(item.id).includes(query)
    || normalize(item.title).includes(query)
    || normalize(item.explanation).includes(query)
    || normalize(item.appMapping).includes(query)
  );

  return { detections, libraries, owasp };
}

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

  toggleButton.setAttribute("aria-expanded", String(shouldOpen));
  body.hidden = !shouldOpen;
  section.classList.toggle("is-open", shouldOpen);
  const indicator = toggleButton.querySelector(".toggle-indicator");
  if (indicator) {
    indicator.textContent = shouldOpen ? "-" : "+";
  }
}

document.addEventListener("click", (event) => {
  const navLink = event.target.closest(".links a[data-open-body]");
  if (navLink) {
    const bodyId = navLink.getAttribute("data-open-body");
    if (bodyId) {
      setSectionOpen(bodyId, true);
    }
  }

  const sectionToggle = event.target.closest("button[data-toggle-section]");
  if (sectionToggle) {
    toggleSection(sectionToggle);
  }
});

document.getElementById("searchForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const query = normalize(document.getElementById("searchInput").value.trim());
  const filtered = filterData(query);
  renderDetections(filtered.detections);
  renderLibraries(filtered.libraries);
  renderOwasp(filtered.owasp);

  const hasQuery = query.length > 0;
  if (hasQuery) {
    setSectionOpen("detectionsBody", filtered.detections.length > 0);
    setSectionOpen("librariesBody", filtered.libraries.length > 0);
    setSectionOpen("owaspBody", filtered.owasp.length > 0);
  }
});

renderDetections(detectionScenarios);
renderLibraries(securityLibraries);
renderOwasp(owaspTop10);

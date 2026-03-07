const detectionScenarios = [
  {
    id: "DET-01",
    title: "Failed Login Burst",
    how: [
      "Send repeated invalid password attempts for one username.",
      "Keep source IP consistent.",
      "Validate alert creation in the dashboard."
    ],
    windowsCommand: "1..5 | % { try { Invoke-RestMethod -Method Post -Uri \"$base/api/auth/login\" -WebSession $s -Headers @{\"x-csrf-token\"=$csrf;\"content-type\"=\"application/json\"} -Body '{\"username\":\"analystlab\",\"password\":\"wrongpass12345\"}' -ErrorAction Stop | Out-Null } catch {} }",
    kaliCommand: "BASE=\"http://localhost:8080\"; COOKIE=\"cookies.txt\"; CSRF=$(curl -s -c \"$COOKIE\" \"$BASE/api/csrf-token\" | jq -r '.csrfToken'); echo \"$CSRF\"; for i in $(seq 1 5); do curl -s -b \"$COOKIE\" -c \"$COOKIE\" -X POST \"$BASE/api/auth/login\" -H \"x-csrf-token: $CSRF\" -H \"content-type: application/json\" -d '{\"username\":\"analystlab\",\"password\":\"wrongpass12345\"}' >/dev/null; done"
  },
  {
    id: "DET-02",
    title: "Account Enumeration",
    how: [
      "Use one IP and rotate usernames quickly.",
      "Use invalid passwords for every attempt.",
      "Validate account-enumeration alert in dashboard."
    ],
    windowsCommand: "\"enum001\",\"enum002\",\"enum003\",\"enum004\",\"enum005\" | % { $u=$_; try { Invoke-RestMethod -Method Post -Uri \"$base/api/auth/login\" -WebSession $s -Headers @{\"x-csrf-token\"=$csrf;\"content-type\"=\"application/json\"} -Body (@{username=$u;password='wrongpass12345'} | ConvertTo-Json) -ErrorAction Stop | Out-Null } catch {} }",
    kaliCommand: "BASE=\"http://localhost:8080\"; COOKIE=\"cookies.txt\"; CSRF=$(curl -s -c \"$COOKIE\" \"$BASE/api/csrf-token\" | jq -r '.csrfToken'); echo \"$CSRF\"; for u in enum001 enum002 enum003 enum004 enum005; do curl -s -b \"$COOKIE\" -c \"$COOKIE\" -X POST \"$BASE/api/auth/login\" -H \"x-csrf-token: $CSRF\" -H \"content-type: application/json\" -d \"{\\\"username\\\":\\\"$u\\\",\\\"password\\\":\\\"wrongpass12345\\\"}\" >/dev/null; done"
  },
  {
    id: "DET-03",
    title: "Honeypot Trigger",
    how: [
      "Request the honeypot route.",
      "Confirm event appears in timeline/alerts."
    ],
    windowsCommand: "curl.exe -i \"http://localhost:8080/internal-debug\"",
    kaliCommand: "curl -i \"http://localhost:8080/internal-debug\""
  },
  {
    id: "DET-04",
    title: "Path Traversal Attempt",
    how: [
      "Send traversal payload against the lab route.",
      "Review resulting alert/timeline event."
    ],
    windowsCommand: "curl.exe -i \"http://localhost:8080/admin-backup?path=../etc/passwd\"",
    kaliCommand: "curl -i \"http://localhost:8080/admin-backup?path=../etc/passwd\""
  },
  {
    id: "DET-05",
    title: "Privilege Escalation Attempt",
    how: [
      "Authenticate as analyst.",
      "Call admin-only endpoint with analyst token.",
      "Confirm denial + detection event."
    ],
    windowsCommand: "$base='http://localhost:8080'; $u='goose2'; $p='pass12345678'; $s=New-Object Microsoft.PowerShell.Commands.WebRequestSession; $csrf=(Invoke-RestMethod -Method Get -Uri \"$base/api/csrf-token\" -WebSession $s).csrfToken; $login=Invoke-RestMethod -Method Post -Uri \"$base/api/auth/login\" -WebSession $s -Headers @{\"x-csrf-token\"=$csrf;\"content-type\"=\"application/json\"} -Body (\"{\\\"username\\\":\\\"$u\\\",\\\"password\\\":\\\"$p\\\"}\"); curl.exe -i \"$base/api/auth/users\" -H (\"Authorization: Bearer \" + $login.accessToken)",
    kaliCommand: "BASE=\"http://localhost:8080\"; USER=\"goose2\"; PASS=\"pass12345678\"; CSRF=$(curl -s -c cookies.txt \"$BASE/api/csrf-token\" | jq -r '.csrfToken'); TOKEN=$(curl -s -b cookies.txt -c cookies.txt -H \"Content-Type: application/json\" -H \"X-CSRF-Token: $CSRF\" -d \"{\\\"username\\\":\\\"$USER\\\",\\\"password\\\":\\\"$PASS\\\"}\" \"$BASE/api/auth/login\" | jq -r '.accessToken'); curl -i -b cookies.txt -H \"Authorization: Bearer $TOKEN\" \"$BASE/api/auth/users\""
  },
  {
    id: "DET-06",
    title: "Excessive API Calls / Request Frequency",
    how: [
      "Burst normal API traffic.",
      "Observe frequency-based detections."
    ],
    windowsCommand: "1..50 | % { try { Invoke-WebRequest -UseBasicParsing -Uri \"http://localhost:8080/api/health\" | Out-Null } catch {} }",
    kaliCommand: "for i in $(seq 1 50); do curl -s \"http://localhost:8080/api/health\" >/dev/null; done"
  }
];

const securityFeatures = [
  {
    name: "Helmet",
    layer: "HTTP hardening",
    protects: "Adds secure browser-facing response headers by default.",
    inApp: "Used as baseline header protection for app responses."
  },
  {
    name: "CSRF Protection",
    layer: "State-change request integrity",
    protects: "Requires valid anti-CSRF token on sensitive operations.",
    inApp: "Used for auth and protected API request flows."
  },
  {
    name: "CORS Policy",
    layer: "Cross-origin controls",
    protects: "Restricts which origins can make credentialed browser requests.",
    inApp: "Configured to allow trusted frontend origin(s)."
  },
  {
    name: "JWT Authentication",
    layer: "Identity and session",
    protects: "Ensures protected APIs require valid signed access tokens.",
    inApp: "Used for authenticated route access and session refresh workflow."
  },
  {
    name: "RBAC",
    layer: "Authorization",
    protects: "Prevents non-admin users from accessing admin functionality.",
    inApp: "Applied on admin-only routes such as user management."
  },
  {
    name: "Rate Limiting",
    layer: "Abuse prevention",
    protects: "Slows brute-force and burst traffic patterns.",
    inApp: "Applied globally and on high-risk auth/API routes."
  },
  {
    name: "Input Validation",
    layer: "Request sanitization",
    protects: "Rejects malformed or unexpected request payloads.",
    inApp: "Used on auth and user-management related payloads."
  },
  {
    name: "WAF + OWASP CRS",
    layer: "Edge filtering",
    protects: "Detects/blocks common web payload patterns before app logic.",
    inApp: "Runs at the reverse-proxy edge in front of the web app."
  },
  {
    name: "Threat Detection Engine",
    layer: "Detection and response",
    protects: "Correlates suspicious behavior into risk-scored alerts.",
    inApp: "Consumes security telemetry and powers dashboard alerts/timeline."
  }
];

const owaspTop10 = [
  { id: "A01:2021", title: "Broken Access Control", meaning: "Unauthorized access due to missing/weak authorization checks.", inApp: "Role checks and protected endpoint enforcement." },
  { id: "A02:2021", title: "Cryptographic Failures", meaning: "Sensitive data exposure from weak crypto handling.", inApp: "Signed tokens and protected credential workflows." },
  { id: "A03:2021", title: "Injection", meaning: "Untrusted input interpreted as commands/queries.", inApp: "Validation plus edge filtering for suspicious payloads." },
  { id: "A04:2021", title: "Insecure Design", meaning: "Design-level gaps enabling abuse paths.", inApp: "Abuse-aware flows with lockout/rate-limit/detection controls." },
  { id: "A05:2021", title: "Security Misconfiguration", meaning: "Unsafe defaults and weak environment/config setup.", inApp: "Hardened headers, controlled origins, and secured defaults." },
  { id: "A06:2021", title: "Vulnerable Components", meaning: "Outdated dependencies with known CVEs.", inApp: "Dependency-managed stack with update/scan workflow." },
  { id: "A07:2021", title: "Identification & Auth Failures", meaning: "Weak login/session controls.", inApp: "Token auth flow, lockout/backoff, and admin restrictions." },
  { id: "A08:2021", title: "Software & Data Integrity Failures", meaning: "Untrusted data/code accepted without integrity validation.", inApp: "Signed token verification and controlled API flows." },
  { id: "A09:2021", title: "Security Logging & Monitoring Failures", meaning: "Insufficient visibility for detection and response.", inApp: "Alerting, timeline, risk scoring, and audit telemetry." },
  { id: "A10:2021", title: "SSRF", meaning: "Server abused into making attacker-controlled outbound calls.", inApp: "No exposed arbitrary URL-fetch feature in normal app flow." }
];

const architectureDiagram = `Browser/Client\n  -> WAF Proxy (Nginx + CRS)\n    -> Protected Web App API\n      -> Security Event Logs\n        -> Python Detection Engine\n          -> Alerts + Risk + Timeline\n            -> Threat Detection Dashboard\n\nAdmin controls: Block/Unblock IP, Test IP management, User management\nManual lab flow: Trigger scenarios -> verify alerts/timeline/risk`; 

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
      <p class="small"><strong>Lab steps:</strong></p>
      <ol class="small">${howList}</ol>
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
      <p class="small"><strong>What it protects:</strong> ${item.protects}</p>
      <p class="small"><strong>How it is used in this app:</strong> ${item.inApp}</p>
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
      <p class="small"><strong>General meaning:</strong> ${item.meaning}</p>
      <p class="small"><strong>How this app addresses it:</strong> ${item.inApp}</p>
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
      libraries: securityFeatures,
      owasp: owaspTop10
    };
  }

  const detections = detectionScenarios.filter((item) =>
    normalize(item.id).includes(query)
    || normalize(item.title).includes(query)
    || normalize(item.how.join(" ")).includes(query)
    || normalize(item.windowsCommand).includes(query)
    || normalize(item.kaliCommand).includes(query)
  );

  const libraries = securityFeatures.filter((item) =>
    normalize(item.name).includes(query)
    || normalize(item.layer).includes(query)
    || normalize(item.protects).includes(query)
    || normalize(item.inApp).includes(query)
  );

  const owasp = owaspTop10.filter((item) =>
    normalize(item.id).includes(query)
    || normalize(item.title).includes(query)
    || normalize(item.meaning).includes(query)
    || normalize(item.inApp).includes(query)
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

  const architectureBtn = event.target.closest("#architectureBtn");
  if (architectureBtn) {
    const box = document.getElementById("architectureDiagram");
    if (!box) {
      return;
    }
    const visible = box.style.display !== "none";
    box.style.display = visible ? "none" : "block";
    box.textContent = architectureDiagram;
    architectureBtn.textContent = visible ? "Show Architecture Diagram" : "Hide Architecture Diagram";
  }
});

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

renderDetections(detectionScenarios);
renderLibraries(securityFeatures);
renderOwasp(owaspTop10);

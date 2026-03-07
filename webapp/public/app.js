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

function normalize(value) {
  return String(value || "").toLowerCase();
}

function filterDetections(query) {
  if (!query) {
    return detectionScenarios;
  }

  return detectionScenarios.filter((item) =>
    normalize(item.id).includes(query)
    || normalize(item.title).includes(query)
    || normalize(item.how.join(" ")).includes(query)
    || normalize(item.windowsCommand).includes(query)
    || normalize(item.kaliCommand).includes(query)
  );
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
  const filtered = filterDetections(query);
  renderDetections(filtered);

  if (query.length > 0) {
    setSectionOpen("detectionsBody", filtered.length > 0);
  }
});

renderDetections(detectionScenarios);

const services = [
  {
    id: "svc-100",
    name: "Managed Detection and Response",
    category: "SOC Operations",
    summary: "24/7 triage, enrichment, and coordinated response for high-confidence threats."
  },
  {
    id: "svc-101",
    name: "Attack Surface Monitoring",
    category: "Exposure Management",
    summary: "External asset inventory and drift detection across public-facing systems."
  },
  {
    id: "svc-102",
    name: "Incident Readiness Program",
    category: "IR Engineering",
    summary: "Runbooks, tabletop workflows, and containment playbooks aligned to ATT&CK."
  },
  {
    id: "svc-103",
    name: "Identity Threat Protection",
    category: "IAM Defense",
    summary: "Detect privilege misuse, suspicious sign-ins, and token abuse patterns."
  },
  {
    id: "svc-104",
    name: "Application Security Monitoring",
    category: "AppSec + SOC",
    summary: "Runtime protection for brute force, traversal, honeypot, and abuse telemetry."
  },
  {
    id: "svc-105",
    name: "Threat Hunting Sprints",
    category: "Hunt Team",
    summary: "Hypothesis-driven hunts across endpoint, network, and authentication telemetry."
  }
];

const mitreTechniques = [
  {
    id: "T1110",
    name: "Brute Force",
    tactic: "Credential Access",
    monitor: "Repeated failed logins from same IP/user over short windows.",
    defend: "Rate limit auth endpoints and lock or backoff on threshold."
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    monitor: "Suspicious requests to uncommon paths and exploit-like payloads.",
    defend: "WAF rules, secure defaults, strict input validation, and patch cadence."
  },
  {
    id: "T1083",
    name: "File and Directory Discovery",
    tactic: "Discovery",
    monitor: "Traversal patterns (`../`) and probing of admin backup endpoints.",
    defend: "Canonicalize paths and deny parent traversal outside approved directories."
  },
  {
    id: "T1068",
    name: "Exploitation for Privilege Escalation",
    tactic: "Privilege Escalation",
    monitor: "User role changes, admin-only endpoint access attempts, token misuse.",
    defend: "RBAC checks server-side, audit role changes, least privilege defaults."
  },
  {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Defense Evasion",
    monitor: "Anomalous login timing/source for otherwise valid accounts.",
    defend: "MFA, session hygiene, refresh-token revocation, adaptive risk scoring."
  },
  {
    id: "T1498",
    name: "Network Denial of Service",
    tactic: "Impact",
    monitor: "Burst traffic, repeated health-check abuse, and elevated request rates.",
    defend: "Global request throttling, upstream filtering, and auto-block policies."
  }
];

let incidentCount = 0;

function renderServices(items) {
  const grid = document.getElementById("productGrid");
  grid.innerHTML = "";
  for (const item of items) {
    const card = document.createElement("article");
    card.className = "product";
    card.innerHTML = `
      <p class="small">${item.category}</p>
      <h3>${item.name}</h3>
      <p>${item.summary}</p>
      <button type="button" data-id="${item.id}">Track Signal</button>
    `;
    grid.appendChild(card);
  }
}

function renderMitreCards(items) {
  const grid = document.getElementById("mitreGrid");
  grid.innerHTML = "";
  for (const item of items) {
    const card = document.createElement("article");
    card.className = "mitre-card";
    card.innerHTML = `
      <div class="mitre-id">${item.id}</div>
      <h3>${item.name}</h3>
      <div class="pill">${item.tactic}</div>
      <p class="small"><strong>Monitor:</strong> ${item.monitor}</p>
      <p class="small"><strong>Defend:</strong> ${item.defend}</p>
    `;
    grid.appendChild(card);
  }
}

function updateIncidentLabel() {
  const incidentBtn = document.getElementById("incidentBtn");
  incidentBtn.textContent = `Incidents Tracked (${incidentCount})`;
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-id]");
  if (!button) {
    return;
  }
  incidentCount += 1;
  updateIncidentLabel();
});

document.getElementById("searchForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const query = document.getElementById("searchInput").value.trim().toLowerCase();

  const serviceMatches = query
    ? services.filter((item) =>
      item.name.toLowerCase().includes(query)
      || item.category.toLowerCase().includes(query)
      || item.summary.toLowerCase().includes(query))
    : services;

  const mitreMatches = query
    ? mitreTechniques.filter((item) =>
      item.id.toLowerCase().includes(query)
      || item.name.toLowerCase().includes(query)
      || item.tactic.toLowerCase().includes(query))
    : mitreTechniques;

  renderServices(serviceMatches);
  renderMitreCards(mitreMatches);
  document.getElementById("searchMsg").textContent = `${serviceMatches.length} service result(s), ${mitreMatches.length} ATT&CK result(s) for "${query || "all"}".`;
});

document.getElementById("newsletterForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const email = document.getElementById("newsletterEmail").value.trim();
  document.getElementById("newsletterMsg").textContent = `Threat brief subscription created for ${email}.`;
  event.target.reset();
});

document.getElementById("supportForm").addEventListener("submit", (event) => {
  event.preventDefault();
  document.getElementById("supportMsg").textContent = "Ticket submitted. SOC queue updated for analyst follow-up.";
  event.target.reset();
});

renderServices(services);
renderMitreCards(mitreTechniques);
updateIncidentLabel();

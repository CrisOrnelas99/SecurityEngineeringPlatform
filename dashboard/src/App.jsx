import React, { useEffect, useMemo, useState } from "react";

const apiBase = import.meta.env.VITE_SOC_API_URL || "http://localhost:8000";
const webApiBase = import.meta.env.VITE_WEB_API_URL || "http://localhost:3000";

async function getJson(path) {
  const response = await fetch(`${apiBase}${path}`);
  if (!response.ok) {
    throw new Error(`Request failed for ${path}`);
  }
  return response.json();
}

export default function App() {
  const [page, setPage] = useState("dashboard");
  const [authState, setAuthState] = useState({
    accessToken: "",
    refreshToken: "",
    user: null
  });
  const [authForm, setAuthForm] = useState({
    username: "",
    password: "",
    role: "analyst"
  });
  const [authStatus, setAuthStatus] = useState("");
  const [sessionStatus, setSessionStatus] = useState("");
  const [alertStatus, setAlertStatus] = useState("");
  const [blockStatus, setBlockStatus] = useState("");
  const [blockIpInput, setBlockIpInput] = useState("");
  const [expandedAlerts, setExpandedAlerts] = useState({});
  const [expandedAlertGroups, setExpandedAlertGroups] = useState({});
  const [expandedTimeline, setExpandedTimeline] = useState({});
  const [showBlocklistTimelineEvents, setShowBlocklistTimelineEvents] = useState(false);

  const [summary, setSummary] = useState({
    activeAlerts: 0,
    blockedIps: 0,
    lockedUsers: 0,
    honeypotTriggers: 0,
    topAttackPatterns: []
  });
  const [alerts, setAlerts] = useState([]);
  const [risk, setRisk] = useState({ riskByIp: [], riskByUser: [] });
  const [timeline, setTimeline] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);

  useEffect(() => {
    let stop = false;

    async function refresh() {
      try {
        const [s, a, r, t, b] = await Promise.all([
          getJson("/summary"),
          getJson("/alerts"),
          getJson("/risk"),
          getJson("/timeline"),
          getJson("/blocked-ips")
        ]);
        if (stop) {
          return;
        }
        setSummary(s);
        setAlerts(a.slice(-50).reverse());
        setRisk(r);
        setTimeline(t.slice(-60).reverse());
        setBlockedIps(b);
      } catch {
        // Keep prior snapshot if refresh fails.
      }
    }

    refresh();
    const id = setInterval(refresh, 4000);
    return () => {
      stop = true;
      clearInterval(id);
    };
  }, []);

  const topIp = useMemo(() => risk.riskByIp[0], [risk]);
  const visibleAlerts = useMemo(
    () => alerts.filter((alert) => alert.type !== "BLACKLISTED_IP_ACCESS"),
    [alerts]
  );
  const attackPatterns = useMemo(() => {
    const merged = new Map();
    for (const pattern of summary.topAttackPatterns || []) {
      const label = normalizeEventName(pattern.pattern);
      if (label === "BLOCKED_IP_REQUEST") {
        continue;
      }
      merged.set(label, (merged.get(label) || 0) + Number(pattern.count || 0));
    }
    return [...merged.entries()]
      .map(([pattern, count]) => ({ pattern, count }))
      .sort((a, b) => b.count - a.count || a.pattern.localeCompare(b.pattern));
  }, [summary.topAttackPatterns]);
  const enforcementEvents = useMemo(() => {
    const counts = new Map();

    for (const entry of timeline) {
      const event = normalizeEventName(String(entry.event || ""));
      if (event === "BLACKLISTED_IP_ACCESS" || event === "MANUAL_BLOCK_IP" || event === "MANUAL_UNBLOCK_IP") {
        counts.set(event, (counts.get(event) || 0) + 1);
      }
      for (const action of entry.actionsTaken || []) {
        if (action === "BLACKLISTED_IP_ACCESS" || action === "LOCKED_USER") {
          const actionLabel = normalizeActionName(action);
          counts.set(actionLabel, (counts.get(actionLabel) || 0) + 1);
        }
      }
    }

    return [...counts.entries()]
      .map(([event, count]) => ({ event, count }))
      .sort((a, b) => b.count - a.count || a.event.localeCompare(b.event));
  }, [timeline]);
  const groupedVisibleAlerts = useMemo(() => {
    const groups = [];
    let current = null;
    for (const alert of visibleAlerts) {
      const eventName = normalizeEventName(alert.type);
      if (!current || current.eventName !== eventName) {
        if (current) {
          groups.push(current);
        }
        current = {
          groupId: `grp-${alert.id}`,
          eventName,
          alerts: [alert],
        };
        continue;
      }
      current.alerts.push(alert);
    }
    if (current) {
      groups.push(current);
    }
    return groups;
  }, [visibleAlerts]);
  const visibleTimeline = useMemo(() => {
    if (showBlocklistTimelineEvents) {
      return timeline;
    }
    return timeline.filter((entry) => {
      const eventName = normalizeEventName(String(entry.event || ""));
      return eventName !== "BLOCKED_IP_REQUEST";
    });
  }, [timeline, showBlocklistTimelineEvents]);

  function formatEventTime(isoTs) {
    const dt = new Date(isoTs);
    if (Number.isNaN(dt.getTime())) {
      return isoTs;
    }
    return dt.toLocaleString();
  }

  function getIpDisplayInfo(rawIp) {
    const ip = String(rawIp || "");
    if (ip.startsWith("::ffff:")) {
      return { version: "IPv4", value: ip.replace("::ffff:", "") };
    }
    if (ip.includes(":")) {
      return { version: "IPv6", value: ip };
    }
    return { version: "IPv4", value: ip };
  }

  function normalizeEventName(name) {
    if (name === "BRUTE_FORCE") {
      return "FAILED_LOGIN_BURST";
    }
    if (name === "BLACKLISTED_IP_ACCESS") {
      return "BLOCKED_IP_REQUEST";
    }
    return name;
  }

  function normalizeActionName(name) {
    if (name === "BLACKLISTED_IP_ACCESS") {
      return "AUTO_BLOCK_IP_ACCESS";
    }
    return name;
  }

  function formatDetailValue(key, value) {
    if (value === null || value === undefined) {
      return "n/a";
    }
    if (typeof value === "string") {
      const keyLc = String(key || "").toLowerCase();
      const maybeIp = keyLc.includes("ip") || value.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
      if (maybeIp) {
        const info = getIpDisplayInfo(value);
        if (info.value) {
          return `${info.version}: ${info.value}`;
        }
      }
      return value;
    }
    return String(value);
  }

  function toggleAlertDetails(alertId) {
    setExpandedAlerts((prev) => ({ ...prev, [alertId]: !prev[alertId] }));
  }

  function toggleTimelineDetails(timelineId) {
    setExpandedTimeline((prev) => ({ ...prev, [timelineId]: !prev[timelineId] }));
  }

  function toggleAlertGroup(groupId) {
    setExpandedAlertGroups((prev) => ({ ...prev, [groupId]: !prev[groupId] }));
  }

  function renderAlertDetails(alert) {
    const info = getIpDisplayInfo(alert.ip);
    const detailEntries = Object.entries(alert.details || {});

    return (
      <div className="alert-details">
        <div className="small">ID: {alert.id}</div>
        <div className="small">Time: {formatEventTime(alert.timestamp)}</div>
        <div className="small">Source: {info.version} {info.value}</div>
        <div className="small">User: {alert.userId || "anonymous"}</div>
        <div className="small">Request: {(alert.method || "UNKNOWN").toUpperCase()} {alert.endpoint || "n/a"}</div>
        <div className="small">Error Type: {alert.errorType || "n/a"}</div>
        {detailEntries.length ? (
          <div className="small">Detector Details: {detailEntries.map(([k, v]) => `${k}=${formatDetailValue(k, v)}`).join(" | ")}</div>
        ) : (
          <div className="small">Detector Details: none</div>
        )}
      </div>
    );
  }

  function renderTimelineDetails(entry) {
    const info = getIpDisplayInfo(entry.ip);
    const detailEntries = Object.entries(entry.details || {});
    const actions = (entry.actionsTaken || []).length ? entry.actionsTaken.join(", ") : "NONE";
    return (
      <div className="alert-details">
        <div className="small">Event: {normalizeEventName(entry.event)}</div>
        <div className="small">Time: {formatEventTime(entry.timestamp)}</div>
        <div className="small">Source: {info.version} {info.value}</div>
        <div className="small">User: {entry.userId || "anonymous"}</div>
        <div className="small">Score Impact: +{entry.scoreImpact}</div>
        <div className="small">Cumulative Risk: {entry.cumulativeRisk ?? "n/a"}</div>
        <div className="small">
          Action Taken: {(entry.actionsTaken || []).length ? entry.actionsTaken.map(normalizeActionName).join(", ") : "NONE"}
        </div>
        {detailEntries.length ? (
          <div className="small">Detector Details: {detailEntries.map(([k, v]) => `${k}=${formatDetailValue(k, v)}`).join(" | ")}</div>
        ) : (
          <div className="small">Detector Details: none</div>
        )}
      </div>
    );
  }

  async function getCsrfToken() {
    const response = await fetch(`${webApiBase}/api/csrf-token`, {
      method: "GET",
      credentials: "include"
    });
    if (!response.ok) {
      throw new Error("Could not fetch CSRF token");
    }
    const payload = await response.json();
    return payload.csrfToken;
  }

  async function postWithCsrf(path, body, accessToken = "") {
    const csrfToken = await getCsrfToken();
    const response = await fetch(`${webApiBase}${path}`, {
      method: "POST",
      credentials: "include",
      headers: {
        "content-type": "application/json",
        "x-csrf-token": csrfToken,
        ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {})
      },
      body: JSON.stringify(body)
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || `Request failed for ${path}`);
    }
    return payload;
  }

  async function registerUser(event) {
    event.preventDefault();
    setAuthStatus("Registering...");
    try {
      await postWithCsrf("/api/auth/register", {
        username: authForm.username,
        password: authForm.password,
        role: authForm.role
      });
      setAuthStatus("Registration successful. You can now log in.");
    } catch (error) {
      setAuthStatus(`Register failed: ${error.message}`);
    }
  }

  async function loginUser(event) {
    event.preventDefault();
    setAuthStatus("Logging in...");
    try {
      const login = await postWithCsrf("/api/auth/login", {
        username: authForm.username,
        password: authForm.password
      });
      setAuthState({
        accessToken: login.accessToken,
        refreshToken: login.refreshToken,
        user: login.user
      });
      setAuthStatus(`Logged in as ${login.user.username} (${login.user.role}).`);
      setPage("session");
    } catch (error) {
      setAuthStatus(`Login failed: ${error.message}`);
    }
  }

  async function runPaymentTest() {
    setSessionStatus("Calling payment simulation...");
    try {
      const payload = await postWithCsrf(
        "/api/payment/simulate",
        { amount: 25, currency: "USD", recipient: "demo-vendor" },
        authState.accessToken
      );
      setSessionStatus(`Payment simulation ok: ${payload.txId}`);
    } catch (error) {
      setSessionStatus(`Payment simulation failed: ${error.message}`);
    }
  }

  async function runAdminTest() {
    setSessionStatus("Calling admin report endpoint...");
    try {
      const response = await fetch(`${webApiBase}/api/admin/secure-report`, {
        method: "GET",
        credentials: "include",
        headers: {
          authorization: `Bearer ${authState.accessToken}`
        }
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.error || "Request denied");
      }
      setSessionStatus(`Admin report result: ${payload.report}`);
    } catch (error) {
      setSessionStatus(`Admin report failed: ${error.message}`);
    }
  }

  async function clearAllAlerts() {
    setAlertStatus("Clearing alerts...");
    try {
      const response = await fetch(`${apiBase}/alerts`, { method: "DELETE" });
      if (!response.ok) {
        throw new Error("Unable to clear alerts");
      }
      setAlerts([]);
      setTimeline([]);
      setRisk({ riskByIp: [], riskByUser: [] });
      setSummary((prev) => ({
        ...prev,
        activeAlerts: 0,
        honeypotTriggers: 0,
        topAttackPatterns: []
      }));
      setAlertStatus("All alerts cleared.");
    } catch (error) {
      setAlertStatus(`Clear failed: ${error.message}`);
    }
  }

  async function deleteAlertById(alertId) {
    try {
      const response = await fetch(`${apiBase}/alerts/${alertId}`, { method: "DELETE" });
      if (!response.ok) {
        throw new Error("Unable to delete alert");
      }
      setAlerts((prev) => prev.filter((a) => a.id !== alertId));
      setAlertStatus(`Deleted alert ${alertId}.`);
    } catch (error) {
      setAlertStatus(`Delete failed: ${error.message}`);
    }
  }

  async function addBlockedIp() {
    const ip = blockIpInput.trim();
    if (!ip) {
      setBlockStatus("Enter an IP first.");
      return;
    }
    setBlockStatus("Blocking IP...");
    try {
      const response = await fetch(`${apiBase}/blocked-ips`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ip, source: "dashboard" })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || "Unable to block IP");
      }
      setBlockedIps((prev) => (prev.includes(ip) ? prev : [...prev, ip].sort()));
      setBlockIpInput("");
      setBlockStatus(payload.added ? `Blocked ${ip}.` : `${ip} is already blocked.`);
    } catch (error) {
      setBlockStatus(`Block failed: ${error.message}`);
    }
  }

  async function unblockIp(ip) {
    setBlockStatus(`Unblocking ${ip}...`);
    try {
      const response = await fetch(`${apiBase}/blocked-ips/${encodeURIComponent(ip)}`, {
        method: "DELETE"
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || "Unable to unblock IP");
      }
      setBlockedIps((prev) => prev.filter((item) => item !== ip));
      setBlockStatus(`Unblocked ${ip}.`);
    } catch (error) {
      setBlockStatus(`Unblock failed: ${error.message}`);
    }
  }

  function renderAuthForms() {
    return (
      <section className="auth-grid">
        <div className="card">
          <h2>Login</h2>
          <form onSubmit={loginUser} className="form">
            <label>
              Username
              <input
                value={authForm.username}
                onChange={(e) => setAuthForm((v) => ({ ...v, username: e.target.value }))}
                placeholder="analyst1"
                required
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={authForm.password}
                onChange={(e) => setAuthForm((v) => ({ ...v, password: e.target.value }))}
                placeholder="minimum 12 chars"
                required
              />
            </label>
            <button type="submit">Login</button>
          </form>
        </div>

        <div className="card">
          <h2>Register</h2>
          <form onSubmit={registerUser} className="form">
            <label>
              Username
              <input
                value={authForm.username}
                onChange={(e) => setAuthForm((v) => ({ ...v, username: e.target.value }))}
                placeholder="newuser1"
                required
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={authForm.password}
                onChange={(e) => setAuthForm((v) => ({ ...v, password: e.target.value }))}
                placeholder="minimum 12 chars"
                required
              />
            </label>
            <label>
              Role
              <select value={authForm.role} onChange={(e) => setAuthForm((v) => ({ ...v, role: e.target.value }))}>
                <option value="analyst">analyst</option>
                <option value="admin">admin</option>
              </select>
            </label>
            <button type="submit">Register</button>
          </form>
        </div>
      </section>
    );
  }

  function renderSessionPanel() {
    return (
      <section className="card">
        <h2>Session</h2>
        <p className="small">
          Current user: {authState.user ? `${authState.user.username} (${authState.user.role})` : "Not logged in"}
        </p>
        <div className="actions">
          <button type="button" onClick={runPaymentTest} disabled={!authState.accessToken}>
            Run Payment Simulation
          </button>
          <button type="button" onClick={runAdminTest} disabled={!authState.accessToken}>
            Try Admin Report
          </button>
          <button
            type="button"
            onClick={() => {
              setAuthState({ accessToken: "", refreshToken: "", user: null });
              setSessionStatus("Logged out in dashboard state.");
            }}
          >
            Clear Session
          </button>
        </div>
        <p className="small">{sessionStatus}</p>
      </section>
    );
  }

  return (
    <div className="container">
      <div className="title-wrap">
        <h1>SOC Security Dashboard</h1>
      </div>
      <div className="header-row">
        <p className="small">Live visibility into alerts, automated response actions, and risk posture.</p>
        <div className="tabs">
          <button type="button" onClick={() => setPage("dashboard")} className={page === "dashboard" ? "active-tab" : ""}>
            Dashboard
          </button>
          <button type="button" onClick={() => setPage("auth")} className={page === "auth" ? "active-tab" : ""}>
            Login / Register
          </button>
          <button type="button" onClick={() => setPage("session")} className={page === "session" ? "active-tab" : ""}>
            Session Tools
          </button>
        </div>
      </div>
      {authStatus ? <p className="small">{authStatus}</p> : null}

      {page === "auth" ? renderAuthForms() : null}
      {page === "session" ? renderSessionPanel() : null}
      {page !== "dashboard" ? null : (
        <>
      <section className="grid kpis">
        <div className="card"><h2>{summary.activeAlerts}</h2><div className="small">Active Alerts</div></div>
        <div className="card"><h2>{summary.blockedIps}</h2><div className="small">Blocked IPs</div></div>
        <div className="card"><h2>{summary.lockedUsers}</h2><div className="small">Locked Users</div></div>
        <div className="card"><h2>{summary.honeypotTriggers}</h2><div className="small">Honeypot Triggers</div></div>
      </section>

      <section className="grid cards" style={{ marginTop: "1rem" }}>
        <div className="card">
          <div className="card-title-row">
            <h2>Active Alerts</h2>
            <div className="item-actions">
              <button type="button" className="danger-btn" onClick={clearAllAlerts}>Clear Alerts</button>
            </div>
          </div>
          {alertStatus ? <p className="small">{alertStatus}</p> : null}
          <div className="list">
            {groupedVisibleAlerts.map((group) => (
              <div className="item" key={group.groupId}>
                <div className="item-row">
                  <div>
                    <span className={`badge ${group.alerts[0].riskLevel}`}>{group.alerts[0].riskLevel}</span> {group.eventName}
                  </div>
                  <div className="item-actions">
                    <span className="small">{group.alerts.length} occurrence{group.alerts.length === 1 ? "" : "s"}</span>
                    <button
                      type="button"
                      className="ghost-btn"
                      onClick={() => toggleAlertGroup(group.groupId)}
                    >
                      {expandedAlertGroups[group.groupId] ? "Hide Group" : "Show Group"}
                    </button>
                  </div>
                </div>
                <div className="small">
                  Latest: {formatEventTime(group.alerts[0].timestamp)} | {getIpDisplayInfo(group.alerts[0].ip).version}: {getIpDisplayInfo(group.alerts[0].ip).value}
                </div>
                {expandedAlertGroups[group.groupId] ? (
                  <div className="list" style={{ marginTop: "0.5rem" }}>
                    {group.alerts.map((alert) => (
                      <div className="item" key={alert.id}>
                        <div className="item-row">
                          <div className="small">{formatEventTime(alert.timestamp)}</div>
                          <div className="item-actions">
                            <button
                              type="button"
                              className="ghost-btn"
                              onClick={() => toggleAlertDetails(alert.id)}
                            >
                              {expandedAlerts[alert.id] ? "Hide" : "Details"}
                            </button>
                            <button
                              type="button"
                              className="alert-delete-btn"
                              title="Delete alert"
                              onClick={() => deleteAlertById(alert.id)}
                            >
                              X
                            </button>
                          </div>
                        </div>
                        <div className="small">
                          {getIpDisplayInfo(alert.ip).version}: {getIpDisplayInfo(alert.ip).value} | user: {alert.userId}
                        </div>
                        <div className="small">
                          Action Taken: {(alert.actionsTaken || []).length ? alert.actionsTaken.map(normalizeActionName).join(", ") : "NONE"}
                        </div>
                        {expandedAlerts[alert.id] ? renderAlertDetails(alert) : null}
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h2>Risk Scores By IP</h2>
          <div className="list">
            {risk.riskByIp.map((entry) => (
              <div className="item" key={entry.ip}>
                <div>{getIpDisplayInfo(entry.ip).version}: {getIpDisplayInfo(entry.ip).value}</div>
                <div className="small">score: {entry.score} <span className={`badge ${entry.riskLevel}`}>{entry.riskLevel}</span></div>
              </div>
            ))}
          </div>
          {topIp && (
            <p className="small">
              Highest risk source: {getIpDisplayInfo(topIp.ip).version} {getIpDisplayInfo(topIp.ip).value} ({topIp.score})
            </p>
          )}
        </div>

        <div className="card">
          <div className="card-title-row">
            <h2>Incident Timeline</h2>
            <button
              type="button"
              className="ghost-btn"
              onClick={() => setShowBlocklistTimelineEvents((v) => !v)}
            >
              {showBlocklistTimelineEvents ? "Hide Blocklist Events" : "Show Blocklist Events"}
            </button>
          </div>
          <div className="list">
            {visibleTimeline.map((entry, idx) => (
              <div className="item" key={`${entry.timestamp}-${idx}`}>
                <div className="item-row">
                  <div>{normalizeEventName(entry.event)}</div>
                  <button
                    type="button"
                    className="ghost-btn"
                    onClick={() => toggleTimelineDetails(`${entry.timestamp}-${idx}`)}
                  >
                    {expandedTimeline[`${entry.timestamp}-${idx}`] ? "Hide" : "Details"}
                  </button>
                </div>
                <div className="small">
                  {formatEventTime(entry.timestamp)} | {getIpDisplayInfo(entry.ip).version}: {getIpDisplayInfo(entry.ip).value} | +{entry.scoreImpact}
                </div>
                {expandedTimeline[`${entry.timestamp}-${idx}`] ? renderTimelineDetails(entry) : null}
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h2>Blocked IPs</h2>
          <div className="actions">
            <input
              className="inline-input"
              value={blockIpInput}
              onChange={(e) => setBlockIpInput(e.target.value)}
              placeholder="127.0.0.1 or ::1"
            />
            <button type="button" onClick={addBlockedIp}>Block IP</button>
          </div>
          {blockStatus ? <p className="small">{blockStatus}</p> : null}
          <div className="list">
            {blockedIps.map((ip) => (
              <div className="item item-row" key={ip}>
                <span>{getIpDisplayInfo(ip).version}: {getIpDisplayInfo(ip).value}</span>
                <button type="button" className="alert-delete-btn" onClick={() => unblockIp(ip)}>Unblock</button>
              </div>
            ))}
          </div>
          <h2 style={{ marginTop: "1rem" }}>Attack Patterns</h2>
          <div className="list">
            {attackPatterns.map((pattern) => (
              <div className="item" key={pattern.pattern}>{pattern.pattern} ({pattern.count})</div>
            ))}
          </div>
          <h2 style={{ marginTop: "1rem" }}>Enforcement Events</h2>
          <div className="list">
            {enforcementEvents.map((event) => (
              <div className="item" key={event.event}>{event.event} ({event.count})</div>
            ))}
          </div>
        </div>
      </section>
        </>
      )}
    </div>
  );
}

import React, { useEffect, useMemo, useState } from "react";

const apiBase = import.meta.env.VITE_TDR_API_URL || "http://localhost:8000";
const webApiBase = import.meta.env.VITE_WEB_API_URL || "http://localhost:3000";

export default function App() {
  const [page, setPage] = useState("auth");
  const [authState, setAuthState] = useState({
    accessToken: "",
    refreshToken: "",
    user: null
  });
  const [authForm, setAuthForm] = useState({
    username: "",
    password: ""
  });
  const [createUserForm, setCreateUserForm] = useState({ username: "", role: "analyst" });
  const [authStatus, setAuthStatus] = useState("");
  const [settingsStatus, setSettingsStatus] = useState("");
  const [accountProfile, setAccountProfile] = useState(null);
  const [passwordForm, setPasswordForm] = useState({ currentPassword: "", newPassword: "" });
  const [alertStatus, setAlertStatus] = useState("");
  const [blockStatus, setBlockStatus] = useState("");
  const [blockIpInput, setBlockIpInput] = useState("");
  const [expandedAlerts, setExpandedAlerts] = useState({});
  const [expandedAlertGroups, setExpandedAlertGroups] = useState({});
  const [expandedTimeline, setExpandedTimeline] = useState({});
  const [settingsPanels, setSettingsPanels] = useState({
    account: true,
    password: true,
    adminDefaults: true
  });
  const [adminDefaults, setAdminDefaults] = useState({ newUserInitialPassword: "" });
  const [defaultsForm, setDefaultsForm] = useState({ newUserInitialPassword: "" });
  const [showBlocklistTimelineEvents, setShowBlocklistTimelineEvents] = useState(false);
  const [usersStatus, setUsersStatus] = useState("");
  const [usersData, setUsersData] = useState([]);
  const [usersLoading, setUsersLoading] = useState(false);

  const [summary, setSummary] = useState({
    activeAlerts: 0,
    applicationAlerts: 0,
    engineSystemAlerts: 0,
    blockedIps: 0,
    lockedUsers: 0,
    honeypotTriggers: 0,
    topAttackPatterns: []
  });
  const [alerts, setAlerts] = useState([]);
  const [systemAlerts, setSystemAlerts] = useState([]);
  const [risk, setRisk] = useState({ riskByIp: [], riskByUser: [] });
  const [timeline, setTimeline] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);

  useEffect(() => {
    if (!authState.accessToken) {
      setSummary({
        activeAlerts: 0,
        applicationAlerts: 0,
        engineSystemAlerts: 0,
        blockedIps: 0,
        lockedUsers: 0,
        honeypotTriggers: 0,
        topAttackPatterns: []
      });
      setAlerts([]);
      setSystemAlerts([]);
      setRisk({ riskByIp: [], riskByUser: [] });
      setTimeline([]);
      setBlockedIps([]);
      setAdminDefaults({ newUserInitialPassword: "" });
      setDefaultsForm({ newUserInitialPassword: "" });
      if (page !== "auth") {
        setPage("auth");
      }
      return undefined;
    }

    let stop = false;
    const headers = { authorization: `Bearer ${authState.accessToken}` };

    async function refresh() {
      try {
        const [s, a, r, t, b] = await Promise.all([
          fetch(`${apiBase}/summary`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("summary failed")))),
          fetch(`${apiBase}/alerts/categorized`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("alerts failed")))),
          fetch(`${apiBase}/risk`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("risk failed")))),
          fetch(`${apiBase}/timeline`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("timeline failed")))),
          fetch(`${apiBase}/blocked-ips`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("blocked-ips failed"))))
        ]);
        if (stop) {
          return;
        }
        setSummary(s);
        setAlerts((a.applicationAlerts || []).slice(-50).reverse());
        setSystemAlerts((a.engineSystemAlerts || []).slice(-20).reverse());
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
  }, [authState.accessToken]);

  useEffect(() => {
    if (!authState.accessToken) {
      setAccountProfile(null);
      return;
    }

    fetch(`${webApiBase}/api/auth/me`, {
      method: "GET",
      credentials: "include",
      headers: { authorization: `Bearer ${authState.accessToken}` }
    })
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error("profile failed"))))
      .then((profile) => setAccountProfile(profile))
      .catch(() => setAccountProfile(null));
  }, [authState.accessToken]);

  useEffect(() => {
    if (!authState.accessToken || authState.user?.role !== "admin") {
      setAdminDefaults({ newUserInitialPassword: "" });
      setDefaultsForm({ newUserInitialPassword: "" });
      return;
    }

    fetch(`${webApiBase}/api/auth/settings`, {
      method: "GET",
      credentials: "include",
      headers: { authorization: `Bearer ${authState.accessToken}` }
    })
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error("settings failed"))))
      .then((payload) => {
        const value = String(payload.newUserInitialPassword || "");
        setAdminDefaults({ newUserInitialPassword: value });
        setDefaultsForm({ newUserInitialPassword: value });
      })
      .catch(() => {
        setAdminDefaults({ newUserInitialPassword: "" });
        setDefaultsForm({ newUserInitialPassword: "" });
      });
  }, [authState.accessToken, authState.user?.role]);

  useEffect(() => {
    if (!authState.accessToken || authState.user?.role !== "admin") {
      setUsersData([]);
      setUsersStatus("");
      setUsersLoading(false);
      return;
    }

    fetchUsers();
  }, [authState.accessToken, authState.user?.role]);

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
      setPasswordForm({ currentPassword: "", newPassword: "" });
      setAuthStatus(`Logged in as ${login.user.username} (${login.user.role}).`);
      setPage("dashboard");
    } catch (error) {
      setAuthStatus(`Login failed: ${error.message}`);
    }
  }

  async function createUserByAdmin(event) {
    event.preventDefault();
    if (authState.user?.role !== "admin") {
      setSettingsStatus("Only admins can create users.");
      return;
    }
    setSettingsStatus("Creating user...");
    try {
      const payload = await postWithCsrf(
        "/api/auth/register",
        { username: createUserForm.username, role: createUserForm.role },
        authState.accessToken
      );
      setCreateUserForm({ username: "", role: "analyst" });
      setSettingsStatus(
        `User ${payload.username} created (${payload.role}). Temporary password: ${payload.temporaryPassword}`
      );
      setUsersStatus(
        `User ${payload.username} created (${payload.role}). Temporary password: ${payload.temporaryPassword}`
      );
      await fetchUsers();
    } catch (error) {
      setSettingsStatus(`Create user failed: ${error.message}`);
      setUsersStatus(`Create user failed: ${error.message}`);
    }
  }

  async function fetchUsers() {
    if (!authState.accessToken || authState.user?.role !== "admin") {
      return;
    }
    setUsersLoading(true);
    try {
      const response = await fetch(`${webApiBase}/api/auth/users`, {
        method: "GET",
        credentials: "include",
        headers: { authorization: `Bearer ${authState.accessToken}` }
      });
      const payload = await response.json().catch(() => []);
      if (!response.ok) {
        throw new Error(payload.error || "Unable to load users");
      }
      setUsersData(Array.isArray(payload) ? payload : []);
      setUsersStatus("");
    } catch (error) {
      setUsersStatus(`Load users failed: ${error.message}`);
    } finally {
      setUsersLoading(false);
    }
  }

  async function resetUserPassword(userId, username) {
    if (!authState.accessToken || authState.user?.role !== "admin") {
      return;
    }
    setUsersStatus(`Resetting password for ${username}...`);
    try {
      const payload = await postWithCsrf(
        `/api/auth/users/${encodeURIComponent(userId)}/reset-password`,
        {},
        authState.accessToken
      );
      setUsersStatus(`Password reset for ${username}. Temporary password: ${payload.temporaryPassword}`);
      await fetchUsers();
    } catch (error) {
      setUsersStatus(`Reset failed for ${username}: ${error.message}`);
    }
  }

  async function deleteUser(userId, username) {
    if (!authState.accessToken || authState.user?.role !== "admin") {
      return;
    }
    setUsersStatus(`Deleting ${username}...`);
    try {
      const csrfToken = await getCsrfToken();
      const response = await fetch(`${webApiBase}/api/auth/users/${encodeURIComponent(userId)}`, {
        method: "DELETE",
        credentials: "include",
        headers: {
          "x-csrf-token": csrfToken,
          authorization: `Bearer ${authState.accessToken}`
        }
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.error || "Delete failed");
      }
      setUsersStatus(`Deleted user ${username}.`);
      await fetchUsers();
    } catch (error) {
      setUsersStatus(`Delete failed for ${username}: ${error.message}`);
    }
  }

  async function runAdminTest() {
    setSettingsStatus("Calling admin report endpoint...");
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
      setSettingsStatus(`Admin report result: ${payload.report}`);
    } catch (error) {
      setSettingsStatus(`Admin report failed: ${error.message}`);
    }
  }

  async function logoutUser() {
    if (!authState.accessToken) {
      return;
    }
    setSettingsStatus("Logging out...");
    try {
      await postWithCsrf("/api/auth/logout", { refreshToken: authState.refreshToken }, authState.accessToken);
    } catch {
      // Even if logout call fails, clear local session to avoid stale access.
    }
    setAuthState({ accessToken: "", refreshToken: "", user: null });
    setAccountProfile(null);
    setSettingsStatus("Logged out.");
    setPage("auth");
  }

  async function changePassword(event) {
    event.preventDefault();
    if (!authState.accessToken) {
      setSettingsStatus("Login required.");
      return;
    }

    setSettingsStatus("Updating password...");
    try {
      const payload = await postWithCsrf(
        "/api/auth/change-password",
        {
          currentPassword: passwordForm.currentPassword,
          newPassword: passwordForm.newPassword
        },
        authState.accessToken
      );
      setPasswordForm({ currentPassword: "", newPassword: "" });
      setAuthState({ accessToken: "", refreshToken: "", user: null });
      setAccountProfile(null);
      setSettingsStatus(payload.message || "Password updated. Please log in again.");
      setPage("auth");
    } catch (error) {
      setSettingsStatus(`Password change failed: ${error.message}`);
    }
  }

  async function clearAllAlerts() {
    setAlertStatus("Clearing alerts...");
    try {
      const response = await fetch(`${apiBase}/alerts`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${authState.accessToken}` }
      });
      if (!response.ok) {
        throw new Error("Unable to clear alerts");
      }
      setAlerts([]);
      setTimeline([]);
      setRisk({ riskByIp: [], riskByUser: [] });
      setSummary((prev) => ({
        ...prev,
        activeAlerts: 0,
        applicationAlerts: 0,
        engineSystemAlerts: 0,
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
      const response = await fetch(`${apiBase}/alerts/${alertId}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${authState.accessToken}` }
      });
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
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${authState.accessToken}`
        },
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
        method: "DELETE",
        headers: { authorization: `Bearer ${authState.accessToken}` }
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
      </section>
    );
  }

  function toggleSettingsPanel(name) {
    setSettingsPanels((prev) => ({ ...prev, [name]: !prev[name] }));
  }

  async function updateDefaultInitialPassword(event) {
    event.preventDefault();
    if (authState.user?.role !== "admin") {
      setSettingsStatus("Only admins can update defaults.");
      return;
    }
    setSettingsStatus("Updating default password...");
    try {
      const payload = await postWithCsrf(
        "/api/auth/settings/new-user-password",
        { newUserInitialPassword: defaultsForm.newUserInitialPassword },
        authState.accessToken
      );
      setAdminDefaults({ newUserInitialPassword: defaultsForm.newUserInitialPassword });
      setSettingsStatus(payload.message || "Default password updated.");
    } catch (error) {
      setSettingsStatus(`Update failed: ${error.message}`);
    }
  }

  function renderSettingsPanel() {
    const isAdmin = authState.user?.role === "admin";
    return (
      <section className="card">
        <h2>Settings</h2>
        <div className="item" style={{ marginTop: "0.75rem" }}>
          <div className="item-row">
            <strong>Account Overview</strong>
            <button type="button" className="ghost-btn" onClick={() => toggleSettingsPanel("account")}>
              {settingsPanels.account ? "Minimize" : "Maximize"}
            </button>
          </div>
          {settingsPanels.account ? (
            <>
              <p className="small">
                Current user: {authState.user ? `${authState.user.username} (${authState.user.role})` : "Not logged in"}
              </p>
              {accountProfile ? (
                <p className="small">
                  Account ID: {accountProfile.id} | Created: {formatEventTime(accountProfile.createdAt)}
                </p>
              ) : null}
              <div className="actions">
                <button type="button" onClick={logoutUser} disabled={!authState.accessToken}>
                  Logout
                </button>
                {isAdmin ? (
                  <button type="button" onClick={runAdminTest} disabled={!authState.accessToken}>
                    Run Admin Check
                  </button>
                ) : null}
              </div>
            </>
          ) : null}
        </div>
        <div className="item" style={{ marginTop: "0.75rem" }}>
          <div className="item-row">
            <strong>Password Management</strong>
            <button type="button" className="ghost-btn" onClick={() => toggleSettingsPanel("password")}>
              {settingsPanels.password ? "Minimize" : "Maximize"}
            </button>
          </div>
          {settingsPanels.password ? (
            <form onSubmit={changePassword} className="form" style={{ marginTop: "0.5rem" }}>
              <label>
                Current Password
                <input
                  type="password"
                  value={passwordForm.currentPassword}
                  onChange={(e) => setPasswordForm((v) => ({ ...v, currentPassword: e.target.value }))}
                  required
                />
              </label>
              <label>
                New Password
                <input
                  type="password"
                  value={passwordForm.newPassword}
                  onChange={(e) => setPasswordForm((v) => ({ ...v, newPassword: e.target.value }))}
                  minLength={12}
                  required
                />
              </label>
              <button type="submit" disabled={!authState.accessToken}>Update Password</button>
            </form>
          ) : null}
        </div>
        {isAdmin ? (
          <div className="item" style={{ marginTop: "0.75rem" }}>
            <div className="item-row">
              <strong>Admin Security Defaults</strong>
              <button type="button" className="ghost-btn" onClick={() => toggleSettingsPanel("adminDefaults")}>
                {settingsPanels.adminDefaults ? "Minimize" : "Maximize"}
              </button>
            </div>
            {settingsPanels.adminDefaults ? (
              <form onSubmit={updateDefaultInitialPassword} className="form" style={{ marginTop: "0.5rem" }}>
                <p className="small">Current temporary password for newly created users: <code>{adminDefaults.newUserInitialPassword || "n/a"}</code></p>
                <label>
                  New Temporary Password
                  <input
                    type="password"
                    value={defaultsForm.newUserInitialPassword}
                    onChange={(e) => setDefaultsForm({ newUserInitialPassword: e.target.value })}
                    minLength={12}
                    required
                  />
                </label>
                <button type="submit" disabled={!authState.accessToken}>Update Default Password</button>
              </form>
            ) : null}
          </div>
        ) : null}
        {!isAdmin && authState.user ? (
          <p className="small">Standard user access: account settings and password management only.</p>
        ) : null}
        <p className="small">{settingsStatus}</p>
      </section>
    );
  }

  function renderUsersPanel() {
    if (authState.user?.role !== "admin") {
      return (
        <section className="card">
          <h2>Users</h2>
          <p className="small">Admin access required.</p>
        </section>
      );
    }
    return (
      <section className="card">
        <h2>Users</h2>
        <div className="item" style={{ marginTop: "0.75rem" }}>
          <div className="item-row">
            <strong>Create User</strong>
          </div>
          <form onSubmit={createUserByAdmin} className="form" style={{ marginTop: "0.5rem" }}>
            <p className="small">Create user with temporary password, then require password change on first login.</p>
            <label>
              Username
              <input
                value={createUserForm.username}
                onChange={(e) => setCreateUserForm((v) => ({ ...v, username: e.target.value }))}
                placeholder="newuser1"
                required
              />
            </label>
            <label>
              Role
              <select
                value={createUserForm.role}
                onChange={(e) => setCreateUserForm((v) => ({ ...v, role: e.target.value }))}
              >
                <option value="analyst">user</option>
                <option value="admin">admin</option>
              </select>
            </label>
            <div className="actions">
              <button type="submit" disabled={!authState.accessToken}>Create User</button>
              <button type="button" className="ghost-btn" onClick={fetchUsers} disabled={usersLoading}>
                {usersLoading ? "Refreshing..." : "Refresh List"}
              </button>
            </div>
          </form>
        </div>

        <div className="item" style={{ marginTop: "0.75rem" }}>
          <div className="item-row">
            <strong>All Users</strong>
            <span className="small">{usersData.length} total</span>
          </div>
          <div className="list" style={{ marginTop: "0.4rem" }}>
            {usersData.map((user) => (
              <div className="item" key={user.id}>
                <div className="item-row">
                  <div>
                    <strong>{user.username}</strong> <span className="small">({user.role})</span>
                  </div>
                  <div className="item-actions">
                    <span className={`badge ${user.locked ? "HIGH" : "LOW"}`}>{user.locked ? "BLOCKED" : "ACTIVE"}</span>
                    <button type="button" className="ghost-btn" onClick={() => resetUserPassword(user.id, user.username)}>
                      Reset Pass
                    </button>
                    <button
                      type="button"
                      className="danger-btn"
                      onClick={() => deleteUser(user.id, user.username)}
                      disabled={user.id === authState.user?.id}
                    >
                      Remove
                    </button>
                  </div>
                </div>
                <div className="small">Created: {formatEventTime(user.createdAt)}</div>
              </div>
            ))}
            {!usersData.length ? <div className="item"><div className="small">No users found.</div></div> : null}
          </div>
        </div>
        <p className="small">{usersStatus}</p>
      </section>
    );
  }

  return (
    <div className="container">
      <div className="title-wrap">
        <h1>Threat Detection & Response Dashboard</h1>
      </div>
      <div className="header-row">
        <p className="small">Live visibility into alerts, automated response actions, and risk posture.</p>
        {authState.accessToken ? (
          <div className="tabs">
            <button type="button" onClick={() => setPage("dashboard")} className={page === "dashboard" ? "active-tab" : ""}>
              Dashboard
            </button>
            <button type="button" onClick={() => setPage("settings")} className={page === "settings" ? "active-tab" : ""}>
              Settings
            </button>
            {authState.user?.role === "admin" ? (
              <button type="button" onClick={() => setPage("users")} className={page === "users" ? "active-tab" : ""}>
                Users
              </button>
            ) : null}
          </div>
        ) : null}
      </div>
      {authStatus ? <p className="small">{authStatus}</p> : null}

      {page === "auth" ? renderAuthForms() : null}
      {page === "settings" ? renderSettingsPanel() : null}
      {page === "users" ? renderUsersPanel() : null}
      {page === "dashboard" && !authState.accessToken ? (
        <section className="card">
          <h2>Authentication Required</h2>
          <p className="small">Log in with a valid webapp account to access threat telemetry.</p>
        </section>
      ) : null}
      {page !== "dashboard" || !authState.accessToken ? null : (
        <>
      <section className="grid kpis">
        <div className="card"><h2>{summary.activeAlerts}</h2><div className="small">Active Alerts</div></div>
        <div className="card"><h2>{summary.applicationAlerts}</h2><div className="small">App Alerts</div></div>
        <div className="card"><h2>{summary.engineSystemAlerts}</h2><div className="small">Engine Alerts</div></div>
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
          <h2>Detection Engine Alerts</h2>
          <div className="list">
            {systemAlerts.length ? (
              systemAlerts.map((alert) => (
                <div className="item" key={alert.id}>
                  <div className="item-row">
                    <div><span className={`badge ${alert.riskLevel || "LOW"}`}>{alert.riskLevel || "LOW"}</span> {alert.type}</div>
                  </div>
                  <div className="small">{formatEventTime(alert.timestamp)}</div>
                  <div className="small">
                    {(alert.details && typeof alert.details === "object")
                      ? Object.entries(alert.details).map(([k, v]) => `${k}=${String(v)}`).join(" | ")
                      : "No details"}
                  </div>
                </div>
              ))
            ) : (
              <div className="item"><div className="small">No detection engine alerts.</div></div>
            )}
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

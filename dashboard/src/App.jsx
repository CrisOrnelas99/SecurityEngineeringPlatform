import React, { useEffect, useMemo, useState } from "react";

const apiBase = import.meta.env.VITE_TDR_API_URL || "http://localhost:8000";
const webApiBase = import.meta.env.VITE_WEB_API_URL || "http://localhost:3000";
const AUTH_STORAGE_KEY = "tdr_dashboard_auth_state";

function loadStoredAuthState() {
  try {
    const raw = sessionStorage.getItem(AUTH_STORAGE_KEY);
    if (!raw) {
      return { accessToken: "", refreshToken: "", user: null };
    }
    const parsed = JSON.parse(raw);
    return {
      accessToken: typeof parsed?.accessToken === "string" ? parsed.accessToken : "",
      refreshToken: typeof parsed?.refreshToken === "string" ? parsed.refreshToken : "",
      user: parsed?.user && typeof parsed.user === "object" ? parsed.user : null
    };
  } catch {
    return { accessToken: "", refreshToken: "", user: null };
  }
}

export default function App() {
  const [authState, setAuthState] = useState(loadStoredAuthState);
  const [page, setPage] = useState(authState.accessToken ? "dashboard" : "auth");
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
  const [testIpInput, setTestIpInput] = useState("");
  const [expandedAlerts, setExpandedAlerts] = useState({});
  const [expandedAlertGroups, setExpandedAlertGroups] = useState({});
  const [expandedTimeline, setExpandedTimeline] = useState({});
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
  const [testIps, setTestIps] = useState([]);

  useEffect(() => {
    try {
      if (authState.accessToken || authState.refreshToken) {
        sessionStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(authState));
      } else {
        sessionStorage.removeItem(AUTH_STORAGE_KEY);
      }
    } catch {
      // Ignore storage failures.
    }
  }, [authState]);

  useEffect(() => {
    if (authState.accessToken && page === "auth") {
      setPage("dashboard");
    }
  }, [authState.accessToken, page]);

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
      setTestIps([]);
      setAdminDefaults({ newUserInitialPassword: "" });
      setDefaultsForm({ newUserInitialPassword: "" });
      if (page !== "auth") {
        setPage("auth");
      }
      return undefined;
    }

    let stop = false;
    const headers = { authorization: `Bearer ${authState.accessToken}` };
    const isAdminSession = authState.user?.role === "admin";

    async function refresh() {
      try {
        const [s, a, r, t, b, testList] = await Promise.all([
          fetch(`${apiBase}/summary`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("summary failed")))),
          fetch(`${apiBase}/alerts/categorized`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("alerts failed")))),
          fetch(`${apiBase}/risk`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("risk failed")))),
          fetch(`${apiBase}/timeline`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("timeline failed")))),
          fetch(`${apiBase}/blocked-ips`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("blocked-ips failed")))),
          isAdminSession
            ? fetch(`${apiBase}/test-ips`, { headers }).then((res) => (res.ok ? res.json() : Promise.reject(new Error("test-ips failed"))))
            : Promise.resolve([])
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
        setTestIps(testList);
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
  }, [authState.accessToken, authState.user?.role]);

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
  function isTimelineOnlyManagementEvent(endpointValue) {
    const endpoint = String(endpointValue || "").toLowerCase();
    return endpoint.includes("/api/auth/users") || endpoint.includes("/api/auth/change-password");
  }
  const realAlerts = useMemo(
    () =>
      alerts.filter(
        (alert) =>
          alert.type !== "BLACKLISTED_IP_ACCESS"
          && !alert?.details?.isTestIp
          && !isTimelineOnlyManagementEvent(alert.endpoint)
      ),
    [alerts]
  );
  const testAlerts = useMemo(
    () =>
      alerts.filter(
        (alert) =>
          alert.type !== "BLACKLISTED_IP_ACCESS"
          && Boolean(alert?.details?.isTestIp)
          && !isTimelineOnlyManagementEvent(alert.endpoint)
      ),
    [alerts]
  );
  const attackPatterns = useMemo(() => {
    const counts = new Map();
    for (const alert of realAlerts) {
      const label = normalizeEventName(alert.type);
      counts.set(label, (counts.get(label) || 0) + 1);
    }
    return [...counts.entries()]
      .map(([pattern, count]) => ({ pattern, count }))
      .sort((a, b) => b.count - a.count || a.pattern.localeCompare(b.pattern));
  }, [realAlerts]);
  function getTimestampSecondBucket(isoTs) {
    const dt = new Date(isoTs);
    if (Number.isNaN(dt.getTime())) {
      return String(isoTs || "").slice(0, 19);
    }
    return new Date(Math.floor(dt.getTime() / 1000) * 1000).toISOString().slice(0, 19);
  }

  function groupAlertsByEvent(inputAlerts) {
    const byKey = new Map();

    for (const alert of inputAlerts) {
      const eventName = normalizeEventName(alert.type);
      const ipValue = getIpDisplayInfo(alert.ip).value || "unknown";
      const secondBucket = getTimestampSecondBucket(alert.timestamp);
      const groupKey = `${eventName}|${ipValue}|${secondBucket}`;

      if (!byKey.has(groupKey)) {
        byKey.set(groupKey, {
          groupId: `grp-${alert.id}`,
          eventName,
          ipValue,
          secondBucket,
          alerts: [alert]
        });
        continue;
      }

      byKey.get(groupKey).alerts.push(alert);
    }

    return [...byKey.values()].sort(
      (a, b) => new Date(b.alerts[0]?.timestamp || 0).getTime() - new Date(a.alerts[0]?.timestamp || 0).getTime()
    );
  }

  const groupedRealAlerts = useMemo(() => groupAlertsByEvent(realAlerts), [realAlerts]);
  const groupedTestAlerts = useMemo(() => groupAlertsByEvent(testAlerts), [testAlerts]);

  const testRiskByIp = useMemo(() => {
    const scores = new Map();
    for (const entry of timeline) {
      const details = entry?.details || {};
      if (!details.isTestIp) {
        continue;
      }
      const ip = String(entry.ip || "unknown");
      const impact = Number(entry.scoreImpact || 0);
      scores.set(ip, (scores.get(ip) || 0) + impact);
    }
    function levelFor(score) {
      if (score >= 120) {
        return "CRITICAL";
      }
      if (score >= 70) {
        return "HIGH";
      }
      if (score >= 35) {
        return "MEDIUM";
      }
      return "LOW";
    }
    return [...scores.entries()]
      .map(([ip, score]) => ({ ip, score, riskLevel: levelFor(score) }))
      .sort((a, b) => b.score - a.score || a.ip.localeCompare(b.ip));
  }, [timeline]);

  const testAttackPatterns = useMemo(() => {
    const counts = new Map();
    for (const alert of testAlerts) {
      const event = normalizeEventName(alert.type);
      counts.set(event, (counts.get(event) || 0) + 1);
    }
    return [...counts.entries()]
      .map(([pattern, count]) => ({ pattern, count }))
      .sort((a, b) => b.count - a.count || a.pattern.localeCompare(b.pattern));
  }, [testAlerts]);
  const visibleTimeline = useMemo(() => {
    const isAdminViewer = authState.user?.role === "admin";
    return timeline.filter((entry) => {
      const eventName = normalizeEventName(String(entry.event || ""));
      const isTestIncident = Boolean(entry?.details?.isTestIp);
      const rawEvent = String(entry.event || "");
      const isAdminOnlyTimelineEvent = rawEvent === "ADMIN_DELETE_USER" || rawEvent === "ADMIN_RESET_USER_PASS";

      // Keep explicit test list management events visible.
      if (eventName === "TEST_IP_ADDED" || eventName === "TEST_IP_REMOVED") {
        return true;
      }

      if (isAdminOnlyTimelineEvent && !isAdminViewer) {
        return false;
      }

      // Hide test-traffic incidents from the primary timeline.
      if (isTestIncident) {
        return false;
      }

      if (showBlocklistTimelineEvents) {
        return true;
      }
      return eventName !== "BLOCKED_IP_REQUEST";
    });
  }, [timeline, showBlocklistTimelineEvents, authState.user?.role]);

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
    if (name === "ADMIN_DELETE_USER") {
      return "Admin Delete User";
    }
    if (name === "ADMIN_RESET_USER_PASS") {
      return "Admin Reset User Pass";
    }
    return name;
  }

  function normalizeActionName(name) {
    if (name === "BLACKLISTED_IP_ACCESS") {
      return "AUTO_BLOCK_IP_ACCESS";
    }
    if (name === "TEST_IP_NO_BLOCK") {
      return "TEST_IP_NO_BLOCK";
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

  async function clearTestAlerts() {
    if (!authState.accessToken) {
      return;
    }
    const ids = testAlerts.map((alert) => alert.id);
    if (!ids.length) {
      setAlertStatus("No test alerts to clear.");
      return;
    }
    setAlertStatus("Clearing test alerts...");
    try {
      await Promise.all(
        ids.map((id) =>
          fetch(`${apiBase}/alerts/${id}`, {
            method: "DELETE",
            headers: { authorization: `Bearer ${authState.accessToken}` }
          }).then((res) => {
            if (!res.ok) {
              throw new Error(`Unable to delete alert ${id}`);
            }
          })
        )
      );
      setAlerts((prev) => prev.filter((alert) => !alert?.details?.isTestIp));
      setAlertStatus("Test alerts cleared.");
    } catch (error) {
      setAlertStatus(`Clear test alerts failed: ${error.message}`);
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

  async function addTestIp() {
    const ip = testIpInput.trim();
    if (!ip) {
      setBlockStatus("Enter a test IP first.");
      return;
    }
    setBlockStatus("Adding test IP...");
    try {
      const response = await fetch(`${apiBase}/test-ips`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${authState.accessToken}`
        },
        body: JSON.stringify({ ip, source: "dashboard" })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || "Unable to add test IP");
      }
      setTestIps((prev) => (prev.includes(ip) ? prev : [...prev, ip].sort()));
      setBlockedIps((prev) => prev.filter((item) => item !== ip));
      setTestIpInput("");
      setBlockStatus(payload.added ? `Added ${ip} to test IPs.` : `${ip} is already a test IP.`);
    } catch (error) {
      setBlockStatus(`Add test IP failed: ${error.message}`);
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

  async function removeTestIp(ip) {
    setBlockStatus(`Removing test IP ${ip}...`);
    try {
      const response = await fetch(`${apiBase}/test-ips/${encodeURIComponent(ip)}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${authState.accessToken}` }
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || "Unable to remove test IP");
      }
      setTestIps((prev) => prev.filter((item) => item !== ip));
      setBlockStatus(`Removed ${ip} from test IPs.`);
    } catch (error) {
      setBlockStatus(`Remove test IP failed: ${error.message}`);
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
          </div>
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
        </div>
        <div className="item" style={{ marginTop: "0.75rem" }}>
          <div className="item-row">
            <strong>Password Management</strong>
          </div>
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
        </div>
        {isAdmin ? (
          <div className="item" style={{ marginTop: "0.75rem" }}>
            <div className="item-row">
              <strong>Admin Security Defaults</strong>
            </div>
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

  function renderTestDashboard() {
    if (authState.user?.role !== "admin") {
      return (
        <section className="card">
          <h2>Test</h2>
          <p className="small">Admin access required.</p>
        </section>
      );
    }

    return (
      <>
        <section className="grid cards" style={{ marginTop: "1rem" }}>
          <div className="card">
              <div className="card-title-row">
              <h2>Test Alerts ({groupedTestAlerts.length})</h2>
                <div className="item-actions">
                  <button type="button" className="danger-btn" onClick={clearTestAlerts}>
                    Clear Alerts
                  </button>
                </div>
              </div>
              {alertStatus ? <p className="small">{alertStatus}</p> : null}
            <div className="list">
              {groupedTestAlerts.map((group) => (
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
                  <div className="small">Test IP traffic.</div>
                  {group.alerts[0]?.details?.description ? (
                    <div className="small">Description: {group.alerts[0].details.description}</div>
                  ) : null}
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
                          <div className="small">Test IP traffic.</div>
                          {alert?.details?.description ? (
                            <div className="small">Description: {alert.details.description}</div>
                          ) : null}
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
              {!testAlerts.length ? (
                <div className="item"><div className="small">No test alerts.</div></div>
              ) : null}
            </div>
          </div>

          <div className="card">
            <h2>Detection Engine Alerts ({systemAlerts.length})</h2>
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
            <h2>Test Risk Scores By IP ({testRiskByIp.length})</h2>
            <div className="list">
              {testRiskByIp.map((entry) => (
                <div className="item" key={entry.ip}>
                  <div>{getIpDisplayInfo(entry.ip).version}: {getIpDisplayInfo(entry.ip).value}</div>
                  <div className="small">score: {entry.score} <span className={`badge ${entry.riskLevel}`}>{entry.riskLevel}</span></div>
                </div>
              ))}
              {!testRiskByIp.length ? (
                <div className="item"><div className="small">No test risk entries.</div></div>
              ) : null}
            </div>
          </div>

          <div className="card">
            <h2>Test IPs ({testIps.length})</h2>
            <div className="actions">
              <input
                className="inline-input"
                value={testIpInput}
                onChange={(e) => setTestIpInput(e.target.value)}
                placeholder="127.0.0.1 or ::1"
              />
              <button type="button" className="ghost-btn" onClick={addTestIp}>Add Test IP</button>
            </div>
            {blockStatus ? <p className="small">{blockStatus}</p> : null}
            <div className="list">
              {testIps.map((ip) => (
                <div className="item item-row" key={`test-${ip}`}>
                  <span>{getIpDisplayInfo(ip).version}: {getIpDisplayInfo(ip).value}</span>
                  <button type="button" className="alert-delete-btn" onClick={() => removeTestIp(ip)}>Remove</button>
                </div>
              ))}
              {!testIps.length ? (
                <div className="item"><div className="small">No test IPs configured.</div></div>
              ) : null}
            </div>
            <h2 style={{ marginTop: "1rem" }}>Test Attack Patterns ({testAttackPatterns.length})</h2>
            <div className="list">
              {testAttackPatterns.map((pattern) => (
                <div className="item" key={pattern.pattern}>{pattern.pattern} ({pattern.count})</div>
              ))}
              {!testAttackPatterns.length ? (
                <div className="item"><div className="small">No test attack patterns.</div></div>
              ) : null}
            </div>
          </div>
        </section>
      </>
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
            {authState.user?.role === "admin" ? (
              <button type="button" onClick={() => setPage("users")} className={page === "users" ? "active-tab" : ""}>
                Users
              </button>
            ) : null}
            <button type="button" onClick={() => setPage("settings")} className={page === "settings" ? "active-tab" : ""}>
              Settings
            </button>
            {authState.user?.role === "admin" ? <span className="tabs-spacer" /> : null}
            {authState.user?.role === "admin" ? (
              <button
                type="button"
                className={page === "test-dashboard" ? "active-tab" : ""}
                onClick={() => setPage("test-dashboard")}
              >
                Test
              </button>
            ) : null}
          </div>
        ) : null}
      </div>
      {authStatus ? <p className="small">{authStatus}</p> : null}

      {page === "auth" ? renderAuthForms() : null}
      {page === "settings" ? renderSettingsPanel() : null}
      {page === "users" ? renderUsersPanel() : null}
      {page === "test-dashboard" ? renderTestDashboard() : null}
      {page === "dashboard" && !authState.accessToken ? (
        <section className="card">
          <h2>Authentication Required</h2>
          <p className="small">Log in with a valid webapp account to access threat telemetry.</p>
        </section>
      ) : null}
      {page !== "dashboard" || !authState.accessToken ? null : (
        <>
      <section className="grid cards" style={{ marginTop: "1rem" }}>
        <div className="card">
          <div className="card-title-row">
            <h2>Active Alerts ({groupedRealAlerts.length})</h2>
            <div className="item-actions">
              <button type="button" className="danger-btn" onClick={clearAllAlerts}>Clear Alerts</button>
            </div>
          </div>
          {alertStatus ? <p className="small">{alertStatus}</p> : null}
          <div className="list">
            {groupedRealAlerts.map((group) => (
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
                {group.alerts[0]?.details?.description ? (
                  <div className="small">Description: {group.alerts[0].details.description}</div>
                ) : null}
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
                        {alert?.details?.description ? (
                          <div className="small">Description: {alert.details.description}</div>
                        ) : null}
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
          <h2>Detection Engine Alerts ({systemAlerts.length})</h2>
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
          <h2>Risk Scores By IP ({risk.riskByIp.length})</h2>
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
            <h2>Incident Timeline ({visibleTimeline.length})</h2>
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
          <h2>Blocked IPs ({blockedIps.length})</h2>
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
        </div>
        <div className="card">
          <h2>Attack Patterns ({attackPatterns.length})</h2>
          <div className="list">
            {attackPatterns.map((pattern) => (
              <div className="item" key={pattern.pattern}>{pattern.pattern} ({pattern.count})</div>
            ))}
          </div>
        </div>
      </section>
        </>
      )}
    </div>
  );
}

import React, { useEffect, useMemo, useState } from "react";
import AuthPanel from "./components/panels/AuthPanel.jsx";
import SettingsPanel from "./components/panels/SettingsPanel.jsx";
import UsersPanel from "./components/panels/UsersPanel.jsx";
import TestDashboardPanel from "./components/panels/TestDashboardPanel.jsx";
import MainDashboardPanel from "./components/panels/MainDashboardPanel.jsx";
import AnalyticsPanel from "./components/panels/AnalyticsPanel.jsx";
import useDashboardActions from "./hooks/useDashboardActions.js";
import { loadStoredAuthState, persistAuthState } from "./lib/authStorage.js";
import {
  formatEventTime,
  getIpDisplayInfo,
  normalizeEventName,
  normalizeActionName,
  formatDetailValue
} from "./lib/formatters.js";
import {
  shouldShowInAlertPanels,
  groupAlertsByEvent,
  buildTestRiskByIp,
  buildAttackPatterns,
  buildVisibleTimeline
} from "./lib/alertDerivations.js";
import {
  getAnalyticsWindowOptions,
  getAnalyticsRangeMs,
  getAnalyticsEventTypes,
  filterAnalyticsEvents,
  buildAnalyticsBucketRows,
  buildAnalyticsCsv
} from "./lib/analytics.js";

const apiBase = import.meta.env.VITE_TDR_API_URL || "http://localhost:8000";
const webApiBase = import.meta.env.VITE_WEB_API_URL || "http://localhost:3000";

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
  const [expandedTimeline, setExpandedTimeline] = useState({});
  const [adminDefaults, setAdminDefaults] = useState({ newUserInitialPassword: "" });
  const [defaultsForm, setDefaultsForm] = useState({ newUserInitialPassword: "" });
  const [usersStatus, setUsersStatus] = useState("");
  const [usersData, setUsersData] = useState([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [analyticsGranularity, setAnalyticsGranularity] = useState("hourly");
  const [analyticsWindowKey, setAnalyticsWindowKey] = useState("24h");
  const [analyticsSelectedTypes, setAnalyticsSelectedTypes] = useState([]);
  const [analyticsTypeFilterTouched, setAnalyticsTypeFilterTouched] = useState(false);

  const [summary, setSummary] = useState({
    activeAlerts: 0,
    applicationAlerts: 0,
    blockedIps: 0,
    lockedUsers: 0,
    honeypotTriggers: 0,
    topAttackPatterns: []
  });
  const [alerts, setAlerts] = useState([]);
  const [risk, setRisk] = useState({ riskByIp: [], riskByUser: [] });
  const [timeline, setTimeline] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);
  const [testIps, setTestIps] = useState([]);

  useEffect(() => {
    persistAuthState(authState);
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
        blockedIps: 0,
        lockedUsers: 0,
        honeypotTriggers: 0,
        topAttackPatterns: []
      });
      setAlerts([]);
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
        setAlerts((a.applicationAlerts || []).slice().reverse());
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
  const realAlerts = useMemo(
    () =>
      alerts.filter(
        (alert) =>
          shouldShowInAlertPanels(alert)
          && !alert?.details?.isTestIp
      ),
    [alerts]
  );
  const testAlerts = useMemo(
    () =>
      alerts.filter(
        (alert) =>
          shouldShowInAlertPanels(alert)
          && Boolean(alert?.details?.isTestIp)
      ),
    [alerts]
  );
  const attackPatterns = useMemo(() => buildAttackPatterns(realAlerts), [realAlerts]);

  const groupedRealAlerts = useMemo(() => groupAlertsByEvent(realAlerts), [realAlerts]);
  const groupedTestAlerts = useMemo(() => groupAlertsByEvent(testAlerts), [testAlerts]);

  const testRiskByIp = useMemo(() => buildTestRiskByIp(timeline), [timeline]);
  const testAttackPatterns = useMemo(() => buildAttackPatterns(testAlerts), [testAlerts]);
  const visibleTimeline = useMemo(
    () => buildVisibleTimeline(timeline, authState.user?.role),
    [timeline, authState.user?.role]
  );

  const analyticsWindowOptions = useMemo(
    () => getAnalyticsWindowOptions(analyticsGranularity),
    [analyticsGranularity]
  );

  useEffect(() => {
    const allowed = new Set(analyticsWindowOptions.map((opt) => opt.value));
    if (!allowed.has(analyticsWindowKey)) {
      setAnalyticsWindowKey(analyticsWindowOptions[0].value);
    }
  }, [analyticsWindowKey, analyticsWindowOptions]);

  const analyticsEventTypes = useMemo(() => getAnalyticsEventTypes(timeline), [timeline]);

  useEffect(() => {
    if (!analyticsEventTypes.length) {
      setAnalyticsSelectedTypes([]);
      setAnalyticsTypeFilterTouched(false);
      return;
    }
    setAnalyticsSelectedTypes((prev) => {
      const validPrev = prev.filter((type) => analyticsEventTypes.includes(type));
      if (!analyticsTypeFilterTouched) {
        return analyticsEventTypes;
      }
      return validPrev;
    });
  }, [analyticsEventTypes, analyticsTypeFilterTouched]);

  const analyticsRangeMs = useMemo(
    () => getAnalyticsRangeMs(analyticsGranularity, analyticsWindowKey),
    [analyticsGranularity, analyticsWindowKey]
  );

  const analyticsFilteredEvents = useMemo(
    () => filterAnalyticsEvents(timeline, analyticsSelectedTypes, analyticsRangeMs),
    [timeline, analyticsSelectedTypes, analyticsRangeMs]
  );

  const analyticsBucketRows = useMemo(
    () => buildAnalyticsBucketRows(analyticsFilteredEvents, analyticsGranularity),
    [analyticsFilteredEvents, analyticsGranularity]
  );

  const analyticsTotalCount = useMemo(
    () => analyticsFilteredEvents.length,
    [analyticsFilteredEvents]
  );

  const {
    loginUser,
    createUserByAdmin,
    fetchUsers,
    resetUserPassword,
    deleteUser,
    runAdminTest,
    logoutUser,
    changePassword,
    clearAllAlerts,
    deleteAlertById,
    clearTestAlerts,
    addBlockedIp,
    addTestIp,
    unblockIp,
    removeTestIp,
    updateDefaultInitialPassword,
    downloadAnalyticsCsv,
    printAnalytics
  } = useDashboardActions({
    apiBase,
    webApiBase,
    authState,
    authForm,
    createUserForm,
    passwordForm,
    defaultsForm,
    blockIpInput,
    testIpInput,
    testAlerts,
    analyticsBucketRows,
    analyticsGranularity,
    analyticsWindowKey,
    setAuthStatus,
    setAuthState,
    setPasswordForm,
    setPage,
    setCreateUserForm,
    setSettingsStatus,
    setUsersStatus,
    setUsersLoading,
    setUsersData,
    setAccountProfile,
    setAlertStatus,
    setAlerts,
    setTimeline,
    setRisk,
    setSummary,
    setBlockedIps,
    setBlockIpInput,
    setTestIps,
    setTestIpInput,
    setBlockStatus,
    setAdminDefaults,
    buildAnalyticsCsv
  });

  function toggleAlertDetails(alertId) {
    setExpandedAlerts((prev) => ({ ...prev, [alertId]: !prev[alertId] }));
  }

  function toggleTimelineDetails(timelineId) {
    setExpandedTimeline((prev) => ({ ...prev, [timelineId]: !prev[timelineId] }));
  }

  function toggleAnalyticsType(type) {
    setAnalyticsTypeFilterTouched(true);
    setAnalyticsSelectedTypes((prev) => (
      prev.includes(type) ? prev.filter((item) => item !== type) : [...prev, type]
    ));
  }

  function selectAllAnalyticsTypes() {
    setAnalyticsTypeFilterTouched(true);
    setAnalyticsSelectedTypes(analyticsEventTypes);
  }

  function clearAllAnalyticsTypes() {
    setAnalyticsTypeFilterTouched(true);
    setAnalyticsSelectedTypes([]);
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
            <button type="button" onClick={() => setPage("analytics")} className={page === "analytics" ? "active-tab" : ""}>
              Analytics
            </button>
            <button type="button" onClick={() => setPage("settings")} className={page === "settings" ? "active-tab" : ""}>
              Settings
            </button>
          </div>
        ) : null}
      </div>
      {authStatus ? <p className="small">{authStatus}</p> : null}

      {page === "auth" ? (
        <AuthPanel authForm={authForm} setAuthForm={setAuthForm} onLogin={loginUser} />
      ) : null}
      {page === "settings" ? (
        <SettingsPanel
          authState={authState}
          accountProfile={accountProfile}
          formatEventTime={formatEventTime}
          onLogout={logoutUser}
          onRunAdminCheck={runAdminTest}
          onChangePassword={changePassword}
          passwordForm={passwordForm}
          setPasswordForm={setPasswordForm}
          onUpdateDefaultInitialPassword={updateDefaultInitialPassword}
          adminDefaults={adminDefaults}
          defaultsForm={defaultsForm}
          setDefaultsForm={setDefaultsForm}
          settingsStatus={settingsStatus}
        />
      ) : null}
      {page === "users" ? (
        <UsersPanel
          authState={authState}
          createUserForm={createUserForm}
          setCreateUserForm={setCreateUserForm}
          onCreateUser={createUserByAdmin}
          onRefreshUsers={fetchUsers}
          usersLoading={usersLoading}
          usersData={usersData}
          onResetUserPassword={resetUserPassword}
          onDeleteUser={deleteUser}
          formatEventTime={formatEventTime}
          usersStatus={usersStatus}
        />
      ) : null}
      {page === "analytics" ? (
        <AnalyticsPanel
          granularity={analyticsGranularity}
          setGranularity={setAnalyticsGranularity}
          windowKey={analyticsWindowKey}
          setWindowKey={setAnalyticsWindowKey}
          windowOptions={analyticsWindowOptions}
          eventTypes={analyticsEventTypes}
          selectedTypes={analyticsSelectedTypes}
          toggleType={toggleAnalyticsType}
          selectAllTypes={selectAllAnalyticsTypes}
          clearAllTypes={clearAllAnalyticsTypes}
          bucketRows={analyticsBucketRows}
          totalCount={analyticsTotalCount}
          formatEventTime={formatEventTime}
          getIpDisplayInfo={getIpDisplayInfo}
          formatDetailValue={formatDetailValue}
          normalizeEventName={normalizeEventName}
          normalizeActionName={normalizeActionName}
          onDownloadCsv={downloadAnalyticsCsv}
          onPrint={printAnalytics}
        />
      ) : null}
      {page === "test-dashboard" ? (
        <TestDashboardPanel
          authState={authState}
          groupedTestAlerts={groupedTestAlerts}
          clearTestAlerts={clearTestAlerts}
          alertStatus={alertStatus}
          formatEventTime={formatEventTime}
          getIpDisplayInfo={getIpDisplayInfo}
          expandedAlerts={expandedAlerts}
          toggleAlertDetails={toggleAlertDetails}
          deleteAlertById={deleteAlertById}
          normalizeActionName={normalizeActionName}
          renderAlertDetails={renderAlertDetails}
          testAlerts={testAlerts}
          testRiskByIp={testRiskByIp}
          testIps={testIps}
          testIpInput={testIpInput}
          setTestIpInput={setTestIpInput}
          addTestIp={addTestIp}
          blockStatus={blockStatus}
          removeTestIp={removeTestIp}
          testAttackPatterns={testAttackPatterns}
        />
      ) : null}
      {page === "dashboard" && !authState.accessToken ? (
        <section className="card">
          <h2>Authentication Required</h2>
          <p className="small">Log in with a valid webapp account to access threat telemetry.</p>
        </section>
      ) : null}
      {page !== "dashboard" || !authState.accessToken ? null : (
        <MainDashboardPanel
          groupedRealAlerts={groupedRealAlerts}
          clearAllAlerts={clearAllAlerts}
          alertStatus={alertStatus}
          formatEventTime={formatEventTime}
          getIpDisplayInfo={getIpDisplayInfo}
          expandedAlerts={expandedAlerts}
          toggleAlertDetails={toggleAlertDetails}
          deleteAlertById={deleteAlertById}
          normalizeActionName={normalizeActionName}
          renderAlertDetails={renderAlertDetails}
          risk={risk}
          topIp={topIp}
          blockedIps={blockedIps}
          blockIpInput={blockIpInput}
          setBlockIpInput={setBlockIpInput}
          addBlockedIp={addBlockedIp}
          blockStatus={blockStatus}
          unblockIp={unblockIp}
          attackPatterns={attackPatterns}
          visibleTimeline={visibleTimeline}
          expandedTimeline={expandedTimeline}
          toggleTimelineDetails={toggleTimelineDetails}
          renderTimelineDetails={renderTimelineDetails}
          normalizeEventName={normalizeEventName}
          isAdmin={authState.user?.role === "admin"}
          onOpenTestDashboard={() => setPage("test-dashboard")}
        />
      )}
    </div>
  );
}

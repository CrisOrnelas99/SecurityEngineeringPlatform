export default function useDashboardActions({
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
}) {
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
        const errorMessage = String(payload?.error || "").toLowerCase();
        const isInvalidToken = response.status === 401
          || response.status === 403
          || errorMessage.includes("invalid access token")
          || errorMessage.includes("invalid token")
          || errorMessage.includes("jwt");
        if (isInvalidToken) {
          setAuthState({ accessToken: "", refreshToken: "", user: null });
          setAuthStatus("Session expired. Please log in again.");
          setPage("auth");
          return;
        }
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
        `User ${payload.username} created (${payload.role}).`
      );
      setUsersStatus(
        `User ${payload.username} created (${payload.role}).`
      );
      await fetchUsers();
    } catch (error) {
      setSettingsStatus(`Create user failed: ${error.message}`);
      setUsersStatus(`Create user failed: ${error.message}`);
    }
  }

  async function resetUserPassword(userId, username) {
    if (!authState.accessToken || authState.user?.role !== "admin") {
      return;
    }
    setUsersStatus(`Resetting password for ${username}...`);
    try {
      await postWithCsrf(
        `/api/auth/users/${encodeURIComponent(userId)}/reset-password`,
        {},
        authState.accessToken
      );
      setUsersStatus(`Password reset for ${username}.`);
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
    if (!authState.accessToken || authState.user?.role !== "admin") {
      setAlertStatus("Only admins can clear all alerts.");
      return;
    }
    setAlertStatus("Clearing alerts...");
    try {
      const response = await fetch(`${apiBase}/alerts`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${authState.accessToken}` }
      });
      if (!response.ok) {
        throw new Error("Unable to clear alerts");
      }
      const [timelineResponse, riskResponse] = await Promise.all([
        fetch(`${apiBase}/timeline`, {
          headers: { authorization: `Bearer ${authState.accessToken}` }
        }),
        fetch(`${apiBase}/risk`, {
          headers: { authorization: `Bearer ${authState.accessToken}` }
        })
      ]);
      if (timelineResponse.ok) {
        const timelinePayload = await timelineResponse.json().catch(() => []);
        setTimeline(Array.isArray(timelinePayload) ? timelinePayload.slice(-60).reverse() : []);
      } else {
        setTimeline([]);
      }
      if (riskResponse.ok) {
        const riskPayload = await riskResponse.json().catch(() => ({ riskByIp: [], riskByUser: [] }));
        setRisk({
          riskByIp: Array.isArray(riskPayload?.riskByIp) ? riskPayload.riskByIp : [],
          riskByUser: Array.isArray(riskPayload?.riskByUser) ? riskPayload.riskByUser : []
        });
      } else {
        setRisk({ riskByIp: [], riskByUser: [] });
      }
      setAlerts([]);
      setSummary((prev) => ({
        ...prev,
        activeAlerts: 0,
        applicationAlerts: 0,
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
      const timelineResponse = await fetch(`${apiBase}/timeline`, {
        headers: { authorization: `Bearer ${authState.accessToken}` }
      });
      if (timelineResponse.ok) {
        const timelinePayload = await timelineResponse.json().catch(() => []);
        setTimeline(Array.isArray(timelinePayload) ? timelinePayload.slice(-60).reverse() : []);
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

  function downloadAnalyticsCsv() {
    const csv = buildAnalyticsCsv(analyticsBucketRows);
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `alerts-analytics-${analyticsGranularity}-${analyticsWindowKey}.csv`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  }

  function printAnalytics() {
    window.print();
  }

  return {
    loginUser,
    createUserByAdmin,
    fetchUsers,
    resetUserPassword,
    deleteUser,
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
  };
}

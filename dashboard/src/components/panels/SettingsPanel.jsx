import React from "react";

export default function SettingsPanel({
  authState,
  accountProfile,
  formatEventTime,
  onLogout,
  onChangePassword,
  passwordForm,
  setPasswordForm,
  onUpdateDefaultInitialPassword,
  defaultsForm,
  setDefaultsForm,
  settingsStatus
}) {
  const collapseDelayMs = 320;
  const isAdmin = authState.user?.role === "admin";
  const [isPasswordHovered, setIsPasswordHovered] = React.useState(false);
  const [isAdminDefaultsHovered, setIsAdminDefaultsHovered] = React.useState(false);
  const passwordCollapseTimeoutRef = React.useRef(null);
  const adminDefaultsCollapseTimeoutRef = React.useRef(null);

  React.useEffect(() => () => {
    if (passwordCollapseTimeoutRef.current) {
      clearTimeout(passwordCollapseTimeoutRef.current);
    }
    if (adminDefaultsCollapseTimeoutRef.current) {
      clearTimeout(adminDefaultsCollapseTimeoutRef.current);
    }
  }, []);

  function handlePasswordMouseEnter() {
    if (passwordCollapseTimeoutRef.current) {
      clearTimeout(passwordCollapseTimeoutRef.current);
      passwordCollapseTimeoutRef.current = null;
    }
    if (adminDefaultsCollapseTimeoutRef.current) {
      clearTimeout(adminDefaultsCollapseTimeoutRef.current);
      adminDefaultsCollapseTimeoutRef.current = null;
    }
    setIsPasswordHovered(true);
    setIsAdminDefaultsHovered(false);
  }

  function handlePasswordMouseLeave() {
    if (passwordCollapseTimeoutRef.current) {
      clearTimeout(passwordCollapseTimeoutRef.current);
    }
    passwordCollapseTimeoutRef.current = setTimeout(() => {
      setIsPasswordHovered(false);
      passwordCollapseTimeoutRef.current = null;
    }, collapseDelayMs);
  }

  function handleAdminDefaultsMouseEnter() {
    if (adminDefaultsCollapseTimeoutRef.current) {
      clearTimeout(adminDefaultsCollapseTimeoutRef.current);
      adminDefaultsCollapseTimeoutRef.current = null;
    }
    if (passwordCollapseTimeoutRef.current) {
      clearTimeout(passwordCollapseTimeoutRef.current);
      passwordCollapseTimeoutRef.current = null;
    }
    setIsAdminDefaultsHovered(true);
    setIsPasswordHovered(false);
  }

  function handleAdminDefaultsMouseLeave() {
    if (adminDefaultsCollapseTimeoutRef.current) {
      clearTimeout(adminDefaultsCollapseTimeoutRef.current);
    }
    adminDefaultsCollapseTimeoutRef.current = setTimeout(() => {
      setIsAdminDefaultsHovered(false);
      adminDefaultsCollapseTimeoutRef.current = null;
    }, collapseDelayMs);
  }

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
            <button type="button" onClick={onLogout} disabled={!authState.accessToken}>
              Logout
            </button>
          </div>
        </>
      </div>
      <div
        className="item"
        style={{ marginTop: "0.75rem" }}
        onMouseEnter={handlePasswordMouseEnter}
        onMouseLeave={handlePasswordMouseLeave}
      >
        <div className="item-row hover-expand-trigger">
          <strong>Password Management</strong>
        </div>
        <div className={`hover-expand-content ${isPasswordHovered ? "is-open" : ""}`}>
          <form onSubmit={onChangePassword} className="form" style={{ marginTop: "0.5rem" }}>
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
      </div>
      {isAdmin ? (
        <div
          className="item"
          style={{ marginTop: "0.75rem" }}
          onMouseEnter={handleAdminDefaultsMouseEnter}
          onMouseLeave={handleAdminDefaultsMouseLeave}
        >
          <div className="item-row hover-expand-trigger">
            <strong>Admin Security Defaults</strong>
          </div>
          <div className={`hover-expand-content ${isAdminDefaultsHovered ? "is-open" : ""}`}>
            <form onSubmit={onUpdateDefaultInitialPassword} className="form" style={{ marginTop: "0.5rem" }}>
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
        </div>
      ) : null}
      {!isAdmin && authState.user ? (
        <p className="small">Standard user access: account settings and password management only.</p>
      ) : null}
      <p className="small">{settingsStatus}</p>
    </section>
  );
}

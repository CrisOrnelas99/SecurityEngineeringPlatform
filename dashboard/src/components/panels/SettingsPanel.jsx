import React from "react";

export default function SettingsPanel({
  authState,
  accountProfile,
  formatEventTime,
  onLogout,
  onRunAdminCheck,
  onChangePassword,
  passwordForm,
  setPasswordForm,
  onUpdateDefaultInitialPassword,
  adminDefaults,
  defaultsForm,
  setDefaultsForm,
  settingsStatus
}) {
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
            <button type="button" onClick={onLogout} disabled={!authState.accessToken}>
              Logout
            </button>
            {isAdmin ? (
              <button type="button" onClick={onRunAdminCheck} disabled={!authState.accessToken}>
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
      {isAdmin ? (
        <div className="item" style={{ marginTop: "0.75rem" }}>
          <div className="item-row">
            <strong>Admin Security Defaults</strong>
          </div>
          <form onSubmit={onUpdateDefaultInitialPassword} className="form" style={{ marginTop: "0.5rem" }}>
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

import React from "react";

export default function UsersPanel({
  authState,
  createUserForm,
  setCreateUserForm,
  onCreateUser,
  usersData,
  onResetUserPassword,
  onDeleteUser,
  formatEventTime,
  usersStatus
}) {
  const collapseDelayMs = 320;
  const [isCreateHovered, setIsCreateHovered] = React.useState(false);
  const createCollapseTimeoutRef = React.useRef(null);

  React.useEffect(() => () => {
    if (createCollapseTimeoutRef.current) {
      clearTimeout(createCollapseTimeoutRef.current);
    }
  }, []);

  function handleCreateMouseEnter() {
    if (createCollapseTimeoutRef.current) {
      clearTimeout(createCollapseTimeoutRef.current);
      createCollapseTimeoutRef.current = null;
    }
    setIsCreateHovered(true);
  }

  function handleCreateMouseLeave() {
    if (createCollapseTimeoutRef.current) {
      clearTimeout(createCollapseTimeoutRef.current);
    }
    createCollapseTimeoutRef.current = setTimeout(() => {
      setIsCreateHovered(false);
      createCollapseTimeoutRef.current = null;
    }, collapseDelayMs);
  }

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
                  <button type="button" className="ghost-btn" onClick={() => onResetUserPassword(user.id, user.username)}>
                    Reset Pass
                  </button>
                  <button
                    type="button"
                    className="danger-btn"
                    onClick={() => onDeleteUser(user.id, user.username)}
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

      <div
        className="item"
        style={{ marginTop: "0.75rem" }}
        onMouseEnter={handleCreateMouseEnter}
        onMouseLeave={handleCreateMouseLeave}
      >
        <div className="item-row hover-expand-trigger">
          <strong>Create User</strong>
        </div>
        <div className={`hover-expand-content ${isCreateHovered ? "is-open" : ""}`}>
          <form onSubmit={onCreateUser} className="form" style={{ marginTop: "0.5rem" }}>
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
            </div>
          </form>
        </div>
      </div>
      <p className="small">{usersStatus}</p>
    </section>
  );
}

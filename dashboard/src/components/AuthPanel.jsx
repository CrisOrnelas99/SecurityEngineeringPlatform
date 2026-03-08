import React from "react";

export default function AuthPanel({ authForm, setAuthForm, onLogin }) {
  return (
    <section className="auth-grid">
      <div className="card">
        <h2>Login</h2>
        <form onSubmit={onLogin} className="form">
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

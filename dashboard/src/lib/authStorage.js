export const AUTH_STORAGE_KEY = "tdr_dashboard_auth_state";

export function loadStoredAuthState() {
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

export function persistAuthState(authState) {
  try {
    if (authState.accessToken || authState.refreshToken) {
      sessionStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(authState));
    } else {
      sessionStorage.removeItem(AUTH_STORAGE_KEY);
    }
  } catch {
    // Ignore storage failures.
  }
}

import { useEffect, useState } from "preact/hooks";

// Optional web login (see components/web_server/web_auth.cpp).
// Module-level store so every component shares one auth state, plus a fetch wrapper
// that notices "401 + auth_required" from any API call (most components call fetch()
// directly) and flips the app back to the login screen.

export type AuthStatus = {
  enabled: boolean;
  enforced: boolean;
  authenticated: boolean;
  password_strong: boolean;
  min_password_length: number;
};

type AuthState = { loaded: boolean; status?: AuthStatus };

let state: AuthState = { loaded: false };
const listeners = new Set<(s: AuthState) => void>();

function setState(next: AuthState) {
  state = next;
  listeners.forEach((l) => l(state));
}

export async function refreshAuthStatus(): Promise<AuthStatus | undefined> {
  try {
    const res = await fetch("/api/auth/status", {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!res.ok) throw new Error(res.statusText);
    const status = (await res.json()) as AuthStatus;
    setState({ loaded: true, status });
    return status;
  } catch {
    // Older firmware without /api/auth/*: behave as if login is off
    const status: AuthStatus = {
      enabled: false,
      enforced: false,
      authenticated: true,
      password_strong: false,
      min_password_length: 8,
    };
    setState({ loaded: true, status });
    return status;
  }
}

function markLoggedOut() {
  if (state.status && state.status.authenticated) {
    setState({
      loaded: true,
      status: { ...state.status, authenticated: false },
    });
  }
}

let fetchPatched = false;

/// Wrap window.fetch once: a 401 carrying auth_required on any /api/ call means the session is gone.
export function installAuthFetchInterceptor() {
  if (fetchPatched || typeof window === "undefined") return;
  fetchPatched = true;
  const original = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const res = await original(input, init);
    if (res.status === 401) {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      const path = new URL(url, window.location.origin).pathname;
      if (path.startsWith("/api/") && !path.startsWith("/api/auth/")) {
        try {
          const body = await res.clone().json();
          if (body && body.auth_required) markLoggedOut();
        } catch {
          /* not JSON: not a login rejection */
        }
      }
    }
    return res;
  };
}

export type LoginResult = { ok: boolean; tooFast?: boolean };

export async function login(password: string): Promise<LoginResult> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ password }),
  });
  if (res.ok) {
    await refreshAuthStatus();
    return { ok: true };
  }
  return { ok: false, tooFast: res.status === 429 };
}

export async function logout(): Promise<void> {
  try {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "same-origin",
    });
  } finally {
    await refreshAuthStatus();
  }
}

/// Shared auth state; triggers the first status request on first use.
export function useAuth(): AuthState {
  const [s, setS] = useState<AuthState>(state);
  useEffect(() => {
    listeners.add(setS);
    if (!state.loaded) void refreshAuthStatus();
    else setS(state);
    return () => {
      listeners.delete(setS);
    };
  }, []);
  return s;
}

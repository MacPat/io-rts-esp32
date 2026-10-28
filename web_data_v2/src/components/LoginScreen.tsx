import { useEffect, useRef, useState } from "preact/hooks";
import useI18n from "../hooks/useI18n";
import { login } from "../hooks/useAuth";

const THEME_STORAGE_KEY = "io-homecontrol-theme";

export function LoginScreen() {
  const i18n = useI18n();
  const t = i18n.t;
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // The header (which normally applies the theme) is not shown before login
  useEffect(() => {
    try {
      const theme =
        window.localStorage.getItem(THEME_STORAGE_KEY) ?? "charcoal";
      document.documentElement.setAttribute("data-theme", theme);
    } catch {
      /* ignore */
    }
    inputRef.current?.focus();
  }, []);

  async function onSubmit(e: Event) {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await login(password);
      if (!result.ok) {
        setError(result.tooFast ? "login.too-fast" : "login.invalid");
        setPassword("");
        inputRef.current?.focus();
      }
    } catch {
      setError("login.error");
    } finally {
      setBusy(false);
    }
  }

  const fallback: Record<string, string> = {
    "login.too-fast": "Too fast — wait 2 seconds and try again.",
    "login.invalid": "Incorrect password.",
    "login.error": "Cannot reach the controller.",
  };
  const tr = (key: string, def: string) => {
    const v = t(key);
    return v && v !== key ? v : def;
  };

  return (
    <main class="login-main">
      <form class="settings-card login-card" onSubmit={onSubmit}>
        <div class="login-brand">
          <img src="img/logo.png" alt="" style="height:28px;width:auto;" />
          <span class="app-wordmark">io-homecontrol</span>
        </div>
        <label class="label-title" for="login-password">
          {tr("login.password", "Password")}
        </label>
        <input
          id="login-password"
          ref={inputRef}
          type="password"
          name="password"
          autoComplete="current-password"
          class="s-input"
          value={password}
          onInput={(e) =>
            setPassword((e.currentTarget as HTMLInputElement).value)
          }
          maxLength={32}
        />
        {error ? (
          <p class="login-error" role="alert">
            {tr(error, fallback[error])}
          </p>
        ) : null}
        <button
          type="submit"
          class="s-btn primary"
          disabled={busy || !password}
        >
          {busy
            ? tr("login.busy", "Logging in…")
            : tr("login.submit", "Log in")}
        </button>
      </form>
    </main>
  );
}

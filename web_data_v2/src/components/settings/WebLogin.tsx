import { useState } from "preact/hooks";
import { AccordionHead } from "../AccordionHead";
import { useOtaKey } from "../../hooks/api/useOtaKey";
import { logout, refreshAuthStatus, useAuth } from "../../hooks/useAuth";
import { ToastType } from "../ToastProvider";
import { useToast } from "../../hooks/useToast";
import useI18n from "../../hooks/useI18n";

// Settings row for the optional web login. The password is the controller's access
// password, shared with the serial console (config_password), which is also the
// recovery path: `config_webauth --disable` or `config_password -d` over USB.

export function WebLoginSettings() {
  const showToast = useToast();
  const { t } = useI18n();
  // Dynamic texts are translated here (data-i18n is only applied to the static DOM)
  const tr = (key: string, def: string) => {
    const v = t(key);
    return v && v !== key ? v : def;
  };
  const otaKey = useOtaKey();
  const auth = useAuth();
  const status = auth.status;
  const minLen = status?.min_password_length ?? 8;

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);

  async function post(endpoint: string, body: unknown) {
    const res = await fetch(endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-OTA-Key": otaKey.data?.key ?? "",
      },
      body: JSON.stringify(body),
    });
    let message = "";
    try {
      message = (await res.json()).message ?? "";
    } catch {
      /* ignore */
    }
    return { ok: res.ok, status: res.status, message };
  }

  function errorToast(status: number) {
    if (status === 429) showToast("toast.login-too-fast", ToastType.ERROR);
    else if (status === 401) showToast("toast.wrong-password", ToastType.ERROR);
    else showToast("toast.error-saving-web-login", ToastType.ERROR);
  }

  async function changePassword(e: Event) {
    e.preventDefault();
    if (next.length < minLen) {
      showToast("toast.password-too-short", ToastType.ERROR);
      return;
    }
    if (next !== repeat) {
      showToast("toast.password-mismatch", ToastType.ERROR);
      return;
    }
    setBusy(true);
    try {
      const r = await post("/api/auth/password", { current, new: next });
      if (r.ok) {
        showToast("toast.password-changed", ToastType.SUCCESS);
        setCurrent("");
        setNext("");
        setRepeat("");
        await refreshAuthStatus();
      } else {
        errorToast(r.status);
      }
    } catch {
      errorToast(0);
    } finally {
      setBusy(false);
    }
  }

  async function setEnabled(enabled: boolean) {
    if (!current) {
      showToast("toast.enter-current-password", ToastType.ERROR);
      return;
    }
    setBusy(true);
    try {
      const r = await post("/api/auth/config", { enabled, password: current });
      if (r.ok) {
        showToast(
          enabled ? "toast.web-login-enabled" : "toast.web-login-disabled",
          ToastType.SUCCESS,
        );
        setCurrent("");
        await refreshAuthStatus();
      } else {
        errorToast(r.status);
      }
    } catch {
      errorToast(0);
    } finally {
      setBusy(false);
    }
  }

  const summaryKey = !status?.enabled
    ? "label.web-login-off"
    : status.enforced
      ? "label.web-login-on"
      : "label.web-login-weak";
  const summaryText = tr(
    summaryKey,
    !status?.enabled ? "Off" : status.enforced ? "On" : "On — weak password",
  );

  return (
    <div class="acc-row" data-help="web-login">
      <AccordionHead
        title="Web login"
        titleI18n="settings.row.web-login"
        summary={<span class="acc-sum-val">{summaryText}</span>}
      >
        <p class="auth-state">
          {tr(
            "label.web-login-info",
            "Protects this web interface with the controller password (the same password as the serial console). Locked out? Connect via USB and run config_webauth --disable.",
          )}
        </p>

        {status?.enabled && !status.enforced ? (
          <p class="warning-notive">
            {tr(
              "label.web-login-weak-notice",
              "⚠ Login is switched on but not enforced: set a password of at least 8 characters that is not the default.",
            )}
          </p>
        ) : null}

        <form onSubmit={changePassword}>
          <label class="label-title">
            {tr("label.current-password", "Current password")}
          </label>
          <input
            type="password"
            class="s-input"
            autoComplete="current-password"
            maxLength={32}
            value={current}
            onInput={(e) =>
              setCurrent((e.currentTarget as HTMLInputElement).value)
            }
            style="margin:4px 0 8px;"
          />
          <div style="display:flex;gap:6px;">
            <div style="flex:1;">
              <label class="label-title">
                {tr("label.new-password", "New password")}
              </label>
              <input
                type="password"
                class="s-input"
                autoComplete="new-password"
                minLength={minLen}
                maxLength={32}
                value={next}
                onInput={(e) =>
                  setNext((e.currentTarget as HTMLInputElement).value)
                }
                style="margin-top:4px;"
              />
            </div>
            <div style="flex:1;">
              <label class="label-title">
                {tr("label.repeat-password", "Repeat")}
              </label>
              <input
                type="password"
                class="s-input"
                autoComplete="new-password"
                maxLength={32}
                value={repeat}
                onInput={(e) =>
                  setRepeat((e.currentTarget as HTMLInputElement).value)
                }
                style="margin-top:4px;"
              />
            </div>
          </div>
          <div class="auth-actions">
            <button
              type="submit"
              class="s-btn"
              disabled={busy || !current || !next}
            >
              {tr("button.change-password", "Change password")}
            </button>
            {status?.enabled ? (
              <button
                type="button"
                class="s-btn danger"
                disabled={busy}
                onClick={() => void setEnabled(false)}
              >
                {tr("button.disable-web-login", "Disable login")}
              </button>
            ) : (
              <button
                type="button"
                class="s-btn primary"
                disabled={busy || !status?.password_strong}
                onClick={() => void setEnabled(true)}
              >
                {tr("button.enable-web-login", "Enable login")}
              </button>
            )}
            {status?.enforced ? (
              <button
                type="button"
                class="s-btn"
                disabled={busy}
                onClick={() => void logout()}
              >
                {tr("button.logout", "Log out")}
              </button>
            ) : null}
          </div>
          {!status?.enabled && !status?.password_strong ? (
            <p class="auth-state">
              {tr(
                "label.web-login-set-password-first",
                "First set a password of at least 8 characters (not the default) to enable login.",
              )}
            </p>
          ) : null}
        </form>
      </AccordionHead>
    </div>
  );
}

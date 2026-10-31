import { useEffect, useState } from "preact/hooks";
import { AccordionHead } from "../AccordionHead";
import { useOtaKey } from "../../hooks/api/useOtaKey";
import useI18n from "../../hooks/useI18n";
import { useToast } from "../../hooks/useToast";
import { ToastType } from "../ToastProvider";

// Settings row for the optional HTTPS web interface. The certificate is self-signed and
// created on the board itself; its SHA-256 fingerprint is shown so it can be compared with
// what the browser reports. Changes take effect after a reboot. Recovery over USB:
// `config_https --disable`.

type HttpsState = {
  available: boolean;
  enabled: boolean;
  active: boolean;
  fingerprint?: string;
  heap_free: number;
  heap_min: number;
  heap_largest: number;
};

const kb = (n: number) => `${Math.round(n / 1024)} KB`;

export function HttpsSettings() {
  const otaKey = useOtaKey();
  const showToast = useToast();
  const { t } = useI18n();
  const tr = (key: string, def: string) => {
    const v = t(key);
    return v && v !== key ? v : def;
  };

  const [state, setState] = useState<HttpsState | undefined>(undefined);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [newCert, setNewCert] = useState(false);
  const [unsupported, setUnsupported] = useState(false);

  async function load() {
    try {
      const res = await fetch("/api/https", {
        headers: { Accept: "application/json" },
        credentials: "same-origin",
        cache: "no-store",
      });
      if (res.ok) setState((await res.json()) as HttpsState);
      else if (res.status === 404) setUnsupported(true); // firmware without HTTPS support
    } catch {
      /* network hiccup: keep showing the placeholder */
    }
  }

  useEffect(() => {
    void load();
  }, []);

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
    return res;
  }

  function errorToast(status: number) {
    if (status === 429) showToast("toast.login-too-fast", ToastType.ERROR);
    else if (status === 401) showToast("toast.wrong-password", ToastType.ERROR);
    else showToast("toast.error-saving-https", ToastType.ERROR);
  }

  async function run(
    endpoint: string,
    body: unknown,
    okToast: string,
    certChanged = false,
  ) {
    if (!password) {
      showToast("toast.enter-current-password", ToastType.ERROR);
      return;
    }
    setBusy(true);
    try {
      const res = await post(endpoint, body);
      if (res.ok) {
        showToast(okToast, ToastType.SUCCESS);
        if (certChanged) setNewCert(true);
        setPassword("");
        await load();
      } else {
        errorToast(res.status);
      }
    } catch {
      errorToast(0);
    } finally {
      setBusy(false);
    }
  }

  async function rebootAndFollow() {
    if (!confirm(t("confirm.reboot"))) return;
    const target = state?.enabled ? "https:" : "http:";
    try {
      await post("/api/reboot", {});
      showToast("toast.rebooting", ToastType.SUCCESS);
    } catch {
      /* the board may drop the connection while rebooting */
    }
    // Give the board time to restart, then continue on the right scheme
    setTimeout(() => {
      window.location.href = `${target}//${window.location.hostname}/settings`;
    }, 20000);
  }

  if (unsupported || (state && !state.available)) return null;

  // Show the row straight away (no jump in the list) and fill it in once the board answers
  if (!state)
    return (
      <div class="acc-row" data-help="https">
        <AccordionHead
          title="HTTPS"
          titleI18n="settings.row.https"
          summary={<span class="acc-sum-val">…</span>}
        />
      </div>
    );

  const pending = state.enabled !== state.active || (newCert && state.active);
  const summary = state.active
    ? tr("label.https-on", "On")
    : tr("label.https-off", "Off");

  return (
    <div class="acc-row" data-help="https">
      <AccordionHead
        title="HTTPS"
        titleI18n="settings.row.https"
        summary={
          <span class="acc-sum-val">
            {pending
              ? `${summary} — ${tr("label.reboot-pending", "reboot required")}`
              : summary}
          </span>
        }
      >
        <p class="auth-state">
          {tr(
            "label.https-info",
            "Encrypts the connection to this web interface with a certificate created on this board. Your browser will warn about it once, because it is self-signed; compare the fingerprint below with what the browser shows. Locked out? Connect via USB and run config_https --disable.",
          )}
        </p>

        {state.fingerprint ? (
          <div style="margin:6px 0;">
            <span class="label-title">
              {tr(
                "label.https-fingerprint",
                "Certificate fingerprint (SHA-256)",
              )}
            </span>
            <div
              class="auth-state"
              style="font-family:var(--mono);font-size:10px;word-break:break-all;margin-top:2px;"
            >
              {state.fingerprint}
            </div>
          </div>
        ) : null}

        <p class="auth-state">
          {tr("label.https-memory", "Free memory")}: {kb(state.heap_free)} (
          {tr("label.https-memory-min", "lowest")} {kb(state.heap_min)},{" "}
          {tr("label.https-memory-block", "largest block")}{" "}
          {kb(state.heap_largest)})
        </p>

        {pending ? (
          <p class="warning-notive">
            {tr(
              "label.https-pending",
              "⚠ The change takes effect after a reboot.",
            )}
          </p>
        ) : null}

        <label class="label-title">
          {tr("label.current-password", "Current password")}
        </label>
        <input
          type="password"
          class="s-input"
          autoComplete="current-password"
          maxLength={32}
          value={password}
          onInput={(e) =>
            setPassword((e.currentTarget as HTMLInputElement).value)
          }
          style="margin:4px 0 8px;"
        />
        <div class="auth-actions">
          {state.enabled ? (
            <button
              type="button"
              class="s-btn danger"
              disabled={busy || !password}
              onClick={() =>
                void run(
                  "/api/https",
                  { enabled: false, password },
                  "toast.https-disabled",
                )
              }
            >
              {tr("button.disable-https", "Disable HTTPS")}
            </button>
          ) : (
            <button
              type="button"
              class="s-btn primary"
              disabled={busy || !password}
              onClick={() =>
                void run(
                  "/api/https",
                  { enabled: true, password },
                  "toast.https-enabled",
                )
              }
            >
              {tr("button.enable-https", "Enable HTTPS")}
            </button>
          )}
          {state.fingerprint ? (
            <button
              type="button"
              class="s-btn"
              disabled={busy || !password}
              onClick={() =>
                void run(
                  "/api/https/regenerate",
                  { password },
                  "toast.https-new-certificate",
                  true,
                )
              }
            >
              {tr("button.https-new-certificate", "New certificate")}
            </button>
          ) : null}
          {pending ? (
            <button
              type="button"
              class="s-btn"
              disabled={busy}
              onClick={() => void rebootAndFollow()}
            >
              {tr("button.reboot-now", "Reboot now")}
            </button>
          ) : null}
        </div>
      </AccordionHead>
    </div>
  );
}

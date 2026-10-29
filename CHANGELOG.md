# Changelog

## [Unreleased] — feature/web-auth

### Added
- **Optional web interface login** (off by default). Uses the controller access password (shared with the serial console). When enforced, all `/api/*` routes and the WebSocket require a session cookie (HttpOnly, SameSite=Strict, RAM-only sessions, 12 h idle / 7 day maximum) or a valid `X-OTA-Key` header for scripts. `GET /api/ota/key` is no longer readable without login once enforced.
- **Brute-force pacing**: after a failed password check, further checks are refused with HTTP 429 for 2 seconds (global, no hard lockout).
- New endpoints `/api/auth/status`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/config`, `/api/auth/password`.
- New CLI command `config_webauth [--enable|--disable|-r]`; `config_password -d` also switches web login off (recovery).
- Web UI: login screen and a "Web login" row under Settings → Security (enable/disable, change password, log out). Translations en/nl/de/fr.
- `CONFIG_HTTPD_WS_PRE_HANDSHAKE_CB_SUPPORT` enabled so the WebSocket upgrade can be checked against the session cookie.
- **Optional HTTPS** (off by default, applied after reboot): self-signed ECDSA P-256 certificate generated on the device (no key in the firmware), SAN with hostname, `hostname.local` and IP. No HTTP->HTTPS redirect (saves heap); falls back to HTTP if the TLS server cannot start. Session cookie gets `Secure`. Settings → Security → HTTPS shows the certificate fingerprint and free memory; `/api/https`, `/api/https/regenerate`; CLI `config_https [--enable|--disable|--regen|-r]`. Build: `CONFIG_ESP_HTTPS_SERVER_ENABLE`, `CONFIG_MBEDTLS_X509_CREATE_C`, `CONFIG_MBEDTLS_DYNAMIC_BUFFER`.
- **Restart diagnostics**: Settings → System → Uptime shows how long the board has been running, why it last started (power on, restart, crash, watchdog, brownout), the number of starts and — unless the power was cut — how long the previous run lasted and its lowest free memory. Kept in RTC memory + NVS, no extra heap. Also in `/api/info` (`uptime_s`, `reset_reason`, `boot_count`, `prev_uptime_s`, `prev_heap_min`, `heap_free`, `heap_min`).
- The pairing-log `BOOT` line now includes the start number, reason and previous-run data, and is written once the clock is set (max. 60 s wait) so it gets a real timestamp instead of `boot+6s`.
- **Snapshot builds** now get a version from the nearest release tag (`git describe`, e.g. `v2.1.11-3-gabc1234`) instead of the branch name, which showed as `v0.0.0` on the display.

## [Unreleased] — fix/web-ui-polish

### Fixed

#### Build
- **LittleFS partition overflow** — `CMakeLists.txt` now clears `web_staged/` before each reconfigure, preventing stale JS hash files and old web UI assets from accumulating and pushing the 450 KB LittleFS partition to capacity. Previously this caused mid-transfer TCP drops when serving assets.

#### Web UI — correctness
- **OTA key guard** — upload flows (firmware, web, pairing, remote wizard) now bail early with a user-visible error when the OTA key is not yet available, instead of sending an empty key.
- **OTA key input** — changed from `type="text"` to `type="password"` so the key is masked by default.
- **`r.ok` checks** — all `fetch()` calls that were missing a response-ok check (OTA key save, fallback AP, pairing start) now throw on non-2xx so the error toast fires correctly.
- **`FirmwareUpdater`** — added `TypeError` catch for the ESP32 TCP drop on reboot during OTA so the progress flow completes cleanly.
- **WiFi form** — password field is omitted from the POST body when left blank (prevents overwriting a saved password with an empty string); scan result keys are now stable (`ssid-idx`) to avoid Preact reconciliation warnings.
- **Network form** — added `name=` attributes on all inputs; added missing `dns2` field; DHCP state initialises from API data via `useEffect`; SNTP field is no longer incorrectly disabled when DHCP is on.
- **Backup** — `data?.success ?? true` default no longer incorrectly styles a fresh (no-data) state as an error.
- **IoSystemKey** — fixed stale closure in unmount cleanup by holding the OTA key in a `useRef`.
- **SoftwareUpdate** — removed non-functional "Check" button and raw i18n key `button.stable-only`.
- **Snapshot CI** — tag sanitisation (`/` → `-`) is now applied and exported via `GITHUB_ENV` in all three board jobs (heltec, t3s3, lora32); upload-artifact paths use the sanitised tag.

#### Web UI — flicker / performance
- **`useApi` flicker** — loading state is only reset when no cached data exists, so navigating back to a page shows the previous data instantly instead of a blank screen.
- **API response cache** — module-level `apiCache` in `useApi` survives component unmount/remount; pages restore from cache immediately on re-navigation.
- **i18n translation cache** — module-level `langCache` in `useI18n` means translation files are fetched once per session; subsequent mounts show translated text immediately without a key-flash.

#### Web UI — UX
- **MQTT status** — `useMqttConfig` now polls every 10 seconds so the connected/disconnected status stays live without a page reload.
- **Scroll outside layout** — wheel events on the margins outside the 600 px centred layout are now forwarded to `<main>`, so scrolling works anywhere on the page on wide desktops.
- **Missing i18n keys** — added `label.not-available`, `toast.syslog-saved`, and `toast.error-saving-syslog` to all four language files (en, nl, de, fr); these were previously showing their raw key strings.

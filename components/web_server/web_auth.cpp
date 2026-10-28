// Optional login for the web interface — see include/web_auth.h for the overview.
//
// Design notes
// - Sessions are kept in RAM only (a few slots). A reboot logs everybody out, which is fine
//   for an admin page and avoids flash wear.
// - Brute-force protection is a global pacing delay: after any failed password check, every
//   password check during the next WEB_AUTH_FAIL_DELAY_US is refused with 429. That caps
//   guessing at one attempt per 2 seconds without a hard lockout an attacker could keep alive
//   to shut the owner out. The httpd server runs in a single task, so we refuse instead of
//   sleeping (sleeping would freeze the whole web server).
// - CSRF: the session cookie is SameSite=Strict and every state-changing API call already
//   requires the custom X-OTA-Key header, which a cross-origin page cannot send.

#include "web_auth_internal.h"

#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "cJSON.h"

#include <string.h>
#include <string>

#include "MiscConfig.hpp"
#include "web_tls.h"
#include "esp_system.h"
#include "esp_heap_caps.h"

static const char *TAG = "web_auth";

#define WEB_AUTH_MAX_SESSIONS     4
#define WEB_AUTH_TOKEN_BYTES      16
#define WEB_AUTH_TOKEN_HEX_LEN    (WEB_AUTH_TOKEN_BYTES * 2)
#define WEB_AUTH_COOKIE_NAME      "iorts_sid"
#define WEB_AUTH_IDLE_TIMEOUT_US  (12LL * 3600 * 1000000)       // 12 h without activity
#define WEB_AUTH_MAX_AGE_S        (7 * 24 * 3600)                // 7 days absolute
#define WEB_AUTH_MAX_AGE_US       ((int64_t)WEB_AUTH_MAX_AGE_S * 1000000)
#define WEB_AUTH_FAIL_DELAY_US    (2LL * 1000000)                // 2 s pacing after a failure
#define WEB_AUTH_MAX_BODY         512

typedef struct
{
    bool in_use;
    char token[WEB_AUTH_TOKEN_HEX_LEN + 1];
    int64_t created_us;
    int64_t last_used_us;
} web_session_t;

static web_session_t s_sessions[WEB_AUTH_MAX_SESSIONS];
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static int64_t s_last_failure_us = 0;
static bool s_has_failure = false;

static bool s_secure_cookie = false;
static web_auth_api_key_check_fn s_api_key_check = nullptr;
static web_auth_sessions_changed_fn s_sessions_changed = nullptr;

// ─── Helpers ────────────────────────────────────────────────────────────────

static bool token_equals(const char *a, const char *b)
{
    // Constant time over the fixed token length
    uint8_t diff = 0;
    for (int i = 0; i < WEB_AUTH_TOKEN_HEX_LEN; i++)
        diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
    return diff == 0;
}

static bool session_expired(const web_session_t &s, int64_t now)
{
    return (now - s.last_used_us) > WEB_AUTH_IDLE_TIMEOUT_US || (now - s.created_us) > WEB_AUTH_MAX_AGE_US;
}

static void notify_sessions_changed()
{
    if (s_sessions_changed)
        s_sessions_changed();
}

/// Read the session cookie from the request. Returns false if absent or malformed.
static bool get_cookie_token(httpd_req_t *req, char *out /* WEB_AUTH_TOKEN_HEX_LEN + 1 */)
{
    char buf[WEB_AUTH_TOKEN_HEX_LEN + 8] = {};
    size_t len = sizeof(buf);
    if (httpd_req_get_cookie_val(req, WEB_AUTH_COOKIE_NAME, buf, &len) != ESP_OK)
        return false;
    if (strlen(buf) != WEB_AUTH_TOKEN_HEX_LEN)
        return false;
    memcpy(out, buf, WEB_AUTH_TOKEN_HEX_LEN + 1);
    return true;
}

/// Validate the session cookie and refresh its idle timer.
static bool has_valid_session(httpd_req_t *req)
{
    char token[WEB_AUTH_TOKEN_HEX_LEN + 1] = {};
    if (!get_cookie_token(req, token))
        return false;

    const int64_t now = esp_timer_get_time();
    bool valid = false;
    taskENTER_CRITICAL(&s_mux);
    for (auto &s : s_sessions)
    {
        if (!s.in_use)
            continue;
        if (session_expired(s, now))
        {
            s.in_use = false;
            continue;
        }
        if (token_equals(s.token, token))
        {
            s.last_used_us = now;
            valid = true;
        }
    }
    taskEXIT_CRITICAL(&s_mux);
    return valid;
}

/// Create a new session (evicting the least recently used one if all slots are taken)
/// and write its token into `out`.
static void create_session(char *out /* WEB_AUTH_TOKEN_HEX_LEN + 1 */)
{
    uint8_t rnd[WEB_AUTH_TOKEN_BYTES];
    esp_fill_random(rnd, sizeof(rnd));
    for (int i = 0; i < WEB_AUTH_TOKEN_BYTES; i++)
        snprintf(out + i * 2, 3, "%02x", rnd[i]);
    out[WEB_AUTH_TOKEN_HEX_LEN] = '\0';

    const int64_t now = esp_timer_get_time();
    taskENTER_CRITICAL(&s_mux);
    web_session_t *slot = nullptr;
    for (auto &s : s_sessions)
    {
        if (!s.in_use || session_expired(s, now)) { slot = &s; break; }
    }
    if (!slot)
    {
        slot = &s_sessions[0];
        for (auto &s : s_sessions)
            if (s.last_used_us < slot->last_used_us) slot = &s;
    }
    slot->in_use = true;
    memcpy(slot->token, out, WEB_AUTH_TOKEN_HEX_LEN + 1);
    slot->created_us = now;
    slot->last_used_us = now;
    taskEXIT_CRITICAL(&s_mux);
}

/// Remove the session belonging to the request's cookie (if any).
static void drop_request_session(httpd_req_t *req)
{
    char token[WEB_AUTH_TOKEN_HEX_LEN + 1] = {};
    if (!get_cookie_token(req, token))
        return;
    taskENTER_CRITICAL(&s_mux);
    for (auto &s : s_sessions)
        if (s.in_use && token_equals(s.token, token))
            s.in_use = false;
    taskEXIT_CRITICAL(&s_mux);
}

static void set_session_cookie(httpd_req_t *req, char *hdr_buf, size_t hdr_len, const char *token)
{
    // hdr_buf must stay valid until the response is sent (httpd keeps the pointer)
    snprintf(hdr_buf, hdr_len, WEB_AUTH_COOKIE_NAME "=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s",
             token, WEB_AUTH_MAX_AGE_S, s_secure_cookie ? "; Secure" : "");
    httpd_resp_set_hdr(req, "Set-Cookie", hdr_buf);
}

static void clear_session_cookie(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Set-Cookie", s_secure_cookie
        ? WEB_AUTH_COOKIE_NAME "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure"
        : WEB_AUTH_COOKIE_NAME "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
}

static esp_err_t send_json_status(httpd_req_t *req, const char *status, cJSON *obj)
{
    char *str = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_sendstr(req, str ? str : "{}");
    free(str);
    return ESP_OK;
}

static esp_err_t send_result_status(httpd_req_t *req, const char *status, bool success, const char *message)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(obj, "success", success);
    cJSON_AddStringToObject(obj, "message", message);
    return send_json_status(req, status, obj);
}

/// Read and parse a small JSON body. Returns nullptr on error (response already sent).
static cJSON *read_json_body(httpd_req_t *req)
{
    if (req->content_len == 0 || req->content_len > WEB_AUTH_MAX_BODY)
    {
        send_result_status(req, "400 Bad Request", false, "Invalid request body");
        return nullptr;
    }
    char buf[WEB_AUTH_MAX_BODY + 1] = {};
    size_t received = 0;
    while (received < req->content_len)
    {
        int r = httpd_req_recv(req, buf + received, req->content_len - received);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0)
        {
            send_result_status(req, "400 Bad Request", false, "Failed to read body");
            return nullptr;
        }
        received += r;
    }
    cJSON *json = cJSON_Parse(buf);
    memset(buf, 0, sizeof(buf)); // body may contain a password
    if (!json)
        send_result_status(req, "400 Bad Request", false, "Invalid JSON");
    return json;
}

/// Returns false (and sends 429) while the pacing delay after a failed password check is running.
static bool pacing_allows_attempt(httpd_req_t *req)
{
    const int64_t now = esp_timer_get_time();
    bool blocked;
    taskENTER_CRITICAL(&s_mux);
    blocked = s_has_failure && (now - s_last_failure_us) < WEB_AUTH_FAIL_DELAY_US;
    taskEXIT_CRITICAL(&s_mux);
    if (blocked)
    {
        httpd_resp_set_hdr(req, "Retry-After", "2");
        send_result_status(req, "429 Too Many Requests", false, "Too fast, please wait 2 seconds");
        return false;
    }
    return true;
}

static void record_failure()
{
    taskENTER_CRITICAL(&s_mux);
    s_last_failure_us = esp_timer_get_time();
    s_has_failure = true;
    taskEXIT_CRITICAL(&s_mux);
}

/// Check the password field of a parsed body against the access password, with pacing.
/// Sends the error response itself and returns false on failure.
static bool check_password_field(httpd_req_t *req, cJSON *json, const char *field)
{
    if (!pacing_allows_attempt(req))
        return false;
    cJSON *jPwd = cJSON_GetObjectItem(json, field);
    if (!cJSON_IsString(jPwd) || !Config::MiscConfig::CheckAccessPassword(jPwd->valuestring))
    {
        record_failure();
        ESP_LOGW(TAG, "Failed password check");
        send_result_status(req, "401 Unauthorized", false, "Invalid password");
        return false;
    }
    return true;
}

// ─── Public / internal API ──────────────────────────────────────────────────

void web_auth_invalidate_all_sessions(void)
{
    taskENTER_CRITICAL(&s_mux);
    for (auto &s : s_sessions)
        s.in_use = false;
    taskEXIT_CRITICAL(&s_mux);
    notify_sessions_changed();
}

void web_auth_set_secure_cookie(bool secure)
{
    s_secure_cookie = secure;
}

void web_auth_init(web_auth_api_key_check_fn api_key_check, web_auth_sessions_changed_fn sessions_changed)
{
    s_api_key_check = api_key_check;
    s_sessions_changed = sessions_changed;
    if (Config::MiscConfig::isWebAuthEnabled() && !Config::MiscConfig::isAccessPasswordStrong())
        ESP_LOGW(TAG, "Web login is switched on but the access password is weak or default — login NOT enforced");
    else
        ESP_LOGI(TAG, "Web login %s", web_auth_is_enforced() ? "enforced" : "disabled");
}

bool web_auth_is_enforced(void)
{
    return Config::MiscConfig::isWebAuthEffective();
}

bool web_auth_request_allowed(httpd_req_t *req)
{
    if (!web_auth_is_enforced())
        return true;
    if (has_valid_session(req))
        return true;
    return s_api_key_check && s_api_key_check(req);
}

esp_err_t web_auth_gate(httpd_req_t *req)
{
    auto handler = reinterpret_cast<esp_err_t (*)(httpd_req_t *)>(req->user_ctx);
    if (!web_auth_request_allowed(req))
    {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddBoolToObject(obj, "success", false);
        cJSON_AddBoolToObject(obj, "auth_required", true);
        cJSON_AddStringToObject(obj, "message", "Login required");
        return send_json_status(req, "401 Unauthorized", obj);
    }
    return handler(req);
}

esp_err_t web_auth_ws_pre_handshake(httpd_req_t *req)
{
    if (!web_auth_is_enforced() || has_valid_session(req))
        return ESP_OK;
    ESP_LOGW(TAG, "WebSocket rejected: no valid session");
    return ESP_FAIL;
}

// ─── Routes ─────────────────────────────────────────────────────────────────

/// Authorization for the settings routes below (they are registered outside the gate):
/// when login is enforced: a valid session or API key; otherwise the API key, like every other write.
static bool caller_may_change_settings(httpd_req_t *req)
{
    if (web_auth_is_enforced())
        return web_auth_request_allowed(req);
    return s_api_key_check && s_api_key_check(req);
}

// GET /api/auth/status — always reachable
static esp_err_t api_auth_status_get(httpd_req_t *req)
{
    const bool enforced = web_auth_is_enforced();
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(obj, "enabled", Config::MiscConfig::isWebAuthEnabled());
    cJSON_AddBoolToObject(obj, "enforced", enforced);
    cJSON_AddBoolToObject(obj, "authenticated", !enforced || has_valid_session(req));
    cJSON_AddBoolToObject(obj, "password_strong", Config::MiscConfig::isAccessPasswordStrong());
    cJSON_AddNumberToObject(obj, "min_password_length", Config::MiscConfig::STRONG_PASSWORD_MINSIZE);
    return send_json_status(req, "200 OK", obj);
}

// POST /api/auth/login  {"password": "..."}
static esp_err_t api_auth_login_post(httpd_req_t *req)
{
    if (!web_auth_is_enforced())
        return send_result_status(req, "200 OK", true, "Login not required");

    cJSON *json = read_json_body(req);
    if (!json)
        return ESP_OK;
    const bool ok = check_password_field(req, json, "password");
    cJSON_Delete(json);
    if (!ok)
        return ESP_OK;

    char token[WEB_AUTH_TOKEN_HEX_LEN + 1];
    char cookie[128];
    create_session(token);
    set_session_cookie(req, cookie, sizeof(cookie), token);
    ESP_LOGI(TAG, "Login successful");
    return send_result_status(req, "200 OK", true, "Logged in");
}

// POST /api/auth/logout
static esp_err_t api_auth_logout_post(httpd_req_t *req)
{
    drop_request_session(req);
    clear_session_cookie(req);
    notify_sessions_changed();
    return send_result_status(req, "200 OK", true, "Logged out");
}

// POST /api/auth/config  {"enabled": true|false, "password": "<current access password>"}
// Requires caller_may_change_settings() and always the current password.
static esp_err_t api_auth_config_post(httpd_req_t *req)
{
    if (!caller_may_change_settings(req))
        return send_result_status(req, "401 Unauthorized", false, "Unauthorized");

    cJSON *json = read_json_body(req);
    if (!json)
        return ESP_OK;
    cJSON *jEnabled = cJSON_GetObjectItem(json, "enabled");
    if (!cJSON_IsBool(jEnabled))
    {
        cJSON_Delete(json);
        return send_result_status(req, "400 Bad Request", false, "Missing 'enabled'");
    }
    const bool enable = cJSON_IsTrue(jEnabled);
    if (!check_password_field(req, json, "password"))
    {
        cJSON_Delete(json);
        return ESP_OK;
    }
    cJSON_Delete(json);

    if (enable && !Config::MiscConfig::isAccessPasswordStrong())
        return send_result_status(req, "400 Bad Request", false,
                                  "Set a password of at least 8 characters (not the default) first");

    if (Config::MiscConfig::SetWebAuthEnabled(enable) != ESP_OK)
        return send_result_status(req, "500 Internal Server Error", false, "Failed to save setting");

    web_auth_invalidate_all_sessions();
    ESP_LOGI(TAG, "Web login %s", enable ? "enabled" : "disabled");

    if (enable)
    {
        // Keep the user who switched it on logged in
        char token[WEB_AUTH_TOKEN_HEX_LEN + 1];
        char cookie[128];
        create_session(token);
        set_session_cookie(req, cookie, sizeof(cookie), token);
        return send_result_status(req, "200 OK", true, "Login enabled");
    }
    clear_session_cookie(req);
    return send_result_status(req, "200 OK", true, "Login disabled");
}

// POST /api/auth/password  {"current": "...", "new": "..."}
// Changes the access password (web + serial console). Requires gate/API key and the current password.
static esp_err_t api_auth_password_post(httpd_req_t *req)
{
    if (!caller_may_change_settings(req))
        return send_result_status(req, "401 Unauthorized", false, "Unauthorized");

    cJSON *json = read_json_body(req);
    if (!json)
        return ESP_OK;
    if (!check_password_field(req, json, "current"))
    {
        cJSON_Delete(json);
        return ESP_OK;
    }
    cJSON *jNew = cJSON_GetObjectItem(json, "new");
    std::string pwd = cJSON_IsString(jNew) ? jNew->valuestring : "";
    cJSON_Delete(json);

    if (pwd.length() < Config::MiscConfig::STRONG_PASSWORD_MINSIZE)
        return send_result_status(req, "400 Bad Request", false, "Password must be at least 8 characters");
    if (pwd.length() > Config::PASSWORD_MAXSIZE)
        return send_result_status(req, "400 Bad Request", false, "Password too long (max 32 characters)");
    if (pwd == CONFIG_CMD_LINE_MANAGEMENT_DEFAULT_PWD)
        return send_result_status(req, "400 Bad Request", false, "Do not use the default password");

    if (Config::MiscConfig::SetAccessPassword(pwd) != ESP_OK)
        return send_result_status(req, "500 Internal Server Error", false, "Failed to save password");
    pwd.assign(pwd.size(), '\0');

    // Log everybody else out; keep this browser logged in with a fresh session
    web_auth_invalidate_all_sessions();
    ESP_LOGI(TAG, "Access password changed via web");
    if (web_auth_is_enforced())
    {
        char token[WEB_AUTH_TOKEN_HEX_LEN + 1];
        char cookie[128];
        create_session(token);
        set_session_cookie(req, cookie, sizeof(cookie), token);
    }
    return send_result_status(req, "200 OK", true, "Password changed");
}

// ─── HTTPS settings ─────────────────────────────────────────────────────────

// GET /api/https — state of the optional HTTPS server (+ memory, to judge if the board copes with TLS)
static esp_err_t api_https_get(httpd_req_t *req)
{
    if (!web_auth_request_allowed(req))
        return send_result_status(req, "401 Unauthorized", false, "Login required");
    cJSON *obj = cJSON_CreateObject();
#if CONFIG_ESP_HTTPS_SERVER_ENABLE
    cJSON_AddBoolToObject(obj, "available", true);
#else
    cJSON_AddBoolToObject(obj, "available", false);
#endif
    cJSON_AddBoolToObject(obj, "enabled", Config::MiscConfig::isHttpsEnabled());
    cJSON_AddBoolToObject(obj, "active", web_tls_is_active());
    char fp[96];
    if (web_tls_get_fingerprint(fp, sizeof(fp)) == ESP_OK)
        cJSON_AddStringToObject(obj, "fingerprint", fp);
    cJSON_AddNumberToObject(obj, "heap_free", esp_get_free_heap_size());
    cJSON_AddNumberToObject(obj, "heap_min", esp_get_minimum_free_heap_size());
    cJSON_AddNumberToObject(obj, "heap_largest", heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    return send_json_status(req, "200 OK", obj);
}

// POST /api/https  {"enabled": true|false, "password": "<current access password>"} — applied after reboot
static esp_err_t api_https_post(httpd_req_t *req)
{
    if (!caller_may_change_settings(req))
        return send_result_status(req, "401 Unauthorized", false, "Unauthorized");
    cJSON *json = read_json_body(req);
    if (!json)
        return ESP_OK;
    cJSON *jEnabled = cJSON_GetObjectItem(json, "enabled");
    if (!cJSON_IsBool(jEnabled))
    {
        cJSON_Delete(json);
        return send_result_status(req, "400 Bad Request", false, "Missing 'enabled'");
    }
    const bool enable = cJSON_IsTrue(jEnabled);
    if (!check_password_field(req, json, "password"))
    {
        cJSON_Delete(json);
        return ESP_OK;
    }
    cJSON_Delete(json);
#if !CONFIG_ESP_HTTPS_SERVER_ENABLE
    if (enable)
        return send_result_status(req, "400 Bad Request", false, "HTTPS is not available in this firmware");
#endif
    if (enable)
    {
        // Create the certificate now, so its fingerprint can be checked before rebooting
        char fp[96];
        if (web_tls_get_fingerprint(fp, sizeof(fp)) != ESP_OK && web_tls_regenerate() != ESP_OK)
            return send_result_status(req, "500 Internal Server Error", false, "Failed to create certificate");
    }
    if (Config::MiscConfig::SetHttpsEnabled(enable) != ESP_OK)
        return send_result_status(req, "500 Internal Server Error", false, "Failed to save setting");
    ESP_LOGI(TAG, "HTTPS %s (after reboot)", enable ? "enabled" : "disabled");
    return send_result_status(req, "200 OK", true, "Saved — reboot to apply");
}

// POST /api/https/regenerate  {"password": "..."} — new key pair + certificate, applied after reboot
static esp_err_t api_https_regenerate_post(httpd_req_t *req)
{
    if (!caller_may_change_settings(req))
        return send_result_status(req, "401 Unauthorized", false, "Unauthorized");
    cJSON *json = read_json_body(req);
    if (!json)
        return ESP_OK;
    const bool ok = check_password_field(req, json, "password");
    cJSON_Delete(json);
    if (!ok)
        return ESP_OK;
    if (web_tls_regenerate() != ESP_OK)
        return send_result_status(req, "500 Internal Server Error", false, "Failed to create certificate");
    return send_result_status(req, "200 OK", true, "New certificate created — reboot to apply");
}

void web_auth_register_routes(httpd_handle_t server)
{
    struct { const char *uri; httpd_method_t method; esp_err_t (*handler)(httpd_req_t *); } routes[] = {
        {"/api/auth/status",   HTTP_GET,  api_auth_status_get},
        {"/api/auth/login",    HTTP_POST, api_auth_login_post},
        {"/api/auth/logout",   HTTP_POST, api_auth_logout_post},
        {"/api/auth/config",   HTTP_POST, api_auth_config_post},
        {"/api/auth/password", HTTP_POST, api_auth_password_post},
        {"/api/https",            HTTP_GET,  api_https_get},
        {"/api/https",            HTTP_POST, api_https_post},
        {"/api/https/regenerate", HTTP_POST, api_https_regenerate_post},
    };
    for (auto &r : routes)
    {
        httpd_uri_t u = {};
        u.uri = r.uri;
        u.method = r.method;
        u.handler = r.handler;
        httpd_register_uri_handler(server, &u);
    }
}

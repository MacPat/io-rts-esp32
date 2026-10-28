#pragma once

// Internal interface between web_server.cpp and web_auth.cpp (not part of the public component API).

#include "esp_http_server.h"
#include "web_auth.h"

/// @brief Returns true if the request carries a valid API key (X-OTA-Key header or _key query param).
/// Must not log anything when no key is present at all.
typedef bool (*web_auth_api_key_check_fn)(httpd_req_t *req);

/// @brief Called whenever sessions are dropped, so the web server can close WebSocket clients
/// (legitimate clients reconnect automatically with their still-valid cookie).
typedef void (*web_auth_sessions_changed_fn)(void);

/// @brief Wire the auth module to the web server. Call once before registering routes.
void web_auth_init(web_auth_api_key_check_fn api_key_check, web_auth_sessions_changed_fn sessions_changed);

/// @brief True when login is enforced (flag on AND strong password).
bool web_auth_is_enforced(void);

/// @brief True when the request may proceed: login not enforced, valid session cookie, or valid API key.
bool web_auth_request_allowed(httpd_req_t *req);

/// @brief Generic URI handler that checks authentication, then calls the real handler stored in req->user_ctx.
esp_err_t web_auth_gate(httpd_req_t *req);

/// @brief WebSocket pre-handshake callback: rejects the upgrade when login is enforced and no valid session.
esp_err_t web_auth_ws_pre_handshake(httpd_req_t *req);

/// @brief Mark the session cookie "Secure" (only sent over HTTPS). Call when the HTTPS server is active.
void web_auth_set_secure_cookie(bool secure);

/// @brief Register the /api/auth/* routes (these are reachable without being logged in).
void web_auth_register_routes(httpd_handle_t server);

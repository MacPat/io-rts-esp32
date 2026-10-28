#pragma once

// Optional login for the web interface.
//
// When enabled (MiscConfig::isWebAuthEffective()), every API route and the WebSocket
// require either a valid session cookie (obtained via POST /api/auth/login with the
// access password) or a valid X-OTA-Key header (API key for scripts). Static files stay
// public so the browser can render the login screen.
//
// The access password is the same one that protects the serial console
// (config_password), so the serial console doubles as the recovery path.

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Drop all active web sessions (e.g. after a password change or when login is switched off).
/// Safe to call from any task, also when the web interface is not compiled in.
void web_auth_invalidate_all_sessions(void);

#ifdef __cplusplus
}
#endif

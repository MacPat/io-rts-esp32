#pragma once

// Self-signed certificate for the optional HTTPS web interface.
//
// The key pair is generated on the device itself (ECDSA P-256), so every board has its own
// private key; nothing secret is compiled into the firmware. Certificate and key are stored
// as DER blobs in NVS (namespace "https").

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Generate a new key pair + self-signed certificate and store them in NVS.
/// Takes about a second on an ESP32. Applied to the server after the next reboot.
esp_err_t web_tls_regenerate(void);

/// @brief Remove the stored certificate and key (a new pair is generated when HTTPS starts).
esp_err_t web_tls_erase(void);

/// @brief Load certificate and key from NVS, generating them first when absent.
/// On success *cert_der and *key_der are malloc'ed buffers the caller must free().
esp_err_t web_tls_load_or_create(uint8_t **cert_der, size_t *cert_len, uint8_t **key_der, size_t *key_len);

/// @brief SHA-256 fingerprint of the stored certificate as "AB:CD:..." (95 chars + NUL).
/// @return ESP_OK, or ESP_ERR_NOT_FOUND when no certificate exists yet
esp_err_t web_tls_get_fingerprint(char *out, size_t out_len);

/// @brief True while the web server is actually serving HTTPS (set by the web server at start).
bool web_tls_is_active(void);
void web_tls_set_active(bool active);

#ifdef __cplusplus
}
#endif

// Self-signed certificate for the optional HTTPS web interface — see include/web_tls.h.

#include "web_tls.h"

#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_netif.h"
#include "nvs.h"

#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include "NetworkConfig.hpp"

static const char *TAG = "web_tls";

#define TLS_NVS_NAMESPACE  "https"
#define TLS_NVS_CERT       "cert"
#define TLS_NVS_KEY        "key"
#define TLS_CERT_BUF       1536
#define TLS_KEY_BUF        512

static bool s_active = false;

bool web_tls_is_active(void) { return s_active; }
void web_tls_set_active(bool active) { s_active = active; }

/// Hostname reduced to [A-Za-z0-9-] so it is safe in a distinguished name and as dnsName
static std::string safe_hostname()
{
    std::string in = Config::NetworkConfig::GetHostname();
    std::string out;
    for (char c : in)
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')
            out += c;
    if (out.empty())
        out = "io-rts-esp32";
    return out;
}

/// Current IPv4 address of the station or Ethernet interface (0 if not connected)
static uint32_t current_ipv4()
{
    const char *netif_keys[] = {"WIFI_STA_DEF", "ETH_DEF", nullptr};
    for (int i = 0; netif_keys[i]; i++)
    {
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey(netif_keys[i]);
        esp_netif_ip_info_t info;
        if (netif && esp_netif_get_ip_info(netif, &info) == ESP_OK && info.ip.addr != 0)
            return info.ip.addr; // network byte order
    }
    return 0;
}

static esp_err_t nvs_store(const uint8_t *cert, size_t cert_len, const uint8_t *key, size_t key_len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(TLS_NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK)
        return err;
    err = nvs_set_blob(h, TLS_NVS_CERT, cert, cert_len);
    if (err == ESP_OK)
        err = nvs_set_blob(h, TLS_NVS_KEY, key, key_len);
    if (err == ESP_OK)
        err = nvs_commit(h);
    nvs_close(h);
    return err;
}

static esp_err_t nvs_load(const char *name, uint8_t **buf, size_t *len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(TLS_NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK)
        return err == ESP_ERR_NVS_NOT_FOUND ? ESP_ERR_NOT_FOUND : err;
    size_t size = 0;
    err = nvs_get_blob(h, name, nullptr, &size);
    if (err == ESP_OK && size > 0)
    {
        *buf = (uint8_t *)malloc(size);
        if (!*buf)
            err = ESP_ERR_NO_MEM;
        else
        {
            err = nvs_get_blob(h, name, *buf, &size);
            if (err == ESP_OK)
                *len = size;
            else
            {
                free(*buf);
                *buf = nullptr;
            }
        }
    }
    else if (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND)
        err = ESP_ERR_NOT_FOUND;
    nvs_close(h);
    return err;
}

esp_err_t web_tls_regenerate(void)
{
    esp_err_t result = ESP_FAIL;
    psa_key_id_t key_id = 0;
    mbedtls_pk_context pk;
    mbedtls_x509write_cert crt;
    mbedtls_pk_init(&pk);
    mbedtls_x509write_crt_init(&crt);
    uint8_t *cert_buf = (uint8_t *)malloc(TLS_CERT_BUF);
    uint8_t *key_buf = (uint8_t *)malloc(TLS_KEY_BUF);
    int ret;
    int cert_len = 0, key_len = 0;

    const std::string host = safe_hostname();
    const std::string host_local = host + ".local";
    const std::string subject = "CN=" + host + ",O=io-rts-esp32";
    uint32_t ip = current_ipv4();
    uint8_t ip_bytes[4];
    memcpy(ip_bytes, &ip, 4); // already network byte order

    mbedtls_x509_san_list san_ip = {};
    mbedtls_x509_san_list san_local = {};
    mbedtls_x509_san_list san_host = {};

    uint8_t serial[16];
    esp_fill_random(serial, sizeof(serial));
    serial[0] = (serial[0] & 0x7F) | 0x40; // positive, no leading zero

    if (!cert_buf || !key_buf)
    {
        result = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    // 1. Key pair, generated inside PSA, then copied into a PK context for the writers
    {
        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attr, 256);
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        psa_status_t st = psa_generate_key(&attr, &key_id);
        psa_reset_key_attributes(&attr);
        if (st != PSA_SUCCESS)
        {
            ESP_LOGE(TAG, "psa_generate_key failed: %d", (int)st);
            goto cleanup;
        }
    }
    if ((ret = mbedtls_pk_copy_from_psa(key_id, &pk)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_pk_copy_from_psa failed: -0x%04x", -ret);
        goto cleanup;
    }

    // 2. Self-signed certificate
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &pk);
    mbedtls_x509write_crt_set_issuer_key(&crt, &pk);
    if ((ret = mbedtls_x509write_crt_set_subject_name(&crt, subject.c_str())) != 0 ||
        (ret = mbedtls_x509write_crt_set_issuer_name(&crt, subject.c_str())) != 0 ||
        (ret = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial))) != 0 ||
        // The device clock may not be set yet, so use a fixed window instead of "now"
        (ret = mbedtls_x509write_crt_set_validity(&crt, "20250101000000", "20491231235959")) != 0 ||
        (ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1)) != 0 ||
        (ret = mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE)) != 0)
    {
        ESP_LOGE(TAG, "certificate setup failed: -0x%04x", -ret);
        goto cleanup;
    }

    // Subject Alternative Names: hostname, hostname.local and the current IP address.
    // Browsers only accept a (trusted) certificate when the address you type is listed here.
    san_host.node.type = MBEDTLS_X509_SAN_DNS_NAME;
    san_host.node.san.unstructured_name.p = (unsigned char *)host.c_str();
    san_host.node.san.unstructured_name.len = host.size();
    san_local.node.type = MBEDTLS_X509_SAN_DNS_NAME;
    san_local.node.san.unstructured_name.p = (unsigned char *)host_local.c_str();
    san_local.node.san.unstructured_name.len = host_local.size();
    san_host.next = &san_local;
    if (ip != 0)
    {
        san_ip.node.type = MBEDTLS_X509_SAN_IP_ADDRESS;
        san_ip.node.san.unstructured_name.p = ip_bytes;
        san_ip.node.san.unstructured_name.len = sizeof(ip_bytes);
        san_local.next = &san_ip;
    }
    if ((ret = mbedtls_x509write_crt_set_subject_alternative_name(&crt, &san_host)) != 0)
    {
        ESP_LOGE(TAG, "SAN setup failed: -0x%04x", -ret);
        goto cleanup;
    }

    // 3. DER encode (the writers fill the buffer from the end)
    cert_len = mbedtls_x509write_crt_der(&crt, cert_buf, TLS_CERT_BUF);
    if (cert_len <= 0)
    {
        ESP_LOGE(TAG, "certificate encoding failed: -0x%04x", -cert_len);
        goto cleanup;
    }
    key_len = mbedtls_pk_write_key_der(&pk, key_buf, TLS_KEY_BUF);
    if (key_len <= 0)
    {
        ESP_LOGE(TAG, "key encoding failed: -0x%04x", -key_len);
        goto cleanup;
    }

    result = nvs_store(cert_buf + TLS_CERT_BUF - cert_len, cert_len, key_buf + TLS_KEY_BUF - key_len, key_len);
    if (result == ESP_OK)
        ESP_LOGI(TAG, "New HTTPS certificate generated for %s (%d bytes)", host.c_str(), cert_len);
    else
        ESP_LOGE(TAG, "Failed to store certificate: %s", esp_err_to_name(result));

cleanup:
    if (key_buf)
    {
        memset(key_buf, 0, TLS_KEY_BUF);
        free(key_buf);
    }
    free(cert_buf);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&pk);
    if (key_id)
        psa_destroy_key(key_id);
    return result;
}

esp_err_t web_tls_erase(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(TLS_NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK)
        return err;
    nvs_erase_key(h, TLS_NVS_CERT);
    nvs_erase_key(h, TLS_NVS_KEY);
    err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t web_tls_load_or_create(uint8_t **cert_der, size_t *cert_len, uint8_t **key_der, size_t *key_len)
{
    *cert_der = nullptr;
    *key_der = nullptr;
    for (int attempt = 0; attempt < 2; attempt++)
    {
        esp_err_t e1 = nvs_load(TLS_NVS_CERT, cert_der, cert_len);
        esp_err_t e2 = (e1 == ESP_OK) ? nvs_load(TLS_NVS_KEY, key_der, key_len) : e1;
        if (e1 == ESP_OK && e2 == ESP_OK)
            return ESP_OK;
        free(*cert_der);
        free(*key_der);
        *cert_der = nullptr;
        *key_der = nullptr;
        if (attempt == 0)
        {
            ESP_LOGI(TAG, "No HTTPS certificate stored yet, generating one");
            esp_err_t err = web_tls_regenerate();
            if (err != ESP_OK)
                return err;
        }
    }
    return ESP_FAIL;
}

esp_err_t web_tls_get_fingerprint(char *out, size_t out_len)
{
    if (out_len < 96)
        return ESP_ERR_INVALID_SIZE;
    uint8_t *der = nullptr;
    size_t len = 0;
    esp_err_t err = nvs_load(TLS_NVS_CERT, &der, &len);
    if (err != ESP_OK)
        return err;
    uint8_t hash[32];
    size_t hash_len = 0;
    psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, der, len, hash, sizeof(hash), &hash_len);
    free(der);
    if (st != PSA_SUCCESS || hash_len != sizeof(hash))
        return ESP_FAIL;
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 3, 4, i < 31 ? "%02X:" : "%02X", hash[i]);
    return ESP_OK;
}

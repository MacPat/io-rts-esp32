#pragma once

#include <string>

#include "esp_err.h"

namespace Config
{
    constexpr size_t PASSWORD_MAXSIZE = 32;
    
    class MiscConfig
    {
    public:
        /// @brief Delete access password in storage (reset to password defined at build in SDK configuration)
        static void ResetAccessPassword();

        /// @brief Check if there is an access password currently defined
        /// @return true if password is defined (not empty)
        static bool isAccessPasswordDefined();

        /// @brief Compare given password to access password in storage
        /// @param password access password to compare
        /// @return true if password is valid
        static bool CheckAccessPassword(const std::string &password);

        /// @brief Set access password to configuration storage
        /// @param password access password to store
        /// @return ESP_OK if configuration put to storage without error
        static esp_err_t SetAccessPassword(const std::string &password);

        /// @brief Get effective access password — NVS value if set, otherwise compile-time default
        /// @return current password
        static const std::string GetEffectiveAccessPassword();

        /// @brief Minimum length of the access password before web login may be enabled
        static constexpr size_t STRONG_PASSWORD_MINSIZE = 8;

        /// @brief Check if the access password is suitable to protect the web interface:
        /// at least STRONG_PASSWORD_MINSIZE characters and different from the build-time default
        /// @return true if the password is strong enough
        static bool isAccessPasswordStrong();

        /// @brief Check if web interface login has been switched on (stored flag only)
        /// @return true if the flag is set
        static bool isWebAuthEnabled();

        /// @brief Store the web interface login flag
        /// @param enabled true to require login on the web interface
        /// @return ESP_OK if stored without error
        static esp_err_t SetWebAuthEnabled(bool enabled);

        /// @brief Check if web interface login is actually enforced: flag set AND password strong.
        /// A weak/default password never protects the web interface, so login is only enforced
        /// when the password cannot be guessed from the public build defaults.
        /// @return true if login is enforced
        static bool isWebAuthEffective();

        /// @brief Check if HTTPS has been switched on for the web interface (applied at boot)
        /// @return true if the flag is set
        static bool isHttpsEnabled();

        /// @brief Store the HTTPS flag (takes effect after reboot)
        /// @param enabled true to serve the web interface over HTTPS
        /// @return ESP_OK if stored without error
        static esp_err_t SetHttpsEnabled(bool enabled);

    private:
        static const std::string GetAccessPassword();
    };

}
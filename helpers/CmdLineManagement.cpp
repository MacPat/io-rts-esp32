#include "CmdLineManagement.hpp"
#include "MiscConfig.hpp"
#include "web_auth.h"
#include "web_tls.h"
#include "NetworkConfig.hpp"

#include <string.h>
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"
#include "esp_console.h"
#include "esp_log.h"

using namespace Config;

static const char *TAG = "cmdline_mngt";
static IoRts::IoRtsManager *sIoRtsManager;
static esp_console_repl_t *sConsoleRepl;
static bool sLogin; // flag to synchronize login task

// ******************* REBOOT ********************

static int do_reboot_cmd(int argc, char **argv)
{
    esp_restart();
    return 0;
}

void register_reboot(void)
{
    const esp_console_cmd_t reboot_cmd = {
        .command = "reboot",
        .help = "Reboot ESP32",
        .hint = NULL,
        .func = &do_reboot_cmd,
        .argtable = NULL,
        .func_w_context = NULL,
        .context = NULL};

    ESP_ERROR_CHECK(esp_console_cmd_register(&reboot_cmd));
}

// ******************* LOGOUT ********************

static int do_logout_cmd(int argc, char **argv)
{
    sLogin = false;
    return 0;
}

void register_logout(void)
{
    const esp_console_cmd_t logout_cmd = {
        .command = "logout",
        .help = "Logout from ESP32 console",
        .hint = NULL,
        .func = &do_logout_cmd,
        .argtable = NULL,
        .func_w_context = NULL,
        .context = NULL};

    ESP_ERROR_CHECK(esp_console_cmd_register(&logout_cmd));
}

// ******************* PASSWORD CONFIG ********************

/// @brief Structure used by the 'config_password' command
static struct
{
    struct arg_lit *del;
    struct arg_str *password;
    struct arg_end *end;
} config_password_args;

static int do_config_password_cmd(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&config_password_args);
    if (nerrors != 0)
    {
        arg_print_errors(stderr, config_password_args.end, argv[0]);
        return 1;
    }
    if (config_password_args.del->count > 0)
    {
        MiscConfig::ResetAccessPassword();
        web_auth_invalidate_all_sessions();
        ESP_LOGI(TAG, "Password configuration restored to default values (web login switched off)");
    }
    else
    {
        esp_err_t err;
        // Set configuration
        if (config_password_args.password->count > 0)
        {
            err = MiscConfig::SetAccessPassword(config_password_args.password->sval[0]);
            if (err != ESP_OK)
            {
                ESP_LOGE(TAG, "Failed to set password to configuration storage! (%d)", err);
            }
            else
            {
                ESP_LOGI(TAG, "Password set to configuration storage.");
                web_auth_invalidate_all_sessions();
                if (MiscConfig::isWebAuthEnabled() && !MiscConfig::isAccessPasswordStrong())
                {
                    ESP_LOGW(TAG, "Password is shorter than %d characters or the default: web login is NOT enforced until a stronger password is set.",
                             (int)MiscConfig::STRONG_PASSWORD_MINSIZE);
                }
            }
        }
    }
    return 0;
}

void register_config_password(void)
{
    config_password_args.del = arg_lit0("d", "delete", "Delete current configuration in storage (no other argument required)");
    config_password_args.password = arg_str0(NULL, "pass", "<password>", "Password (up to 32 characters)");
    config_password_args.end = arg_end(2);

    const esp_console_cmd_t config_password_cmd = {
        .command = "config_password",
        .help = "Configure console password (change is applied immediately)",
        .hint = NULL,
        .func = &do_config_password_cmd,
        .argtable = &config_password_args,
        .func_w_context = NULL,
        .context = NULL};

    ESP_ERROR_CHECK(esp_console_cmd_register(&config_password_cmd));
}

// ******************* WEB LOGIN CONFIG ********************

/// @brief Structure used by the 'config_webauth' command
static struct
{
    struct arg_lit *read;
    struct arg_lit *enable;
    struct arg_lit *disable;
    struct arg_end *end;
} config_webauth_args;

static int do_config_webauth_cmd(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&config_webauth_args);
    if (nerrors != 0)
    {
        arg_print_errors(stderr, config_webauth_args.end, argv[0]);
        return 1;
    }
    if (config_webauth_args.enable->count > 0 && config_webauth_args.disable->count > 0)
    {
        ESP_LOGE(TAG, "Use either --enable or --disable");
        return 1;
    }
    if (config_webauth_args.enable->count > 0)
    {
        if (!MiscConfig::isAccessPasswordStrong())
        {
            ESP_LOGE(TAG, "Set a password of at least %d characters (not the default) with config_password first.",
                     (int)MiscConfig::STRONG_PASSWORD_MINSIZE);
            return 1;
        }
        if (MiscConfig::SetWebAuthEnabled(true) != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to store web login setting");
            return 1;
        }
        web_auth_invalidate_all_sessions();
        ESP_LOGI(TAG, "Web login enabled (applied immediately).");
    }
    else if (config_webauth_args.disable->count > 0)
    {
        if (MiscConfig::SetWebAuthEnabled(false) != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to store web login setting");
            return 1;
        }
        web_auth_invalidate_all_sessions();
        ESP_LOGI(TAG, "Web login disabled (applied immediately).");
    }
    ESP_LOGI(TAG, "Web login: switched %s, %s", MiscConfig::isWebAuthEnabled() ? "on" : "off",
             MiscConfig::isWebAuthEffective() ? "enforced" : "not enforced");
    return 0;
}

void register_config_webauth(void)
{
    config_webauth_args.read = arg_lit0("r", "read", "Show current web login state");
    config_webauth_args.enable = arg_lit0(NULL, "enable", "Require login on the web interface (needs a strong password)");
    config_webauth_args.disable = arg_lit0(NULL, "disable", "Switch web interface login off (recovery)");
    config_webauth_args.end = arg_end(3);

    const esp_console_cmd_t config_webauth_cmd = {
        .command = "config_webauth",
        .help = "Configure login on the web interface (uses the console password)",
        .hint = NULL,
        .func = &do_config_webauth_cmd,
        .argtable = &config_webauth_args,
        .func_w_context = NULL,
        .context = NULL};

    ESP_ERROR_CHECK(esp_console_cmd_register(&config_webauth_cmd));
}

// ******************* HTTPS CONFIG ********************

/// @brief Structure used by the 'config_https' command
static struct
{
    struct arg_lit *read;
    struct arg_lit *enable;
    struct arg_lit *disable;
    struct arg_lit *regen;
    struct arg_end *end;
} config_https_args;

static int do_config_https_cmd(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&config_https_args);
    if (nerrors != 0)
    {
        arg_print_errors(stderr, config_https_args.end, argv[0]);
        return 1;
    }
    if (config_https_args.enable->count > 0 && config_https_args.disable->count > 0)
    {
        ESP_LOGE(TAG, "Use either --enable or --disable");
        return 1;
    }
    if (config_https_args.regen->count > 0)
    {
        if (web_tls_regenerate() != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to create a new certificate");
            return 1;
        }
        ESP_LOGI(TAG, "New certificate created (applied after reboot).");
    }
    if (config_https_args.enable->count > 0 || config_https_args.disable->count > 0)
    {
        const bool enable = config_https_args.enable->count > 0;
        if (MiscConfig::SetHttpsEnabled(enable) != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to store HTTPS setting");
            return 1;
        }
        ESP_LOGI(TAG, "HTTPS %s (applied after reboot).", enable ? "enabled" : "disabled");
    }
    char fp[96];
    ESP_LOGI(TAG, "HTTPS: switched %s, currently %s", MiscConfig::isHttpsEnabled() ? "on" : "off",
             web_tls_is_active() ? "active" : "not active");
    if (web_tls_get_fingerprint(fp, sizeof(fp)) == ESP_OK)
        ESP_LOGI(TAG, "Certificate SHA-256: %s", fp);
    return 0;
}

void register_config_https(void)
{
    config_https_args.read = arg_lit0("r", "read", "Show HTTPS state and certificate fingerprint");
    config_https_args.enable = arg_lit0(NULL, "enable", "Serve the web interface over HTTPS (after reboot)");
    config_https_args.disable = arg_lit0(NULL, "disable", "Back to plain HTTP (after reboot, recovery)");
    config_https_args.regen = arg_lit0(NULL, "regen", "Create a new key pair and certificate (after reboot)");
    config_https_args.end = arg_end(4);

    const esp_console_cmd_t config_https_cmd = {
        .command = "config_https",
        .help = "Configure HTTPS for the web interface (self-signed certificate created on the device)",
        .hint = NULL,
        .func = &do_config_https_cmd,
        .argtable = &config_https_args,
        .func_w_context = NULL,
        .context = NULL};

    ESP_ERROR_CHECK(esp_console_cmd_register(&config_https_cmd));
}

// ******************* Misc Register commands ********************

void register_misc_cmdline_tools()
{
    register_reboot();
    register_logout();
    register_config_password();
    register_config_webauth();
    register_config_https();
}

// ******************* LOGIN ********************

/// @brief Task to manage login
/// @param arg currently not used
static void cmd_line_task(void *arg)
{
    int32_t retry_counter = 0; // retry counter for failed attempts to login
    while (true)
    {
        bool login_success = false;
        if (MiscConfig::isAccessPasswordDefined())
        {
            // Read password
            linenoiseHistorySetMaxLen(0);
            char *input = linenoise("Enter password: ");
            if (input == NULL)
            {
                printf("Failed to read password\n");
            }
            else
            {
                std::string password(input);
                linenoiseFree(input);
                if (MiscConfig::CheckAccessPassword(password))
                {
                    printf("Login success!\n");
                    retry_counter = 0;
                    login_success = true;
                }
                else
                {
                    retry_counter++;
                    int32_t penalty = 2 * retry_counter;
                    printf("Login failed! %ld attempts failed, %ld seconds penalty!\n", retry_counter, penalty);
                    vTaskDelay(pdMS_TO_TICKS(penalty * 1000));
                }
            }
        }
        else
        {
            login_success = true;
        }
        if (login_success)
        {
            init_cmdline_tools();
            sLogin = true;
            while (sLogin) vTaskDelay(pdMS_TO_TICKS(1000)); // wait for logout
            vTaskDelay(pdMS_TO_TICKS(100));
            // Remove command line tools
            esp_console_stop_repl(sConsoleRepl);
            // Reinit console (deinit done by esp_console_stop_repl)
            init_console();
        }
    }
    return;
}

// ******************* INIT ********************

void init_console()
{
    // Initialize Command line tools
    sConsoleRepl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = "io-rts-esp32>";

    // install console REPL environment
#if CONFIG_ESP_CONSOLE_UART
    esp_console_dev_uart_config_t uart_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&uart_config, &repl_config, &sConsoleRepl));
#elif CONFIG_ESP_CONSOLE_USB_CDC
    esp_console_dev_usb_cdc_config_t cdc_config = ESP_CONSOLE_DEV_CDC_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_cdc(&cdc_config, &repl_config, &sConsoleRepl));
#elif CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    esp_console_dev_usb_serial_jtag_config_t usbjtag_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&usbjtag_config, &repl_config, &sConsoleRepl));
#endif
}

void init_cmdline(IoRts::IoRtsManager *io_rts_manager)
{
    sIoRtsManager = io_rts_manager;
    sConsoleRepl = NULL;
    init_console();
    // launch login task
    xTaskCreate(cmd_line_task, "process_log_task", 4096, NULL, tskIDLE_PRIORITY, NULL);
}

void init_cmdline_tools()
{
    if (sIoRtsManager) {
        register_io_cmdline_tools(sIoRtsManager);
    }
    register_misc_cmdline_tools();
    register_network_config_cmdline_tools();
    register_mqtt_config_cmdline_tools();
    register_syslog_config_cmdline_tools();

    printf("\n ==============================================================\n");
    printf(" |            Steps to Use io-rts-esp32                       |\n");
    printf(" |                                                            |\n");
    printf(" |  Try 'help' to check all supported commands                |\n");
    printf(" |  Try TAB for commands auto-completion                      |\n");
    printf(" |                                                            |\n");
    printf(" ==============================================================\n\n");

    // start console REPL
    ESP_ERROR_CHECK(esp_console_start_repl(sConsoleRepl));
}

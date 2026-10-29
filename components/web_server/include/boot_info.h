#pragma once

// Restart diagnostics: why the board last restarted, how long it had been running and how low
// its free memory went before that, plus a boot counter. Costs no heap: the "previous run" data
// lives in RTC memory that survives a restart (but not a power cut), the counter lives in NVS.

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *reason;        ///< short code: power_on, software, crash, task_watchdog, ...
    uint32_t boot_count;       ///< number of starts since the counter was introduced
    bool prev_valid;           ///< false after a power cut (RTC memory is lost then)
    uint32_t prev_uptime_s;    ///< how long the previous run lasted (last sample, ≤ 5 s off)
    uint32_t prev_heap_min;    ///< lowest free heap seen during the previous run
} boot_info_t;

/// @brief Read the reset reason and previous-run data. Call once, early in app_main.
void boot_info_init(void);

/// @brief Record uptime and minimum free heap in RTC memory. Call every few seconds.
void boot_info_sample(void);

/// @brief Writes the BOOT line to the pairing log once the clock is set (or after 60 s).
/// Call from a periodic loop; returns true once done.
bool boot_info_log_boot_when_ready(void);

const boot_info_t *boot_info_get(void);

/// @brief Seconds since this start.
uint32_t boot_info_uptime_s(void);

#ifdef __cplusplus
}
#endif

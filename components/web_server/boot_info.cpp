// Restart diagnostics — see include/boot_info.h.

#include "boot_info.h"

#include <stdio.h>
#include <time.h>

#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs.h"

#include "pair_log.h"

static const char *TAG = "boot_info";

#define BOOT_INFO_MAGIC 0x10B0071Fu

// Survives software restarts, crashes and watchdog resets; garbage after a power cut,
// hence the magic + check value.
typedef struct {
    uint32_t magic;
    uint32_t uptime_s;
    uint32_t heap_min;
    uint32_t check;
} rtc_record_t;

static RTC_NOINIT_ATTR rtc_record_t s_rtc;

static boot_info_t s_info = {"unknown", 0, false, 0, 0};
static bool s_logged = false;

static uint32_t record_check(const rtc_record_t *r)
{
    return r->magic ^ (r->uptime_s * 2654435761u) ^ (r->heap_min + 0x5A5A5A5Au);
}

static const char *reason_code(esp_reset_reason_t r)
{
    switch (r)
    {
    case ESP_RST_POWERON:   return "power_on";
    case ESP_RST_EXT:       return "external";
    case ESP_RST_SW:        return "software";
    case ESP_RST_PANIC:     return "crash";
    case ESP_RST_INT_WDT:   return "interrupt_watchdog";
    case ESP_RST_TASK_WDT:  return "task_watchdog";
    case ESP_RST_WDT:       return "watchdog";
    case ESP_RST_DEEPSLEEP: return "deep_sleep";
    case ESP_RST_BROWNOUT:  return "brownout";
    case ESP_RST_SDIO:      return "sdio";
    default:                return "unknown";
    }
}

uint32_t boot_info_uptime_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000LL);
}

void boot_info_init(void)
{
    esp_reset_reason_t r = esp_reset_reason();
    s_info.reason = reason_code(r);

    if (r != ESP_RST_POWERON && r != ESP_RST_BROWNOUT &&
        s_rtc.magic == BOOT_INFO_MAGIC && s_rtc.check == record_check(&s_rtc))
    {
        s_info.prev_valid = true;
        s_info.prev_uptime_s = s_rtc.uptime_s;
        s_info.prev_heap_min = s_rtc.heap_min;
    }

    nvs_handle_t h;
    if (nvs_open("bootinfo", NVS_READWRITE, &h) == ESP_OK)
    {
        uint32_t n = 0;
        nvs_get_u32(h, "count", &n);
        s_info.boot_count = n + 1;
        nvs_set_u32(h, "count", s_info.boot_count);
        nvs_commit(h);
        nvs_close(h);
    }

    s_rtc.magic = BOOT_INFO_MAGIC;
    s_rtc.uptime_s = 0;
    s_rtc.heap_min = (uint32_t)esp_get_free_heap_size();
    s_rtc.check = record_check(&s_rtc);

    if (s_info.prev_valid)
        ESP_LOGI(TAG, "Start #%u, reason %s, previous run %us, lowest free heap %u",
                 (unsigned)s_info.boot_count, s_info.reason,
                 (unsigned)s_info.prev_uptime_s, (unsigned)s_info.prev_heap_min);
    else
        ESP_LOGI(TAG, "Start #%u, reason %s", (unsigned)s_info.boot_count, s_info.reason);
}

void boot_info_sample(void)
{
    s_rtc.uptime_s = boot_info_uptime_s();
    s_rtc.heap_min = (uint32_t)esp_get_minimum_free_heap_size();
    s_rtc.check = record_check(&s_rtc);
}

bool boot_info_log_boot_when_ready(void)
{
    if (s_logged)
        return true;
    // Wait for SNTP so the entry gets a real timestamp, but don't wait forever (no internet)
    if (time(nullptr) < 1000000000L && boot_info_uptime_s() < 60)
        return false;

    char line[112];
    if (s_info.prev_valid)
        snprintf(line, sizeof(line), "BOOT #%u reason=%s prev_uptime=%us prev_heap_min=%uKB",
                 (unsigned)s_info.boot_count, s_info.reason,
                 (unsigned)s_info.prev_uptime_s, (unsigned)(s_info.prev_heap_min / 1024));
    else
        snprintf(line, sizeof(line), "BOOT #%u reason=%s", (unsigned)s_info.boot_count, s_info.reason);
    pair_log_append(line);
    s_logged = true;
    return true;
}

const boot_info_t *boot_info_get(void)
{
    return &s_info;
}

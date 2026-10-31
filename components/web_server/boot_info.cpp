// Restart diagnostics — see include/boot_info.h.

#include "boot_info.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"

#include "pair_log.h"

static const char *TAG = "boot_info";

#define BOOT_INFO_MAGIC 0x10B00720u // changed whenever rtc_record_t changes

#define HEAP_LOG_FIRST_S    600   // first memory line 10 minutes after start (baseline)
#define HEAP_LOG_INTERVAL_S 3600  // then every hour

// Survives software restarts, crashes and watchdog resets; garbage after a power cut,
// hence the magic + check value.
typedef struct {
    uint32_t magic;
    uint32_t uptime_s;
    uint32_t heap_min;
    // Last failed memory allocation in this run (written by the heap's failure hook)
    uint32_t fail_count;
    uint32_t fail_size;
    uint32_t fail_free;
    uint32_t fail_uptime_s;
    char fail_task[BOOT_INFO_TASK_NAME_LEN];
    uint32_t check;
} rtc_record_t;

static RTC_NOINIT_ATTR rtc_record_t s_rtc;

static boot_info_t s_info = {};
static bool s_logged = false;
static uint32_t s_next_heap_log_s = HEAP_LOG_FIRST_S;

static uint32_t record_check(const rtc_record_t *r)
{
    const uint32_t *w = (const uint32_t *)r;
    uint32_t h = 0x5A5A5A5Au;
    for (size_t i = 0; i < offsetof(rtc_record_t, check) / sizeof(uint32_t); i++)
        h = (h ^ w[i]) * 16777619u;
    return h;
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

// Called by the heap allocator whenever an allocation fails. Must not allocate or block.
static void alloc_failed_hook(size_t size, uint32_t caps, const char *function_name)
{
    (void)caps;
    (void)function_name;
    s_rtc.fail_count++;
    s_rtc.fail_size = (uint32_t)size;
    s_rtc.fail_free = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    s_rtc.fail_uptime_s = (uint32_t)(esp_timer_get_time() / 1000000LL);
    const char *name = "?";
    if (!xPortInIsrContext() && xTaskGetSchedulerState() != taskSCHEDULER_NOT_STARTED)
    {
        const char *n = pcTaskGetName(nullptr);
        if (n)
            name = n;
    }
    strncpy(s_rtc.fail_task, name, sizeof(s_rtc.fail_task) - 1);
    s_rtc.fail_task[sizeof(s_rtc.fail_task) - 1] = '\0';
    s_rtc.check = record_check(&s_rtc);
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
        s_info.prev_fail_count = s_rtc.fail_count;
        if (s_rtc.fail_count > 0)
        {
            s_info.prev_fail_size = s_rtc.fail_size;
            s_info.prev_fail_free = s_rtc.fail_free;
            s_info.prev_fail_uptime_s = s_rtc.fail_uptime_s;
            memcpy(s_info.prev_fail_task, s_rtc.fail_task, sizeof(s_info.prev_fail_task));
            s_info.prev_fail_task[sizeof(s_info.prev_fail_task) - 1] = '\0';
        }
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

    memset(&s_rtc, 0, sizeof(s_rtc));
    s_rtc.magic = BOOT_INFO_MAGIC;
    s_rtc.heap_min = (uint32_t)esp_get_free_heap_size();
    s_rtc.check = record_check(&s_rtc);

    heap_caps_register_failed_alloc_callback(alloc_failed_hook);

    if (s_info.prev_valid)
        ESP_LOGI(TAG, "Start #%u, reason %s, previous run %us, lowest free heap %u, failed allocations %u",
                 (unsigned)s_info.boot_count, s_info.reason, (unsigned)s_info.prev_uptime_s,
                 (unsigned)s_info.prev_heap_min, (unsigned)s_info.prev_fail_count);
    else
        ESP_LOGI(TAG, "Start #%u, reason %s", (unsigned)s_info.boot_count, s_info.reason);
}

void boot_info_sample(void)
{
    s_rtc.uptime_s = boot_info_uptime_s();
    s_rtc.heap_min = (uint32_t)esp_get_minimum_free_heap_size();
    s_rtc.check = record_check(&s_rtc);
}

uint32_t boot_info_fail_count(void)
{
    return s_rtc.fail_count;
}

bool boot_info_log_boot_when_ready(void)
{
    if (s_logged)
        return true;
    // Wait for SNTP so the entry gets a real timestamp, but don't wait forever (no internet)
    if (time(nullptr) < 1000000000L && boot_info_uptime_s() < 60)
        return false;

    char line[200];
    int n;
    if (s_info.prev_valid)
        n = snprintf(line, sizeof(line), "BOOT #%u reason=%s prev_uptime=%us prev_heap_min=%uKB",
                     (unsigned)s_info.boot_count, s_info.reason,
                     (unsigned)s_info.prev_uptime_s, (unsigned)(s_info.prev_heap_min / 1024));
    else
        n = snprintf(line, sizeof(line), "BOOT #%u reason=%s", (unsigned)s_info.boot_count, s_info.reason);
    if (s_info.prev_valid && s_info.prev_fail_count > 0 && n > 0 && n < (int)sizeof(line))
        snprintf(line + n, sizeof(line) - n, " alloc_fail=%u last=%uB task=%s free=%uB at=%us",
                 (unsigned)s_info.prev_fail_count, (unsigned)s_info.prev_fail_size, s_info.prev_fail_task,
                 (unsigned)s_info.prev_fail_free, (unsigned)s_info.prev_fail_uptime_s);
    pair_log_append(line);
    s_logged = true;
    return true;
}

void boot_info_log_heap_periodic(void)
{
    uint32_t up = boot_info_uptime_s();
    if (up < s_next_heap_log_s)
        return;
    s_next_heap_log_s = up + HEAP_LOG_INTERVAL_S;
    char line[112];
    snprintf(line, sizeof(line), "HEAP up=%us free=%uKB min=%uKB largest=%uKB alloc_fail=%u",
             (unsigned)up,
             (unsigned)(esp_get_free_heap_size() / 1024),
             (unsigned)(esp_get_minimum_free_heap_size() / 1024),
             (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT) / 1024),
             (unsigned)s_rtc.fail_count);
    pair_log_append(line);
}

const boot_info_t *boot_info_get(void)
{
    return &s_info;
}

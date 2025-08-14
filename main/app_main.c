#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"

void app_main(void)
{
    uint32_t count = 0;
    while (1) {
        ESP_LOGI("main", "count: %lu", count++);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

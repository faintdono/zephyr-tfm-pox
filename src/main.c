/*
 * Copyright (c) 2019,2020 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/logging/log.h>

#include "tfm_ns_interface.h"
#include "psa_attestation.h"
#include "util_app_cfg.h"
#include "util_app_log.h"
#include "util_sformat.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

/* Create an instance of the system config struct for the application. */
static struct cfg_data cfg;

int main(void)
{
    pox_test();
    return 0;
}

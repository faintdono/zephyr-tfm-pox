/*
 * Copyright (c) 2019,2020 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <stdio.h>
#include <zephyr/logging/log.h>

#include "psa/initial_attestation.h"
#include "psa_attestation.h"
#include "util_sformat.h"
#include "util_app_log.h"

LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);


psa_status_t att_get_iat(uint8_t *ch_buffer, uint32_t ch_sz,
                         uint8_t *token_buffer, uint32_t *token_sz)
{
    psa_status_t err = PSA_SUCCESS;
    uint32_t sys_token_sz;
    size_t token_buf_size = ATT_MAX_TOKEN_SIZE;

    /* Call with bigger challenge object than allowed */

    /*
     * First determine how large the token is on this system.
     * We don't need to compare with the size of ATT_MAX_TOKEN_SIZE here
     * since a check will be made in 'psa_initial_attest_get_token' and the
     * error return code will indicate a mismatch.
     */
    switch (ch_sz)
    {
    case 32:
        err = psa_initial_attest_get_token(
            ch_buffer,
            PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32,
            token_buffer,
            token_buf_size,
            &sys_token_sz);
        break;
    case 48:
        err = psa_initial_attest_get_token(
            ch_buffer,
            PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48,
            token_buffer,
            token_buf_size,
            &sys_token_sz);
        break;
    case 64:
        err = psa_initial_attest_get_token(
            ch_buffer,
            PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64,
            token_buffer,
            token_buf_size,
            &sys_token_sz);
        break;
    default:
        err = -EINVAL;
        break;
    }
    if (err)
    {
        goto err;
    }

    LOG_INF("att: System IAT size is: %u bytes.", sys_token_sz);

    /* Request the initial attestation token w/the challenge data. */
    LOG_INF("att: Requesting IAT with %u byte challenge.", ch_sz);
    err = psa_initial_attest_get_token(
        ch_buffer,    /* Challenge/nonce input buffer. */
        ch_sz,        /* Challenge size (32, 48 or 64). */
        token_buffer, /* Token output buffer. */
        token_buf_size,
        token_sz /* Post exec output token size. */
    );
    LOG_INF("att: IAT data received: %u bytes.", *token_sz);

err:
    /* Log any eventual errors via app_log */
    return err ? al_psa_status(err, __func__) : err;
}

psa_status_t att_get_pox(uintptr_t *faddr, uint8_t *ch_buffer, uint32_t ch_sz,
                         uint8_t *token_buffer, uint32_t *token_sz)
{
    psa_status_t err = PSA_SUCCESS;
    uint32_t sys_token_sz;
    size_t token_buf_size = ATT_MAX_TOKEN_SIZE;

    /* Call with bigger challenge object than allowed */

    /*
     * First determine how large the token is on this system.
     * We don't need to compare with the size of ATT_MAX_TOKEN_SIZE here
     * since a check will be made in 'psa_initial_attest_get_token' and the
     * error return code will indicate a mismatch.
     */
    switch (ch_sz)
    {
    case 32:
        err = psa_proof_of_execution_get_token(
            faddr,
            ch_buffer,
            PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32,
            token_buffer,
            token_buf_size,
            &sys_token_sz);
        break;
    case 48:
        err = psa_proof_of_execution_get_token(
            faddr,
            ch_buffer,
            PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48,
            token_buffer,
            token_buf_size,
            &sys_token_sz);
        break;
    case 64:
        err = psa_proof_of_execution_get_token(
            faddr,
            ch_buffer,
            PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64,
            token_buffer,
            token_buf_size,
            &sys_token_sz);
        break;
    default:
        err = -EINVAL;
        break;
    }
    if (err)
    {
        goto err;
    }

    LOG_INF("att: System POX size is: %u bytes.", sys_token_sz);

    /* Request the initial attestation token w/the challenge data. */
    LOG_INF("att: Requesting POX with %u byte challenge.", ch_sz);
    err = psa_proof_of_execution_get_token(
        faddr,
        ch_buffer,    /* Challenge/nonce input buffer. */
        ch_sz,        /* Challenge size (32, 48 or 64). */
        token_buffer, /* Token output buffer. */
        token_buf_size,
        token_sz /* Post exec output token size. */
    );
    LOG_INF("att: POX data received: %u bytes.", *token_sz);

err:
    /* Log any eventual errors via app_log */
    return err ? al_psa_status(err, __func__) : err;
}

int sample_function2(void)
{
    return 12345; // Example output
}

psa_status_t pox_test(void)
{
    psa_status_t err = PSA_SUCCESS;

    /* 64-byte nonce/challenge, encrypted using the default public key;
     *
     * 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
     * 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
     * 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
     * 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
     */
    uint32_t nonce_sz = 32;
    // uint8_t nonce_buf[ATT_MAX_TOKEN_SIZE] = {
    //     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    //     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    //     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    //     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    //     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    //     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    //     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    //     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    //     0};
    uint8_t nonce_buf[ATT_MAX_TOKEN_SIZE] = {0};
    /* POX response buffer. */
    uint32_t pox_sz = ATT_MAX_TOKEN_SIZE;
    uint8_t pox_buf[1024] = {0};

    /* String format output config. */
    struct sf_hex_tbl_fmt fmt = {
        .ascii = false,
        .addr_label = false,
        .addr = 0};

    /* Request the POX from the initial attestation service. */
    uintptr_t func_addr = (uintptr_t)sample_function2;
    err = att_get_pox(&func_addr, nonce_buf, nonce_sz, pox_buf, &pox_sz);
    if (err)
    {
        goto err;
    }

    /* Display queued log messages before dumping the IAT. */
    al_dump_log();

    /* Dump the IAT for debug purposes. */
    sf_hex_tabulate_16(&fmt, pox_buf, (size_t)pox_sz);

err:
    return err;
}
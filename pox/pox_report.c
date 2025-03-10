

#include "pox_report.h"
#include "psa/initial_attestation.h"
#include "qcbor/qcbor.h"
#include <stdio.h>
#include "tfm_sp_log.h" // TF-M Secure Partition Logging

// Structure to store formatting options
struct sf_hex_tbl_fmt
{
    bool ascii;      // Flag to include ASCII representation
    bool addr_label; // Flag to show address labels
    uint32_t addr;   // Starting address
};

void print_hex(struct sf_hex_tbl_fmt *fmt, unsigned char *data, size_t len)
{
    uint32_t idx = 0;
    uint32_t cpos = fmt->addr % 16; // Current position in the row
    uint32_t ca = fmt->addr;        // Current address
    uint32_t ea = fmt->addr + len;  // End address

    if (!len)
    {
        return;
    }

    // Check if we need to render the top address bar
    if (fmt->addr_label)
    {
        LOG_INFFMT("\n");
        LOG_INFFMT("          0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F");
        LOG_INFFMT("%08X ", fmt->addr - (fmt->addr % 16));
    }

    // Insert offset padding for first row if necessary
    if (cpos != 0)
    {
        for (uint32_t i = 0; i < cpos; i++)
        {
            LOG_INFFMT("   ");
        }
    }

    // Print data row by row
    while (len)
    {
        // Print the current byte in hexadecimal
        LOG_INFFMT("%X ", data[idx++]);
        cpos++;
        ca++;

        // Wrap around to the next line if necessary
        if (cpos == 16 || ca == ea)
        {
            // Handle ASCII representation if required
            if (fmt->ascii)
            {
                if (ca == ea)
                {
                    // Handle last/single row
                    if (ca % 16)
                    {
                        // PARTIAL row (< 16 values)
                        for (uint32_t i = 0; i < (16 - ca % 16); i++)
                        {
                            LOG_INFFMT("   ");
                        }
                        // Print ASCII equivalent
                        for (uint32_t i = idx - (ca % 16); i < idx; i++)
                        {
                            LOG_INFFMT("%c", (data[i] >= 32 && data[i] <= 126) ? data[i] : '.');
                        }
                    }
                    else
                    {
                        // FULL row
                        for (uint32_t i = idx - 16; i < idx; i++)
                        {
                            LOG_INFFMT("%c", (data[i] >= 32 && data[i] <= 126) ? data[i] : '.');
                        }
                    }
                }
                else if (ca < fmt->addr + 15)
                {
                    // Handle first row
                    for (uint32_t i = 0; i < fmt->addr % 16; i++)
                    {
                        LOG_INFFMT("   ");
                    }
                    // Print ASCII
                    for (uint32_t i = 0; i < 16 - fmt->addr % 16; i++)
                    {
                        LOG_INFFMT("%c", (data[idx - 16 + i] >= 32 && data[idx - 16 + i] <= 126) ? data[idx - 16 + i] : '.');
                    }
                }
                else
                {
                    // Full row
                    for (uint32_t i = idx - 16; i < idx; i++)
                    {
                        LOG_INFFMT("%c", (data[i] >= 32 && data[i] <= 126) ? data[i] : '.');
                    }
                }
            }

            // Wrap around if this isn't the last row
            LOG_INFFMT("\n");
            if (ca != ea)
            {
                // Render the next base row address
                if (fmt->addr_label)
                {
                    LOG_INFFMT("%X ", ca);
                }
            }
            cpos = 0;
        }
        len--;
    }
    LOG_INFFMT("\n");
}

/**
 * @brief Retrieves the Initial Attestation (IA) token.
 */
psa_status_t att_get_iat(uint8_t *challenge, uint8_t *token_buf, size_t *sys_token_sz)
{
    size_t token_buf_size = ATT_MAX_TOKEN_SIZE; // Use ATT_MAX_TOKEN_SIZE

    printf("[Secure] Requesting attestation token...\n");

    psa_status_t status = psa_initial_attest_get_token(challenge, PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, token_buf, token_buf_size, sys_token_sz);
    if (status != PSA_SUCCESS)
    {
        printf("[Secure] ERROR: Failed to get attestation token (status: %d)\n", status);
        return status;
    }

    printf("[Secure] Attestation token size: %d\n", *sys_token_sz);
    struct sf_hex_tbl_fmt fmt = {
        .ascii = false,
        .addr_label = false,
        .addr = 0};

    print_hex(&fmt, token_buf, token_buf_size);
    return PSA_SUCCESS;
}

/**
 * @brief Generates the PoX report in CBOR format.
 */
psa_status_t generate_pox_report(uint8_t *token_buf, size_t token_size, uintptr_t faddr, int execution_output, uint8_t *cbor_report, size_t *cbor_report_len)
{
    if (!token_buf || !cbor_report || !cbor_report_len)
    {
        printf("[Secure] ERROR: Null pointer argument in generate_pox_report.\n");
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    uint8_t test[32] = "AAAA";
    printf("[Secure] Initialize CBOR\n");
    UsefulBuf buffer = {cbor_report, 644};
    QCBOREncodeContext encode_ctx;
    QCBOREncode_Init(&encode_ctx, buffer);
    // Start encoding the CBOR map
    QCBOREncode_OpenMap(&encode_ctx);
    printf("[Secure] Add IA report to CBOR\n");
    // Step 1: Add IA report (attestation token)
    if (token_size > 0)
    {
        QCBOREncode_AddBytesToMap(&encode_ctx, "ia_report", (UsefulBufC){token_buf, 516});
    }
    else
    {
        printf("[Secure] WARNING: IA report (attestation token) is empty or invalid.\n");
    }
    printf("[Secure] Add function address\n");
    // Step 2: Add function address
    QCBOREncode_AddUInt64ToMap(&encode_ctx, "faddr", (uint64_t)faddr);
    printf("[Secure] Add output\n");
    // Step 3: Add execution output
    QCBOREncode_AddInt64ToMap(&encode_ctx, "execution_output", (int64_t)execution_output);
    printf("[Secure] before close\n");
    // Close CBOR map
    QCBOREncode_CloseMap(&encode_ctx);
    printf("[Secure] After close\n");

    // Finish encoding and check for errors
    UsefulBufC encoded;
    QCBORError err = QCBOREncode_Finish(&encode_ctx, &encoded);
    if (err != QCBOR_SUCCESS)
    {
        printf("[Secure] ERROR: Failed to encode CBOR report. QCBOR Error: %d\n", err); // -> 1
        // Debugging: Check if the buffer size is insufficient
        if (err == QCBOR_ERR_BUFFER_TOO_SMALL)
        {
            printf("[Secure] ERROR: The buffer size is too small. Required size: %d  bytes\n", encoded.len);
        }
        return PSA_ERROR_GENERIC_ERROR;
    }

    // Set the output length
    printf("[Secure] Before Return PSA_SUCCESS\n");
    *cbor_report_len = encoded.len;
    return PSA_SUCCESS;
}

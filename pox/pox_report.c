

#include "pox_report.h"
#include "psa/initial_attestation.h"
#include "qcbor/qcbor.h"
#include <stdio.h>
#include <string.h>

/**
 * @brief Retrieves the Initial Attestation (IA) token.
 */
psa_status_t att_get_iat(uint8_t *challenge, uint8_t *token_buf,size_t *sys_token_sz)
{
    size_t token_buf_size = ATT_MAX_TOKEN_SIZE; // Use ATT_MAX_TOKEN_SIZE

    printf("[Secure] Requesting attestation token...\n");

    psa_status_t status = psa_initial_attest_get_token(challenge, PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, token_buf, token_buf_size, &sys_token_sz);
    if (status != PSA_SUCCESS)
    {
        printf("[Secure] ERROR: Failed to get attestation token (status: %d)\n", status);
        return status;
    }

    printf("[Secure] Attestation token size: %d\n", sys_token_sz);
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

    UsefulBuf buffer = {cbor_report, CBOR_BUFFER_SIZE};
    QCBOREncodeContext encode_ctx;
    QCBOREncode_Init(&encode_ctx, buffer);

    // Start encoding the CBOR map
    QCBOREncode_OpenMap(&encode_ctx);

    // Step 1: Add IA report (attestation token)
    QCBOREncode_AddBytesToMap(&encode_ctx, "ia_report", (UsefulBufC){token_buf, token_size});

    // Step 2: Add function address
    QCBOREncode_AddUInt64ToMap(&encode_ctx, "faddr", (uint64_t)faddr);

    // Step 3: Add execution output
    QCBOREncode_AddInt64ToMap(&encode_ctx, "execution_output", (int64_t)execution_output);

    // Close CBOR map
    QCBOREncode_CloseMap(&encode_ctx);

    // Finish encoding and check for errors
    UsefulBufC encoded;
    QCBORError err = QCBOREncode_Finish(&encode_ctx, &encoded);
    if (err != QCBOR_SUCCESS)
    {
        printf("[Secure] ERROR: Failed to encode CBOR report. QCBOR Error: %d\n", err);
        return PSA_ERROR_GENERIC_ERROR;
    }

    // Set the output length
    *cbor_report_len = encoded.len;
    return PSA_SUCCESS;
}

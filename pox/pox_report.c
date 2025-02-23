#include "pox_report.h"
#include "psa/initial_attestation.h"
#include "qcbor/qcbor.h"
#include <stdio.h>

#define CBOR_BUFFER_SIZE 256
#define ATT_MAX_TOKEN_SIZE (0x240)

// Function to get the Initial Attestation (IA) report
psa_status_t att_get_iat(uint8_t *challenge, uint8_t *token_buf)
{
    uint32_t sys_token_sz;
    size_t token_buf_size = ATT_MAX_TOKEN_SIZE;

    status = psa_initial_attest_get_token(challenge, PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, token_buf, token_buf_size, &sys_token_sz);
    if (status != PSA_SUCCESS)
    {
        printf("[Secure] ERROR: Failed to get attestation token.\n");
        return status;
    }

    return PSA_SUCCESS;
}

// Function to generate the PoX report in CBOR format
psa_status_t generate_pox_report(uint8_t *token_buf, size_t token_size, uintptr_t faddr, int execution_output, uint8_t *cbor_report, size_t *cbor_report_len)
{
    QCBOREncodeContext encode_ctx;
    QCBOREncode_Init(&encode_ctx, (UsefulBuf){cbor_report, CBOR_BUFFER_SIZE});

    // Start encoding the CBOR map
    QCBOREncode_OpenMap(&encode_ctx);

    // Add IA report (attestation token)
    QCBOREncode_AddBytesToMap(&encode_ctx, "ia_report", (UsefulBufC){token_buf, token_size});

    // Add function address
    QCBOREncode_AddUInt64ToMap(&encode_ctx, "faddr", (uint64_t)faddr);

    // Add execution output
    QCBOREncode_AddInt64ToMap(&encode_ctx, "execution_output", (int64_t)execution_output);

    // Close the CBOR map
    QCBOREncode_CloseMap(&encode_ctx);

    // Finish encoding and check for errors
    UsefulBufC encoded;
    QCBORError err = QCBOREncode_Finish(&encode_ctx, &encoded);
    if (err != QCBOR_SUCCESS)
    {
        printf("[Secure] ERROR: Failed to encode CBOR report.\n");
        return PSA_ERROR_GENERIC_ERROR;
    }

    // Set the output length
    *cbor_report_len = encoded.len;

    return PSA_SUCCESS;
}

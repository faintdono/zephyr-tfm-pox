#include <stdio.h>
#include <stdlib.h>
#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "util_sformat.h"
// #include "qcbor/qcbor.h"

#define CHALLENGE_SIZE 32
#define REPORT_BUF_SIZE 512

int sample_function(void)
{
    return 12345; // Example output
}

// // Function to parse the CBOR-encoded PoX report
// void parse_pox_report(uint8_t *cbor_data, size_t cbor_len)
// {
//     QCBORError err;
//     QCBORDecodeContext decode_ctx;
//     QCBORItem item;

//     QCBORDecode_Init(&decode_ctx, (UsefulBufC){cbor_data, cbor_len}, QCBOR_DECODE_MODE_NORMAL);
//     err = QCBORDecode_EnterMap(&decode_ctx, NULL);
//     if (err != QCBOR_SUCCESS)
//     {
//         printf("[NS] ERROR: Invalid CBOR format!\n");
//         return;
//     }

//     // Extract IA token
//     err = QCBORDecode_GetByteString(&decode_ctx, &item);
//     if (err == QCBOR_SUCCESS && item.label.string.len > 0)
//     {
//         printf("[NS] Attestation Token: ");
//         for (size_t i = 0; i < item.val.string.len; i++)
//         {
//             printf("%02x", item.val.string.ptr[i]);
//         }
//         printf("\n");
//     }

//     // Extract function address
//     err = QCBORDecode_GetUInt64(&decode_ctx, &item);
//     if (err == QCBOR_SUCCESS)
//     {
//         printf("[NS] Function Address: 0x%lx\n", (uintptr_t)item.val.uint64);
//     }

//     // Extract execution output
//     err = QCBORDecode_GetInt64(&decode_ctx, &item);
//     if (err == QCBOR_SUCCESS)
//     {
//         printf("[NS] Execution Output: %ld\n", item.val.int64);
//     }

//     QCBORDecode_ExitMap(&decode_ctx);
//     err = QCBORDecode_Finish(&decode_ctx);
//     if (err != QCBOR_SUCCESS)
//     {
//         printf("[NS] ERROR: Failed to decode CBOR data!\n");
//     }
// }

int main(void)
{
    psa_handle_t handle;
    uint8_t challenge[CHALLENGE_SIZE] = {0};       // Example challenge data
    uintptr_t faddr = (uintptr_t)&sample_function; // Function address

    psa_invec in_vec[2] = {
        {challenge, CHALLENGE_SIZE},
        {&faddr, sizeof(uintptr_t)}};

    uint8_t *report_buf = malloc(REPORT_BUF_SIZE);
    size_t report_len = REPORT_BUF_SIZE;

    psa_outvec out_vec[2] = {
        {0},
        {report_buf, report_len} // PoX Report
    };

    int result;
    out_vec[0].base = &result;
    out_vec[0].len = sizeof(int);

    printf("[NS] Requesting Proof of Execution...\n");

    handle = psa_connect(POX_SERVICE_SID, 1);
    if (handle <= 0)
    {
        printf("[NS] ERROR: Failed to connect to PoX Secure Partition!\n");
        return -1;
    }

    printf("[NS] Sending Challenge Size: %d, Function Ptr Size: %d\n", CHALLENGE_SIZE, (int)sizeof(uintptr_t));
    psa_status_t status = psa_call(handle, PSA_IPC_CALL, in_vec, 2, out_vec, 2);

    struct sf_hex_tbl_fmt fmt = {
		.ascii = false,
		.addr_label = false,
		.addr = 0
	};

    if (status == PSA_SUCCESS)
    {
        printf("[NS] Received Output: %d\n", result);
        printf("[NS] Received PoX Report.\n");
        sf_hex_tabulate_16(&fmt, report_buf, (size_t) report_len);
        // parse_pox_report(report_buf, out_vec[0].len);
    }
    else
    {
        printf("[NS] ERROR: Failed to retrieve PoX report.\n");
    }

    psa_close(handle);
    free(report_buf); // Free allocated buffer
    return 0;
}

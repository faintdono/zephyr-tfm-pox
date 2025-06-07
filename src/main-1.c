#include <stdio.h>
#include <stdlib.h>
#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "util_sformat.h"

#define POX_SERVICE_SID 0xFFFFF0E1
#define POX_SERVICE_VERSION 1
#define CHALLENGE_SIZE 32
#define REPORT_BUF_SIZE 1024

int sample_function(void)
{
    return 12345; // Example output
}

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
    printf("[NS] SID: %X\n",POX_SERVICE_SID);
    handle = psa_connect(POX_SERVICE_SID, POX_SERVICE_VERSION);
    if (handle <= 0)
    {
        printf("[NS] ERROR: psa_connect() failed with status: %d\n", handle);
        return -1;
    }

    printf("[NS] Sending Challenge Size: %d, Function Ptr Size: %d\n", CHALLENGE_SIZE, (int)sizeof(uintptr_t));
    psa_status_t status = psa_call(handle, PSA_IPC_CALL, in_vec, 2, out_vec, 2);

    struct sf_hex_tbl_fmt fmt = {
        .ascii = false,
        .addr_label = false,
        .addr = 0};

    if (status == PSA_SUCCESS)
    {
        printf("[NS] Received Output: %d\n", result);
        printf("[NS] Received PoX Report.\n");
        sf_hex_tabulate_16(&fmt, report_buf, (size_t)report_len);
    }
    else
    {
        printf("[NS] ERROR: Failed to retrieve PoX report.\n");
    }

    psa_close(handle);
    free(report_buf); // Free allocated buffer
    return 0;
}

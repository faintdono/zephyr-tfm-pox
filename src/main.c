#include <stdio.h>
#include "psa/client.h"
#include "psa_manifest/sid.h"

#define CHALLENGE_SIZE 32

int sample_function(void)
{
    return 12345; // Example output
}

int main(void)
{
    psa_handle_t handle;
    uint8_t challenge[32] = {0};                   // Example challenge data
    uintptr_t faddr = (uintptr_t)&sample_function; // Get function address

    psa_invec in_vec[2] = {
        {challenge, CHALLENGE_SIZE},
        {&faddr, sizeof(uintptr_t)}};
    psa_outvec out_vec[3] = {{0}};

    int result;
    out_vec[0].base = &result;
    out_vec[0].len = sizeof(int);
    out_vec[1].base = malloc(256); // Allocate space for the IA token
    out_vec[1].len = 256;          // Max size for the IA token
    out_vec[2].base = malloc(512); // Allocate space for the PoX report
    out_vec[2].len = 512;          // Max size for the PoX report

    printf("[NS] Requesting Proof of Execution...\n");

    handle = psa_connect(POX_SERVICE_SID, 1);
    if (handle <= 0)
    {
        printf("[NS] ERROR: Failed to connect to PoX Secure Partition!\n");
        return -1;
    }

    printf("[NS] Sending Challenge Size: %d, Function Ptr Size: %d\n", CHALLENGE_SIZE, (int)sizeof(uintptr_t));
    psa_status_t status = psa_call(handle, PSA_IPC_CALL, in_vec, 2, out_vec, 1);

    if (status == PSA_SUCCESS)
    {
        printf("[NS] Result: %d\n", result);
        printf("[NS] Attestation Token: ");
        for (size_t i = 0; i < out_vec[1].len; i++)
        {
            printf("%02x", ((uint8_t *)out_vec[1].base)[i]);
        }
        printf("\n");

        // Print PoX report as hex (you may choose to parse it if needed)
        printf("[NS] PoX Report: ");
        for (size_t i = 0; i < out_vec[2].len; i++)
        {
            printf("%02x", ((uint8_t *)out_vec[2].base)[i]);
        }
        printf("\n");
    }
    else
    {
        printf("[NS] ERROR: Failed to retrieve Result, IA token, or PoX report.\n");
    }

    psa_close(handle);
    free(out_vec[1].base); // Free the IA token buffer
    free(out_vec[2].base); // Free the PoX report buffer
    return 0;
}
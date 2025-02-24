#include "pox_handler.h"
#include "pox_execute.h"
#include "pox_report.h"
#include "psa/crypto.h"
#include "psa/initial_attestation.h"
#include <stdio.h>

// Size of the challenge in bytes (256 bits)
#define CHALLENGE_SIZE 32
#define TOKEN_BUF_SIZE 256
#define REPORT_BUF_SIZE 512

// Securely stored values
static uint8_t stored_challenge[CHALLENGE_SIZE];
static uintptr_t stored_faddr;
static int execution_output;

// PoX IPC Handler function
psa_status_t pox_ipc_handler(psa_msg_t *msg)
{
    printf("[Secure] POX Initialize \n");

    psa_status_t status;
    size_t sys_token_sz;                 // Actual size of retrieved token
    uint8_t token_buf[TOKEN_BUF_SIZE];   // Buffer for the IA token
    uint8_t report_buf[REPORT_BUF_SIZE]; // Buffer for the PoX report
    size_t report_size = REPORT_BUF_SIZE;

    switch (msg->type)
    {
    case PSA_IPC_CONNECT:
        printf("[Secure] PSA_IPC_CONNECT received.\n");
        psa_reply(msg->handle, PSA_SUCCESS);
        break;

    case PSA_IPC_CALL:
        printf("[Secure] PSA_IPC_CALL received. Processing request...\n");
        printf("[Secure] Received input sizes: %d, %d\n", msg->in_size[0], msg->in_size[1]);

        if (msg->in_size[0] != CHALLENGE_SIZE || msg->in_size[1] != sizeof(uintptr_t))
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        // Read input parameters
        psa_read(msg->handle, 0, stored_challenge, CHALLENGE_SIZE);
        psa_read(msg->handle, 1, &stored_faddr, sizeof(uintptr_t));

        printf("[Secure] Function trying to execute\n");
        execution_output = execute_function(stored_faddr); // Call the function from pox_execute.c

        // Get Initial Attestation Token
        status = att_get_iat(stored_challenge, token_buf, &sys_token_sz);
        if (status != PSA_SUCCESS)
        {
            printf("[Secure] ERROR: Failed to get attestation token.\n");
            return PSA_ERROR_GENERIC_ERROR;
        }

        // Generate PoX Report
        status = generate_pox_report(token_buf, sys_token_sz, stored_faddr, execution_output, report_buf, &report_size);
        if (status != PSA_SUCCESS)
        {
            printf("[Secure] ERROR: Failed to generate PoX report.\n");
            return PSA_ERROR_GENERIC_ERROR;
        }

        // Send PoX Report to Non-Secure World
        psa_write(msg->handle, 0, &execution_output, sizeof(int));
        psa_write(msg->handle, 1, report_buf, report_size); // Send only the PoX report
        psa_reply(msg->handle, PSA_SUCCESS);
        printf("[Secure] Response sent successfully.\n");
        break;

    case PSA_IPC_DISCONNECT:
        printf("[Secure] PSA_IPC_DISCONNECT received.\n");
        psa_reply(msg->handle, PSA_SUCCESS);
        break;

    default:
        printf("[Secure] ERROR: Invalid message type received: %d\n", msg->type);
        psa_reply(msg->handle, PSA_ERROR_PROGRAMMER_ERROR);
    }

    return PSA_SUCCESS;
}

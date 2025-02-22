#include "psa_manifest/tfm_pox.h"
#include "psa/service.h"
#include "psa/crypto.h"
#include "psa/initial_attestation.h"
#include <stdio.h>
#include <string.h>

/* Size of the challenge in bytes (256 bits) */
#define CHALLENGE_SIZE 32

typedef psa_status_t (*hw_service_handler_t)(psa_msg_t *);
typedef int (*function_ptr_t)(void);

// Securely stored values
static uint8_t stored_challenge[CHALLENGE_SIZE];
static uintptr_t stored_faddr;
static int execution_output;

static void handle_psa_message(psa_signal_t signal, hw_service_handler_t handler);
static psa_status_t pox_ipc_handler(psa_msg_t *msg);

// Function to execute `F()`
int execute_function(uintptr_t faddr) {
    function_ptr_t func = (function_ptr_t)faddr;
    return func();  // Execute and return output
}


static psa_status_t pox_ipc_handler(psa_msg_t *msg)
{
    if (msg->in_size[0] != CHALLENGE_SIZE || msg->in_size[1] != sizeof(uintptr_t)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // Read input parameters
    psa_read(msg->handle, 0, stored_challenge, CHALLENGE_SIZE);
    psa_read(msg->handle, 1, &stored_faddr, sizeof(uintptr_t));

    execution_output = execute_function(stored_faddr);

    // Return result
    psa_write(msg->handle, 0, &execution_output, sizeof(int));
    return PSA_SUCCESS;
}

/**
 * Generic PSA request handler that retrieves and processes messages.
 */
static void handle_psa_message(psa_signal_t signal, hw_service_handler_t handler)
{
    psa_status_t status;
    psa_msg_t msg;

    status = psa_get(signal, &msg);
    if (status != PSA_SUCCESS)
    {
        printf("[Secure] ERROR: psa_get() failed with status: %d\n", status);
        psa_panic();
    }

    handler(&msg);
}

/**
 * Secure partition entry point that continuously listens for requests.
 */
void tfm_pox_main(void)
{
    psa_signal_t signals = 0;

    printf("[Secure] POX Partition Started.\n");

    while (1)
    {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
        printf("[Secure] Received signal: 0x%X\n", signals);

        if (signals & POX_SERVICE_SIGNAL)
        {
            handle_psa_message(POX_SERVICE_SIGNAL, pox_ipc_handler);
        }
        else
        {
            printf("[Secure] ERROR: Unexpected signal received (0x%X)\n", signals);
            psa_panic();
        }
    }
}
#include "pox_execute.h"
#include <stdio.h>

// Define the function pointer type for non-secure functions
typedef int (*ns_function_ptr_t)(void) __attribute__((cmse_nonsecure_call));

// Implementation of execute_function
int execute_function(uintptr_t faddr)
{
    ns_function_ptr_t ns_func = (ns_function_ptr_t)faddr;
    if (!ns_func)
    {
        printf("[Secure] ERROR: Invalid function address.\n");
        return -1;
    }

    // Execute and return the output
    return ns_func();
}

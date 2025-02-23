#ifndef POX_REPORT_H
#define POX_REPORT_H

#include "psa/initial_attestation.h"
#include "qcbor/qcbor.h"

// Function declarations
psa_status_t att_get_iat(uint8_t *challenge, uint8_t *token_buf);
psa_status_t generate_pox_report(uint8_t *token_buf, size_t token_size, uintptr_t faddr, int execution_output, uint8_t *cbor_report, size_t *cbor_report_len);

#endif /* POX_REPORT_H */

#ifndef ARGON2IDDPC_GATE_H__
#define ARGON2IDDPC_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>
#include <stdbool.h>

bool register_argon2idDPC_algo(algo_gate_t *gate);


void argon2idDPC_hash(const char *input, char *output);


int scanhash_dualpowdpc(struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr);

#endif /* ARGON2IDDPC_GATE_H__ */

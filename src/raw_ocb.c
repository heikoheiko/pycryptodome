/* ===================================================================
 *
 * Copyright (c) 2014, Legrandin <helderijs@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
 */

#include "pycrypto_common.h"

FAKE_INIT(raw_ocb)

#include "block_base.h"

#define BLOCK_SIZE 16

typedef uint8_t DataBlock[BLOCK_SIZE];

typedef struct {
    BlockBase   *cipher;

    DataBlock   L_star;
    DataBlock   L_dollar;
    DataBlock   L[65];  /** 0..64 **/

    uint64_t    counter_A;
    DataBlock   offset_A;
    DataBlock   sum;

    uint64_t    counter_P;
    DataBlock   offset_P;
    DataBlock   checksum;
} OcbModeState;

static void double_L(DataBlock *out, DataBlock *in)
{
    unsigned carry;
    int i;

    carry = 0;
    for (i=BLOCK_SIZE-1; i>=0; i--) {
        unsigned t;

        t = ((*in)[i] << 1) | carry;
        carry = t >> 8;
        (*out)[i] = t;
    }
    if (carry)
        (*out)[BLOCK_SIZE-1] ^= 0x87;
}

static unsigned ntz(uint64_t counter)
{
    unsigned i;
    for (i=0; i<65; i++) {
        if (counter & 1)
            return i;
        counter >>= 1;
    }
    return 64;
}

EXPORT_SYM int OCB_start_operation(BlockBase *cipher,
                                   const uint8_t *offset_0,
                                   size_t offset_0_len,
                                   OcbModeState **pState)
{

    OcbModeState *state;
    int result;
    unsigned i;

    if ((NULL == cipher) || (NULL == pState)) {
        return ERR_NULL;
    }

    if ((BLOCK_SIZE != cipher->block_len) || (BLOCK_SIZE != offset_0_len)) {
        return ERR_BLOCK_SIZE;
    }

    *pState = state = calloc(1, sizeof(OcbModeState));
    if (NULL == state) {
        return ERR_MEMORY;
    }

    state->cipher = cipher;

    result = state->cipher->encrypt(state->cipher, state->checksum, state->L_star, BLOCK_SIZE);
    if (result)
        return result;

    double_L(&state->L_dollar, &state->L_star);
    double_L(&state->L[0], &state->L_dollar);
    for (i=1; i<=64; i++)
        double_L(&state->L[i], &state->L[i-1]);

    memcpy(state->offset_P, offset_0, BLOCK_SIZE);

    state->counter_A = state->counter_P = 1;

    return 0;
}

EXPORT_SYM int OCB_encrypt(OcbModeState *state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    DataBlock pt;
    unsigned i;
    int result;

    if ((NULL == state) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    for (;data_len>BLOCK_SIZE; data_len-=BLOCK_SIZE) {
        unsigned idx;

        idx = ntz(state->counter_P);
        for (i=0; i<BLOCK_SIZE; i++) {
            state->offset_P[i] ^= state->L[idx][i];
            pt[i] = in[i] ^ state->offset_P[i];
            state->checksum[i] ^= in[i];
        }
        if (++state->counter_P == 0)
            return ERR_MAX_DATA;

        result = state->cipher->encrypt(state->cipher, pt, out, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<BLOCK_SIZE; i++) {
            out[i] ^= state->offset_P[i];
        }

        in += BLOCK_SIZE;
        out += BLOCK_SIZE;
    }

    /** Process the residual block **/
    if (data_len>0) {
        uint8_t pad[BLOCK_SIZE];

        for (i=0; i<BLOCK_SIZE; i++)
            state->offset_P[i] ^= state->L_star[i];

        result = state->cipher->encrypt(state->cipher, state->offset_P, pad, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<data_len; i++) {
            *out++ = *in ^ pad[i];
            state->checksum[i] ^= *in++;
        }
        state->checksum[data_len] ^= 0x80;
    }

    return 0;
}

EXPORT_SYM int OCB_decrypt(OcbModeState *state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    DataBlock ct;
    unsigned i;
    int result;

    if ((NULL == state) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    for (;data_len>BLOCK_SIZE; data_len-=BLOCK_SIZE) {
        unsigned idx;

        idx = ntz(state->counter_P);
        for (i=0; i<BLOCK_SIZE; i++) {
            state->offset_P[i] ^= state->L[idx][i];
            ct[i] = in[i] ^ state->offset_P[i];
        }
        if (++state->counter_P == 0)
            return ERR_MAX_DATA;

        result = state->cipher->decrypt(state->cipher, ct, out, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<BLOCK_SIZE; i++) {
            out[i] ^= state->offset_P[i];
            state->checksum[i] ^= out[i];
        }

        in += BLOCK_SIZE;
        out += BLOCK_SIZE;
    }

    if (data_len>0) {
        uint8_t pad[BLOCK_SIZE];

        for (i=0; i<BLOCK_SIZE; i++)
            state->offset_P[i] ^= state->L_star[i];

        result = state->cipher->encrypt(state->cipher, state->offset_P, pad, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<data_len; i++) {
            out[i] = in[i] ^ pad[i];
            state->checksum[i] ^= out[i];
        }
        state->checksum[data_len] ^= 0x80;
    }

    return 0;
}

EXPORT_SYM int OCB_update(OcbModeState *state,
                          const uint8_t *in,
                          size_t data_len)
{
    int result;
    unsigned i;
    DataBlock pt;
    DataBlock ct;

    for (;data_len>BLOCK_SIZE; data_len-=BLOCK_SIZE) {
        unsigned idx;

        idx = ntz(state->counter_A);
        for (i=0; i<BLOCK_SIZE; i++) {
            state->offset_A[i] ^= state->L[idx][i];
            pt[i] = *in++ ^ state->offset_A[i];
        }
        if (++state->counter_A == 0)
            return ERR_MAX_DATA;

        result = state->cipher->encrypt(state->cipher, pt, ct, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<BLOCK_SIZE; i++)
            state->sum[i] ^= ct[i];
    }

    if (data_len>0) {

        memset(pt, 0, sizeof pt);
        memcpy(pt, in, data_len);
        pt[data_len] = 0x80;

        for (i=0; i<BLOCK_SIZE; i++)
            pt[i] ^= state->offset_A[i] ^ state->L_star[i];

        result = state->cipher->encrypt(state->cipher, pt, ct, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<BLOCK_SIZE; i++)
            state->sum[i] ^= ct[i];
    }

    return 0;
}

EXPORT_SYM int OCB_digest(OcbModeState *state,
                          uint8_t *tag,
                          size_t tag_len)
{
    DataBlock pt;
    unsigned i;
    int result;

    if (BLOCK_SIZE != tag_len)
        return ERR_TAG_SIZE;

    for (i=0; i<BLOCK_SIZE; i++)
        pt[i] = state->checksum[i] ^ state->offset_P[i] ^ state->L_dollar[i];

    result = state->cipher->encrypt(state->cipher, pt, tag, BLOCK_SIZE);
    if (result)
        return result;

    for (i=0; i<BLOCK_SIZE; i++)
        tag[i] ^= state->sum[i];

    return 0;
}

EXPORT_SYM int CBC_stop_operation(OcbModeState *state)
{
    state->cipher->destructor(state->cipher);
    free(state);
    return 0;
}

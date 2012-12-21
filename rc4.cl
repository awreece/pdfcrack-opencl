/*
 * rc4.c
 *
 * Copyright (c) 1996-2000 Whistle Communications, Inc.
 * All rights reserved.
 * 
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 * 
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/crypto/rc4/rc4.c,v 1.2.2.1 2000/04/18 04:48:31 archie Exp $
 */

#include "common.h"

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

static __inline void swap_bytes(uchar* a, uchar* b) {
  uchar temp;

  temp = *a;
  *a = *b;
  *b = temp;
}

/*
 * Initialize an RC4 state buffer using the supplied key,
 * which can have arbitrary length.
 */
void rc4_init(rc4_state_t* const state, const char* key, int keylen) {
  uchar j;
  int i;
  const uchar* keybuf = (const uchar*) key;

  /* Initialize state with identity permutation */
  for (i = 0; i < 256; i++) {
    state->perm[i] = (uchar)i;
  }
  state->index1 = 0;
  state->index2 = 0;

  /* Randomize the permutation using key data */
  for (j = i = 0; i < 256; i++) {
    j += state->perm[i] + keybuf[i % keylen];
    swap_bytes(&state->perm[i], &state->perm[j]);
  }
}

/*
 * Encrypt some data using the supplied RC4 state buffer.
 * The input and output buffers may be the same buffer.
 * Since RC4 is a stream cypher, this function is used
 * for both encryption and decryption.
 */
void rc4_crypt(rc4_state_t* const state, const char* in, char* out, int buflen) {
  int i;
  uchar j;
  const uchar* inbuf = (const uchar*) in;
  uchar* outbuf = (uchar*) out;

  for (i = 0; i < buflen; i++) {

    /* Update modification indicies */
    state->index1++;
    state->index2 += state->perm[state->index1];

    /* Modify permutation */
    swap_bytes(&state->perm[state->index1],
               &state->perm[state->index2]);

    /* Encrypt/decrypt next byte */
    j = state->perm[state->index1] + state->perm[state->index2];
    outbuf[i] = inbuf[i] ^ state->perm[j];
  }
}

__kernel void do_rc4s(global const password_t* keys, global const password_t* messages, global password_hash_t* out) {
  int id = get_global_id(0);
  uint i;
  password_t key;
  password_t message;
  password_hash_t lhash;
  for (i = 0; i < keys[id].size_bytes; i++) {
    key.password[i] = keys[id].password[i];
  }
  key.size_bytes = keys[id].size_bytes;
  for (i = 0; i < messages[id].size_bytes; i++) {
    message.password[i] = messages[id].password[i];
  }
  message.size_bytes = messages[id].size_bytes;

  rc4_state_t state;
  rc4_init(&state, key.password, key.size_bytes);
  rc4_crypt(&state, message.password, (char*) &lhash, message.size_bytes);

  for (i = 0; i < 4; i++) {
    out[id].v[i] = lhash.v[i];
  }
}

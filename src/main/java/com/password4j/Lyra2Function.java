/*
 *  (C) Copyright 2021 Password4j (http://password4j.com/).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package com.password4j;
/**
 * Class containing the implementation of Lyra2 function and its parameters.
 *
 * @author David Bertoldi
 * @see <a href="https://en.wikipedia.org/wiki/Lyra2">Lyra2</a>
 * @since 1.6.0
 */
public class Lyra2Function extends AbstractHashingFunction
{
    private static final int COLS = 256;

    private static final int FULL_ROUNDS = 12;

    private static final int HALF_ROUNDS = FULL_ROUNDS;

    private static final int BLOCK = 12;

    private static final int BLOCK_BYTES = 8 * BLOCK;

    private static final int SIZEOF_INT   = 4;
    private static final int SIZEOF_INT64 = 8;

    private static final int BLOCK_LEN_BLAKE2_SAFE_INT64 = 8;
    private static final int BLOCK_LEN_BLAKE2_SAFE_BYTES = 64;

    private static final int ROW_LEN_INT64 =     COLS * BLOCK;
    private static final int ROW_LEN_BYTES =  COLS * BLOCK_BYTES;

    private int keyLength;

    private int time;

    private int memory;




    @Override
    public Hash hash(CharSequence plainTextPassword)
    {
        return null;
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt)
    {

        byte[] pwdAsBytes = Utils.fromCharSequenceToBytes(plainTextPassword);
        byte[] saltAsBytes = Utils.fromCharSequenceToBytes(salt);
        int    gap = 1;
        int   step = 1;
        int window = 2;
        int   sqrt = 2;

        int  row0;
        int prev0 = 2;
        int  row1 = 1;
        int prev1 = 0;


        int pwdLen = pwdAsBytes.length;
        int saltLen = saltAsBytes.length;

        long[] matrix = new long[memory * ROW_LEN_INT64];

        int[] offsets = new int[memory];

        for (int i = 0, row = 0; i != memory; ++i, row += ROW_LEN_INT64) {
            offsets[i] = row;
        }

        // See comment about constant 6 in original code: make it 8 integers total
        int nBlocksInput = (pwdLen + saltLen + 6 * SIZEOF_INT) / BLOCK_LEN_BLAKE2_SAFE_BYTES + 1;

        int ii;
        for (ii = 0; ii != nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_INT64; ++ii) {
            matrix[ii] = 0;
        }

        ii = 0;
        byte[] buffer0 = new byte[nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES];

        for (int jj = 0; jj != pwdLen; ++ii, ++jj) {
            buffer0[ii] = pwdAsBytes[jj];
        }

        for (int jj = 0; jj != saltLen; ++ii, ++jj) {
            buffer0[ii] = saltAsBytes[jj];
        }

        // NOTE: the order of mem.copy calls matters
        mem.copy(buffer0, ii, keyLength); ii += 4;
        mem.copy(buffer0, ii, pwdLen); ii += 4;
        mem.copy(buffer0, ii, saltLen); ii += 4;
        mem.copy(buffer0, ii, time); ii += 4;
        mem.copy(buffer0, ii, memory); ii += 4;
        mem.copy(buffer0, ii, COLS); ii += 4;

        buffer0[ii] = (byte) 0x80;
        buffer0[nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1] |= (byte) 0x01;

        final long[] buffer1 = pack.longs(buffer0);

        for (int jj = 0; jj != buffer1.length; ++jj) {
            matrix[jj] = buffer1[jj];
        }

        Sponge sponge;
        if (params.SPONGE.equals("blake2b")) {
            sponge = new SpongeBlake2b(params);
        } else if (params.SPONGE.equals("blamka")) {
            sponge = new SpongeBlamka(params);
        } else if (params.SPONGE.equals("half-round-blamka")) {
            sponge = new SpongeHalfBlamka(params);
        } else {
            System.err.println("Could not recognize sponge: " + params.SPONGE);

            return;
        }

        for (int jj = 0, offset = 0; jj < nBlocksInput; ++jj) {
            sponge.absorb(matrix, BLOCK_LEN_BLAKE2_SAFE_INT64, offset);

            offset += BLOCK_LEN_BLAKE2_SAFE_INT64;
        }

        // Setup phase:
        sponge.reduced_squeeze_row0(matrix, offsets[0]);

        sponge.reduced_duplex_row1_and_row2(matrix, offsets[0], offsets[1]);
        sponge.reduced_duplex_row1_and_row2(matrix, offsets[1], offsets[2]);

        // Setup phase: filling loop:
        for (row0 = 3; row0 != m_cost; ++row0) {
            sponge.reduced_duplex_row_filling(
                    matrix,
                    offsets[row1],
                    offsets[prev0],
                    offsets[prev1],
                    offsets[row0]
            );

            prev0 = row0;
            prev1 = row1;

            row1 = (row1 + step) & (window - 1);

            if (row1 == 0) {
                window *= 2;
                step = sqrt + gap;
                gap = -gap;

                if (gap == -1) {
                    sqrt *= 2;
                }
            }
        }

        // Wandering phase:
        for (int i = 0; i != time * memory; ++i) {
            row0 = (int) Long.remainderUnsigned(mem.flip(sponge.state[0]), memory);
            row1 = (int) Long.remainderUnsigned(mem.flip(sponge.state[2]), memory);

            sponge.reduced_duplex_row_wandering(matrix, offsets[row0], offsets[row1], offsets[prev0], offsets[prev1]);

            prev0 = row0;
            prev1 = row1;
        }

        // Wrap-up phase:
        sponge.absorb(matrix, BLOCK_BYTES, offsets[row0]);

        sponge.squeeze(hash, n_hash);
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        return false;
    }
}

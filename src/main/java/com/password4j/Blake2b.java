/*
 *  (C) Copyright 2020 Password4j (http://password4j.com/).
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

import java.util.Arrays;


class Blake2b
{
    private static final long[] IV = {0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L};

    private static final byte[][] SIGMA = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}, {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}, {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}, {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}, {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

    private static final int ROUNDS = 12;

    private static final int BLOCK_LENGTH_BYTES = 128;

    private final int digestLength;

    private final int keyLength;

    private final byte[] buffer;

    private final long[] internalState = new long[16];

    private int bufferPos = 0;

    private long[] chainValue = null;

    private long t0 = 0L;

    private long t1 = 0L;

    private long f0 = 0L;

    /**
     * Basic sized constructor - size in bytes.
     *
     * @param digestSize size of the digest in bytes
     */
    Blake2b(int digestSize)
    {
        if (digestSize < 1 || digestSize > 64)
        {
            throw new BadParametersException("BLAKE2b digest bytes length must be not greater than 64");
        }

        buffer = new byte[BLOCK_LENGTH_BYTES];
        keyLength = 0;
        this.digestLength = digestSize;
        init();
    }

    // initialize chainValue
    private void init()
    {
        chainValue = new long[8];
        chainValue[0] = IV[0] ^ (digestLength | ((long) keyLength << 8) | 0x1010000);
        chainValue[1] = IV[1];
        chainValue[2] = IV[2];
        chainValue[3] = IV[3];
        chainValue[4] = IV[4];
        chainValue[5] = IV[5];
        chainValue[6] = IV[6];
        chainValue[7] = IV[7];
    }

    private void initializeInternalState()
    {
        System.arraycopy(chainValue, 0, internalState, 0, chainValue.length);
        System.arraycopy(IV, 0, internalState, chainValue.length, 4);
        internalState[12] = t0 ^ IV[4];
        internalState[13] = t1 ^ IV[5];
        internalState[14] = f0 ^ IV[6];
        internalState[15] = IV[7];// ^ f1 with f1 = 0
    }

    void update(byte[] message)
    {
        if (message == null)
        {
            return;
        }
        update(message, 0, message.length);
    }

    /**
     * update the message digest with a block of bytes.
     *
     * @param message the byte array containing the data.
     * @param offset  the offset into the byte array where the data starts.
     * @param len     the length of the data.
     */
    void update(byte[] message, int offset, int len)
    {
        int remainingLength = 0;

        if (bufferPos != 0)
        {
            remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
            if (remainingLength < len)
            {
                System.arraycopy(message, offset, buffer, bufferPos, remainingLength);
                t0 += BLOCK_LENGTH_BYTES;
                if (t0 == 0)
                {
                    t1++;
                }
                compress(buffer, 0);
                bufferPos = 0;
                Arrays.fill(buffer, (byte) 0);// clear buffer
            }
            else
            {
                System.arraycopy(message, offset, buffer, bufferPos, len);
                bufferPos += len;
                return;
            }
        }

        int messagePos;
        int blockWiseLastPos = offset + len - BLOCK_LENGTH_BYTES;
        for (messagePos = offset + remainingLength; messagePos < blockWiseLastPos; messagePos += BLOCK_LENGTH_BYTES)
        {
            t0 += BLOCK_LENGTH_BYTES;
            if (t0 == 0)
            {
                t1++;
            }
            compress(message, messagePos);
        }

        // fill the buffer with left bytes, this might be a full block
        System.arraycopy(message, messagePos, buffer, 0, offset + len - messagePos);
        bufferPos += offset + len - messagePos;
    }

    /**
     * close the digest, producing the final digest value. The doFinal
     * call leaves the digest reset.
     * Key, salt and personal string remain.
     *
     * @param out       the array the digest is to be copied into.
     * @param outOffset the offset into the out array the digest is to start at.
     */
    void doFinal(byte[] out, int outOffset)
    {

        f0 = 0xFFFFFFFFFFFFFFFFL;
        t0 += bufferPos;
        if (bufferPos > 0 && t0 == 0)
        {
            t1++;
        }
        compress(buffer, 0);
        Arrays.fill(buffer, (byte) 0);// Holds eventually the key if input is null
        Arrays.fill(internalState, 0L);

        for (int i = 0; i < chainValue.length && (i * 8 < digestLength); i++)
        {
            byte[] bytes = Utils.longToLittleEndian(chainValue[i]);

            if (i * 8 < digestLength - 8)
            {
                System.arraycopy(bytes, 0, out, outOffset + i * 8, 8);
            }
            else
            {
                System.arraycopy(bytes, 0, out, outOffset + i * 8, digestLength - (i * 8));
            }
        }

        Arrays.fill(chainValue, 0L);

        reset();
    }

    /**
     * Reset the digest back to it's initial state.
     * The key, the salt and the personal string will
     * remain for further computations.
     */
    void reset()
    {
        bufferPos = 0;
        f0 = 0L;
        t0 = 0L;
        t1 = 0L;
        chainValue = null;
        Arrays.fill(buffer, (byte) 0);
        init();
    }

    private void compress(byte[] message, int messagePos)
    {

        initializeInternalState();

        long[] m = new long[16];
        for (int j = 0; j < 16; j++)
        {
            m[j] = Utils.littleEndianToLong(message, messagePos + j * 8);
        }

        for (int round = 0; round < ROUNDS; round++)
        {

            // G apply to columns of internalState:m[blake2b_sigma[round][2 *
            // blockPos]] /+1
            functionG(m[SIGMA[round][0]], m[SIGMA[round][1]], 0, 4, 8, 12);
            functionG(m[SIGMA[round][2]], m[SIGMA[round][3]], 1, 5, 9, 13);
            functionG(m[SIGMA[round][4]], m[SIGMA[round][5]], 2, 6, 10, 14);
            functionG(m[SIGMA[round][6]], m[SIGMA[round][7]], 3, 7, 11, 15);
            // G apply to diagonals of internalState:
            functionG(m[SIGMA[round][8]], m[SIGMA[round][9]], 0, 5, 10, 15);
            functionG(m[SIGMA[round][10]], m[SIGMA[round][11]], 1, 6, 11, 12);
            functionG(m[SIGMA[round][12]], m[SIGMA[round][13]], 2, 7, 8, 13);
            functionG(m[SIGMA[round][14]], m[SIGMA[round][15]], 3, 4, 9, 14);
        }

        // update chain values:
        for (int offset = 0; offset < chainValue.length; offset++)
        {
            chainValue[offset] = chainValue[offset] ^ internalState[offset] ^ internalState[offset + 8];
        }
    }

    private void functionG(long m1, long m2, int posA, int posB, int posC, int posD)
    {

        internalState[posA] = internalState[posA] + internalState[posB] + m1;
        internalState[posD] = Long.rotateRight(internalState[posD] ^ internalState[posA], 32);
        internalState[posC] = internalState[posC] + internalState[posD];
        internalState[posB] = Long.rotateRight(internalState[posB] ^ internalState[posC], 24); // replaces 25 of BLAKE
        internalState[posA] = internalState[posA] + internalState[posB] + m2;
        internalState[posD] = Long.rotateRight(internalState[posD] ^ internalState[posA], 16);
        internalState[posC] = internalState[posC] + internalState[posD];
        internalState[posB] = Long.rotateRight(internalState[posB] ^ internalState[posC], 63); // replaces 11 of BLAKE
    }
}

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

import static java.lang.System.arraycopy;

/**
 * Blake2b offers a built-in keying mechanism to be used directly
 * for authentication ("Prefix-MAC") rather than a HMAC construction.
 * <p>
 * Blake2b offers a built-in support for a salt for randomized hashing
 * and a personal string for defining a unique hash function for each application.
 * <p>
 * BLAKE2b is optimized for 64-bit platforms and produces digests of any size
 * between 1 and 64 bytes.
 */
public class Blake2b
{

    private static final long F_0 = 0xFFFFFFFFFFFFFFFFL;

    // Blake2b Initialization Vector:
    // Produced from the square root of primes 2, 3, 5, 7, 11, 13, 17, 19.
    // The same as SHA-512 IV.
    private static final long[] BLAKE2B_IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL,
            0xa54ff53a5f1d36f1L, 0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    // Message word permutations:
    private static final byte[][] BLAKE2B_SIGMA = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };

    private static final int BLOCK_LENGTH_BYTES = 128;// bytes

    private static final int ROUNDS = 12; // to use for Catenas H'


    // General parameters
    private int digestSize = 64; // 1- 64 bytes
    private int keyLength = 0; // 0 - 64 bytes for keyed hashing for MAC
    private byte[] salt = null;
    private byte[] personalization = null;

    // The key
    private byte[] key = null;

    // whenever this buffer overflows, it will be processed
    // in the compress() function.
    // For performance issues, long messages will not use this buffer.
    private byte[] buffer;

    // Position of last inserted byte:
    private int bufferPos = 0;// a value from 0 up to 128

    private final long[] internalState = new long[16]; // In the Blake2b paper it is called: v

    private long[] chainValue = null; // state vector, in the Blake2b paper it is called: h

    private long t0 = 0L; // holds last significant bits, counter (counts bytes)
    private long t1 = 0L; // counter: Length up to 2^128 are supported
    private long f0 = 0L; // finalization flag, for last block: ~0L

    public Blake2b()
    {
        this(512);
    }

    public Blake2b(final Blake2b digest)
    {
        this.bufferPos = digest.bufferPos;
        this.buffer = cloneByteArray(digest.buffer);
        this.keyLength = digest.keyLength;
        this.key = cloneByteArray(digest.key);
        this.digestSize = digest.digestSize;
        this.chainValue = cloneByteArray(digest.chainValue);
        this.personalization = cloneByteArray(digest.personalization);
        this.salt = cloneByteArray(digest.salt);
        this.t0 = digest.t0;
        this.t1 = digest.t1;
        this.f0 = digest.f0;
    }

    /**
     * Basic sized constructor - size in bits.
     *
     * @param digestSize size of the digest in bits
     */
    public Blake2b(final int digestSize)
    {
        if (digestSize != 160 && digestSize != 256 && digestSize != 384 && digestSize != 512)
        {
            throw new IllegalArgumentException("Blake2b digest restricted to one of [160, 256, 384, 512]");
        }

        buffer = new byte[BLOCK_LENGTH_BYTES];
        keyLength = 0;
        this.digestSize = digestSize / 8;
        init();
    }

    /**
     * Blake2b for authentication ("Prefix-MAC mode").
     * After calling the digest() method, the key will
     * remain to be used for further computations of
     * this instance.
     * The key can be overwritten using the clearKey() method.
     *
     * @param key A key up to 64 bytes or null
     */
    public Blake2b(final byte[] key)
    {
        buffer = new byte[BLOCK_LENGTH_BYTES];
        if (null != key)
        {
            this.key = new byte[key.length];
            arraycopy(key, 0, this.key, 0, key.length);

            if (64 < key.length)
            {
                throw new IllegalArgumentException(
                        "Keys > 64 are not supported");
            }

            keyLength = key.length;
            arraycopy(key, 0, buffer, 0, key.length);
            bufferPos = BLOCK_LENGTH_BYTES; // zero padding
        }
        init();
    }

    /**
     * Blake2b with key, required digest length (in bytes), salt and personalization.
     * After calling the digest() method, the key, the salt and the personal string
     * will remain and might be used for further computations with this instance.
     * The key can be overwritten using the clearKey() method, the salt (pepper)
     * can be overwritten using the clearSalt() method.
     *
     * @param key             A key up to 64 bytes or null
     * @param digestSize      from 1 up to 64 bytes
     * @param salt            16 bytes or null
     * @param personalization 16 bytes or null
     */
    public Blake2b(final byte[] key, final int digestSize, final byte[] salt, final byte[] personalization)
    {
        buffer = new byte[BLOCK_LENGTH_BYTES];

        if (digestSize < 1 || digestSize > 64)
        {
            throw new IllegalArgumentException(
                    "Invalid digest length (required: 1 - 64)");
        }

        this.digestSize = digestSize;

        if (salt != null)
        {
            if (salt.length != 16)
            {
                throw new IllegalArgumentException(
                        "salt length must be exactly 16 bytes");
            }
            this.salt = new byte[16];
            arraycopy(salt, 0, this.salt, 0, salt.length);
        }

        if (personalization != null)
        {
            if (personalization.length != 16)
            {
                throw new IllegalArgumentException(
                        "personalization length must be exactly 16 bytes");
            }
            this.personalization = new byte[16];
            arraycopy(personalization, 0, this.personalization, 0,
                    personalization.length
            );
        }

        if (key != null)
        {
            this.key = new byte[key.length];
            arraycopy(key, 0, this.key, 0, key.length);

            if (key.length > 64)
            {
                throw new IllegalArgumentException(
                        "Keys > 64 are not supported");
            }
            keyLength = key.length;
            arraycopy(key, 0, buffer, 0, key.length);
            bufferPos = BLOCK_LENGTH_BYTES; // zero padding
        }

        init();
    }

    /**
     * update the message digest with a single byte.
     *
     * @param b the input byte to be entered.
     */
    public void update(final byte b)
    {
        // left bytes of buffer
        // process the buffer if full else add to buffer:
        final int remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
        if (remainingLength == 0)
        { // full buffer
            t0 += BLOCK_LENGTH_BYTES;
            if (t0 == 0)
            { // if message > 2^64
                t1++;
            }
            compress(buffer, 0);
            Arrays.fill(buffer, (byte) 0);// clear buffer
            buffer[0] = b;
            bufferPos = 1;
        }
        else
        {
            buffer[bufferPos] = b;
            bufferPos++;
        }
    }

    /**
     * update the message digest with a block of bytes.
     *
     * @param message the byte array containing the data.
     * @param offset  the offset into the byte array where the data starts.
     * @param len     the length of the data.
     */
    public void update(byte[] message, int offset, int len)
    {

        if (null == message || 0 == len)
        {
            return;
        }

        int remainingLength = 0; // left bytes of buffer

        if (0 != bufferPos)
        { // commenced, incomplete buffer

            // complete the buffer:
            remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
            if (remainingLength < len)
            { // full buffer + at least 1 byte
                arraycopy(message, offset, buffer, bufferPos,
                        remainingLength
                );

                t0 += BLOCK_LENGTH_BYTES;

                if (0 == t0)
                { // if message > 2^64
                    t1++;
                }

                compress(buffer, 0);

                bufferPos = 0;

                Arrays.fill(buffer, (byte) 0);// clear buffer
            }
            else
            {
                arraycopy(message, offset, buffer, bufferPos, len);

                bufferPos += len;

                return;
            }
        }

        // process blocks except last block (also if last block is full)
        int messagePos;
        final int blockWiseLastPos = offset + len - BLOCK_LENGTH_BYTES;

        // block wise 128 bytes
        for (messagePos = offset + remainingLength; messagePos < blockWiseLastPos; messagePos += BLOCK_LENGTH_BYTES)
        {
            // without buffer:
            t0 += BLOCK_LENGTH_BYTES;

            if (0 == t0)
            {
                t1++;
            }

            compress(message, messagePos);
        }

        // fill the buffer with left bytes, this might be a full block
        arraycopy(message, messagePos, buffer, 0, offset + len - messagePos);

        bufferPos += (offset + len) - messagePos;
    }

    /**
     * close the digest, producing the final digest value. The digest
     * call leaves the digest reset.
     * Key, salt and personal string remain.
     *
     * @param out       the array the digest is to be copied into.
     * @param outOffset the offset into the out array the digest is to start at.
     * @return length of the digest
     */
    public int digest(final byte[] out, final int outOffset)
    {

        f0 = F_0;
        t0 += bufferPos;

        if (0 < bufferPos && 0 == t0)
        {
            t1++;
        }

        compress(buffer, 0);
        Arrays.fill(buffer, (byte) 0);// Holds eventually the key if input is null
        Arrays.fill(internalState, 0L);

        for (int i = 0; i < chainValue.length && (i * 8 < digestSize); i++)
        {
            byte[] bytes = long2bytes(chainValue[i]);

            if ((i * 8) < (digestSize - 8))
            {
                arraycopy(bytes, 0, out, outOffset + (i * 8), 8);
            }
            else
            {
                arraycopy(bytes, 0, out, outOffset + (i * 8), digestSize - (i * 8));
            }
        }

        Arrays.fill(chainValue, 0L);

        reset();

        return digestSize;
    }

    /**
     * Reset the digest back to it's initial state.
     * The key, the salt and the personal string will
     * remain for further computations.
     */
    public void reset()
    {
        bufferPos = 0;
        f0 = 0L;
        t0 = 0L;
        t1 = 0L;
        chainValue = null;

        Arrays.fill(buffer, (byte) 0);

        if (key != null)
        {
            arraycopy(key, 0, buffer, 0, key.length);
            bufferPos = BLOCK_LENGTH_BYTES; // zero padding
        }

        init();
    }

    /**
     * return the size, in bytes, of the digest produced by this message digest.
     *
     * @return the size, in bytes, of the digest produced by this message digest.
     */
    public int getDigestSize()
    {
        return digestSize;
    }

    /**
     * Return the size in bytes of the internal buffer the digest applies it's compression
     * function to.
     *
     * @return byte length of the digests internal buffer.
     */
    public int getByteLength()
    {
        return BLOCK_LENGTH_BYTES;
    }

    /**
     * Overwrite the key
     * if it is no longer used (zeroization)
     */
    public void clearKey()
    {
        if (null != key)
        {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(buffer, (byte) 0);
        }
    }

    /**
     * Overwrite the salt (pepper) if it
     * is secret and no longer used (zeroization)
     */
    public void clearSalt()
    {
        if (null != salt)
        {
            Arrays.fill(salt, (byte) 0);
        }
    }

    // initialize chainValue
    private void init()
    {
        if (null == chainValue)
        {
            final long[] newChainValue = new long[8];

            newChainValue[0] = BLAKE2B_IV[0]
                    ^ (digestSize | (keyLength << 8) | 0x1010000);

            newChainValue[1] = BLAKE2B_IV[1];
            newChainValue[2] = BLAKE2B_IV[2];
            newChainValue[3] = BLAKE2B_IV[3];
            newChainValue[4] = BLAKE2B_IV[4];
            newChainValue[5] = BLAKE2B_IV[5];

            if (null != salt)
            {
                newChainValue[4] ^= (bytes2long(salt, 0));
                newChainValue[5] ^= (bytes2long(salt, 8));
            }

            newChainValue[6] = BLAKE2B_IV[6];
            newChainValue[7] = BLAKE2B_IV[7];

            if (null != personalization)
            {
                newChainValue[6] ^= (bytes2long(personalization, 0));
                newChainValue[7] ^= (bytes2long(personalization, 8));
            }

            chainValue = newChainValue;
        }
    }

    private void initializeInternalState()
    {
        // initialize v:
        arraycopy(chainValue, 0, internalState, 0, chainValue.length);
        arraycopy(BLAKE2B_IV, 0, internalState, chainValue.length, 4);

        internalState[12] = t0 ^ BLAKE2B_IV[4];
        internalState[13] = t1 ^ BLAKE2B_IV[5];
        internalState[14] = f0 ^ BLAKE2B_IV[6];
        internalState[15] = BLAKE2B_IV[7];// ^ f1 with f1 = 0
    }

    private void compress(byte[] message, int messagePos)
    {

        initializeInternalState();

        long[] m = new long[16];

        for (int j = 0; j < 16; j++)
        {
            m[j] = bytes2long(message, messagePos + j * 8);
        }

        for (int round = 0; round < ROUNDS; round++)
        {
            // G apply to columns of internalState:m[BLAKE2B_SIGMA[round][2 * blockPos]] /+1
            G(m[BLAKE2B_SIGMA[round][0]], m[BLAKE2B_SIGMA[round][1]], 0, 4, 8, 12);
            G(m[BLAKE2B_SIGMA[round][2]], m[BLAKE2B_SIGMA[round][3]], 1, 5, 9, 13);
            G(m[BLAKE2B_SIGMA[round][4]], m[BLAKE2B_SIGMA[round][5]], 2, 6, 10, 14);
            G(m[BLAKE2B_SIGMA[round][6]], m[BLAKE2B_SIGMA[round][7]], 3, 7, 11, 15);
            // G apply to diagonals of internalState:
            G(m[BLAKE2B_SIGMA[round][8]], m[BLAKE2B_SIGMA[round][9]], 0, 5, 10, 15);
            G(m[BLAKE2B_SIGMA[round][10]], m[BLAKE2B_SIGMA[round][11]], 1, 6, 11, 12);
            G(m[BLAKE2B_SIGMA[round][12]], m[BLAKE2B_SIGMA[round][13]], 2, 7, 8, 13);
            G(m[BLAKE2B_SIGMA[round][14]], m[BLAKE2B_SIGMA[round][15]], 3, 4, 9, 14);
        }

        // update chain values:
        for (int offset = 0; offset < chainValue.length; offset++)
        {
            chainValue[offset] = chainValue[offset] ^ internalState[offset] ^ internalState[offset + 8];
        }
    }

    private void G(long m1, long m2, int posA, int posB, int posC, int posD)
    {
        internalState[posA] = internalState[posA] + internalState[posB] + m1;
        internalState[posD] = rotr64(internalState[posD] ^ internalState[posA], 32);
        internalState[posC] = internalState[posC] + internalState[posD];
        internalState[posB] = rotr64(internalState[posB] ^ internalState[posC], 24);
        internalState[posA] = internalState[posA] + internalState[posB] + m2;
        internalState[posD] = rotr64(internalState[posD] ^ internalState[posA], 16);
        internalState[posC] = internalState[posC] + internalState[posD];
        internalState[posB] = rotr64(internalState[posB] ^ internalState[posC], 63);
    }


    static byte[] cloneByteArray(byte[] data)
    {
        if (data == null)
        {
            return null;
        }

        final byte[] copy = new byte[data.length];

        arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    static long[] cloneByteArray(long[] data)
    {
        if (data == null)
        {
            return null;
        }

        final long[] copy = new long[data.length];

        arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    static long bytes2long(final byte[] byteArray, final int offset)
    {
        return (((long) byteArray[offset] & 0xFF)
                | (((long) byteArray[offset + 1] & 0xFF) << 8)
                | (((long) byteArray[offset + 2] & 0xFF) << 16)
                | (((long) byteArray[offset + 3] & 0xFF) << 24)
                | (((long) byteArray[offset + 4] & 0xFF) << 32)
                | (((long) byteArray[offset + 5] & 0xFF) << 40)
                | (((long) byteArray[offset + 6] & 0xFF) << 48)
                | (((long) byteArray[offset + 7] & 0xFF) << 56));
    }

    // convert one long value in byte array
    // little-endian byte order!
    static byte[] long2bytes(final long longValue)
    {
        return new byte[]
                {(byte) longValue, (byte) (longValue >> 8),
                        (byte) (longValue >> 16), (byte) (longValue >> 24),
                        (byte) (longValue >> 32), (byte) (longValue >> 40),
                        (byte) (longValue >> 48), (byte) (longValue >> 56)
                };
    }

    static long rotr64(final long x, final int rot)
    {
        return x >>> rot | (x << (64 - rot));
    }

}
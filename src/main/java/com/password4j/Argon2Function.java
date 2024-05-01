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

import com.password4j.types.Argon2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;


/**
 * Class containing the implementation of Argon2 function and its parameters.
 *
 * @author David Bertoldi
 * @see <a href="https://en.wikipedia.org/wiki/Argon2">Argon2</a>
 * @since 1.5.0
 */
public class Argon2Function extends AbstractHashingFunction
{
    public static final int ARGON2_VERSION_10 = 0x10;

    public static final int ARGON2_VERSION_13 = 0x13;

    public static final int ARGON2_INITIAL_DIGEST_LENGTH = 64;

    public static final int ARGON2_ADDRESSES_IN_BLOCK = 128;

    private static final ConcurrentMap<String, Argon2Function> INSTANCES = new ConcurrentHashMap<>();

    private static final int ARGON2_SYNC_POINTS = 4;

    private static final int ARGON2_INITIAL_SEED_LENGTH = 72;

    private static final int ARGON2_BLOCK_SIZE = 1024;

    public static final int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;
    private final int iterations;
    private final int memory;
    private final long[][] initialBlockMemory;
    private final int parallelism;
    private final int outputLength;
    private final int segmentLength;
    private final Argon2 variant;
    private final int version;
    private final int laneLength;
    private ExecutorService service;

    Argon2Function(int memory, int iterations, int parallelism, int outputLength, Argon2 variant, int version)
    {
        this.variant = variant;
        this.iterations = iterations;
        this.memory = memory;
        this.parallelism = parallelism;
        this.outputLength = outputLength;
        this.version = version;

        int memoryBlocks = this.memory;

        if (this.memory < 2 * ARGON2_SYNC_POINTS * parallelism)
        {
            memoryBlocks = 2 * ARGON2_SYNC_POINTS * parallelism;
        }

        segmentLength = memoryBlocks / (parallelism * ARGON2_SYNC_POINTS);
        this.laneLength = segmentLength * ARGON2_SYNC_POINTS;

        memoryBlocks = segmentLength * (parallelism * ARGON2_SYNC_POINTS);

        initialBlockMemory = new long[memoryBlocks][ARGON2_QWORDS_IN_BLOCK];
        for (int i = 0; i < memoryBlocks; i++)
        {
            initialBlockMemory[i] = new long[ARGON2_QWORDS_IN_BLOCK];
        }

        if (parallelism >= 1)
        {
            service = Utils.createExecutorService();
        }
    }

    /**
     * Creates a singleton instance, depending on the provided
     * memory (KiB), number of iterations, parallelism, length og the output and type.
     *
     * @param memory       memory (KiB)
     * @param iterations   number of iterations
     * @param parallelism  level of parallelism
     * @param outputLength length of the final hash
     * @param type         argon2 type (i, d or id)
     * @return a singleton instance
     * @since 1.5.0
     */
    public static Argon2Function getInstance(int memory, int iterations, int parallelism, int outputLength, Argon2 type)
    {
        return getInstance(memory, iterations, parallelism, outputLength, type, ARGON2_VERSION_13);
    }

    /**
     * Creates a singleton instance, depending on the provided
     * logarithmic memory, number of iterations, parallelism, lenght og the output, type and version.
     *
     * @param memory       logarithmic memory
     * @param iterations   number of iterations
     * @param parallelism  level of parallelism
     * @param outputLength length of the final hash
     * @param type         argon2 type (i, d or id)
     * @param version      version of the algorithm (16 or 19)
     * @return a singleton instance
     * @since 1.5.0
     */
    public static Argon2Function getInstance(int memory, int iterations, int parallelism, int outputLength, Argon2 type,
                                             int version)
    {
        String key = getUID(memory, iterations, parallelism, outputLength, type, version);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            Argon2Function function = new Argon2Function(memory, iterations, parallelism, outputLength, type, version);
            INSTANCES.put(key, function);
            return function;
        }
    }

    /**
     * Reads the configuration contained in the given hash and
     * builds a singleton instance based on these configurations.
     *
     * @param hashed an already hashed password
     * @return a singleton instance based on the given hash
     * @since 1.5.0
     */
    public static Argon2Function getInstanceFromHash(String hashed)
    {
        Object[] params = decodeHash(hashed);
        Argon2 type = Argon2.valueOf(((String) params[0]).toUpperCase());
        int version = (int) params[1];
        int memory = (int) params[2];
        int iterations = (int) params[3];
        int parallelism = (int) params[4];
        int outputLength = ((byte[]) params[6]).length;
        return getInstance(memory, iterations, parallelism, outputLength, type, version);
    }

    protected static String getUID(int memory, int iterations, int parallelism, int outputLength, Argon2 type, int version)
    {
        return memory + "|" + iterations + "|" + parallelism + "|" + outputLength + "|" + type.ordinal() + "|" + version;
    }

    private static byte[] getInitialHashLong(byte[] initialHash, byte[] appendix)
    {
        byte[] initialHashLong = new byte[ARGON2_INITIAL_SEED_LENGTH];

        System.arraycopy(initialHash, 0, initialHashLong, 0, ARGON2_INITIAL_DIGEST_LENGTH);
        System.arraycopy(appendix, 0, initialHashLong, ARGON2_INITIAL_DIGEST_LENGTH, 4);

        return initialHashLong;
    }

    private static void updateWithLength(Blake2b blake2b, byte[] input)
    {
        if (input != null)
        {
            blake2b.update(Utils.intToLittleEndianBytes(input.length));
            blake2b.update(input);
        }
        else
        {
            blake2b.update(Utils.intToLittleEndianBytes(0));
        }
    }

    private static int getStartingIndex(int pass, int slice)
    {
        if ((pass == 0) && (slice == 0))
        {
            return 2;
        }
        else
        {
            return 0;
        }
    }

    private static void nextAddresses(long[] zeroBlock, long[] inputBlock, long[] addressBlock)
    {
        inputBlock[6]++;
        fillBlock(zeroBlock, inputBlock, addressBlock, false);
        fillBlock(zeroBlock, addressBlock, addressBlock, false);
    }

    private static void fillBlock(long[] x, long[] y, long[] currentBlock, boolean withXor)
    {

        long[] r = new long[ARGON2_QWORDS_IN_BLOCK];
        long[] z = new long[ARGON2_QWORDS_IN_BLOCK];

        Utils.xor(r, x, y);
        System.arraycopy(r, 0, z, 0, z.length);

        for (int i = 0; i < 8; i++)
        {

            roundFunction(z, 16 * i, 16 * i + 1, 16 * i + 2, 16 * i + 3, 16 * i + 4, 16 * i + 5, 16 * i + 6, 16 * i + 7,
                    16 * i + 8, 16 * i + 9, 16 * i + 10, 16 * i + 11, 16 * i + 12, 16 * i + 13, 16 * i + 14, 16 * i + 15);
        }

        for (int i = 0; i < 8; i++)
        {

            roundFunction(z, 2 * i, 2 * i + 1, 2 * i + 16, 2 * i + 17, 2 * i + 32, 2 * i + 33, 2 * i + 48, 2 * i + 49, 2 * i + 64,
                    2 * i + 65, 2 * i + 80, 2 * i + 81, 2 * i + 96, 2 * i + 97, 2 * i + 112, 2 * i + 113);

        }

        if (withXor)
        {
            Utils.xor(currentBlock, r, z, currentBlock);
        }
        else
        {
            Utils.xor(currentBlock, r, z);
        }
    }

    private static void roundFunction(long[] block, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8,
                                      int v9, // NOSONAR
                                      int v10, int v11, int v12, int v13, int v14, int v15)
    {
        f(block, v0, v4, v8, v12);
        f(block, v1, v5, v9, v13);
        f(block, v2, v6, v10, v14);
        f(block, v3, v7, v11, v15);

        f(block, v0, v5, v10, v15);
        f(block, v1, v6, v11, v12);
        f(block, v2, v7, v8, v13);
        f(block, v3, v4, v9, v14);
    }

    private static void f(long[] block, int a, int b, int c, int d)
    {
        fBlaMka(block, a, b);
        rotr64(block, d, a, 32);

        fBlaMka(block, c, d);
        rotr64(block, b, c, 24);

        fBlaMka(block, a, b);
        rotr64(block, d, a, 16);

        fBlaMka(block, c, d);
        rotr64(block, b, c, 63);
    }

    private static void fBlaMka(long[] block, int x, int y)
    {
        final long m = 0xFFFFFFFFL;
        final long xy = (block[x] & m) * (block[y] & m);

        block[x] = block[x] + block[y] + 2 * xy;
    }

    private static void rotr64(long[] block, int v, int w, long c)
    {
        final long temp = block[v] ^ block[w];
        block[v] = (temp >>> c) | (temp << (64 - c));
    }

    private static Object[] decodeHash(String hash)
    {
        Object[] result = new Object[7];
        String[] parts = hash.split("\\$");
        if (parts.length == 6)
        {
            result[0] = remove(parts[1], "argon2");
            String[] params = parts[3].split(",");
            result[1] = Integer.parseInt(remove(parts[2], "v="));
            result[2] = Integer.parseInt(remove(params[0], "m="));
            result[3] = Integer.parseInt(remove(params[1], "t="));
            result[4] = Integer.parseInt(remove(params[2], "p="));
            result[5] = Utils.decodeBase64(parts[4]);
            result[6] = Utils.decodeBase64(parts[5]);
            return result;
        }
        else
        {
            throw new BadParametersException("Invalid hashed value");
        }

    }

    protected static String toString(int memory, int iterations, int parallelism, int outputLength, Argon2 type, int version)
    {
        return "m=" + memory + ", i=" + iterations + ", p=" + parallelism + ", l=" + outputLength + ", t=" + type
                .name() + ", v=" + version;
    }

    private static String remove(String source, String remove)
    {
        return source.substring(remove.length());
    }

    @Override
    public Hash hash(CharSequence plainTextPassword)
    {
        byte[] salt = SaltGenerator.generate();
        return internalHash(Utils.fromCharSequenceToBytes(plainTextPassword), salt, null);
    }

    @Override
    public Hash hash(byte[] plainTextPassword)
    {
        byte[] salt = SaltGenerator.generate();
        return internalHash(plainTextPassword, salt, null);
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt)
    {
        return hash(plainTextPassword, salt, null);
    }

    @Override
    public Hash hash(byte[] plainTextPassword, byte[] salt)
    {
        return hash(plainTextPassword, salt, null);
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt, CharSequence pepper)
    {
        return internalHash(Utils.fromCharSequenceToBytes(plainTextPassword), Utils.fromCharSequenceToBytes(salt), pepper);
    }

    @Override
    public Hash hash(byte[] plainTextPassword, byte[] salt, CharSequence pepper)
    {
        return internalHash(plainTextPassword, salt, pepper);
    }

    private Hash internalHash(byte[] plainTextPassword, byte[] salt, CharSequence pepper)
    {
        long[][] blockMemory = copyOf(initialBlockMemory);

        if (salt == null)
        {
            salt = SaltGenerator.generate();
        }
        initialize(plainTextPassword, salt, Utils.fromCharSequenceToBytes(pepper), null, blockMemory);
        fillMemoryBlocks(blockMemory);
        byte[] hash = ending(blockMemory);
        Hash result = new Hash(this, encodeHash(hash, salt), hash, salt);
        result.setPepper(pepper);
        return result;
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        return check(plainTextPassword, hashed, null, null);
    }

    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed)
    {
        return check(plainTextPassword, hashed, null, null);
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt, CharSequence pepper)
    {
        byte[] plainTextPasswordAsBytes = Utils.fromCharSequenceToBytes(plainTextPassword);
        byte[] saltAsBytes = Utils.fromCharSequenceToBytes(salt);
        byte[] hashedAsBytes = Utils.fromCharSequenceToBytes(hashed);
        return check(plainTextPasswordAsBytes, hashedAsBytes, saltAsBytes, pepper);
    }

    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed, byte[] salt, CharSequence pepper)
    {
        byte[] theSalt;
        if (salt == null || salt.length == 0)
        {
            Object[] params = decodeHash(Utils.fromBytesToString(hashed));
            theSalt = (byte[]) params[5];
        }
        else
        {
            theSalt = salt;
        }

        Hash internalHash = internalHash(plainTextPassword, theSalt, pepper);
        return slowEquals(internalHash.getResultAsBytes(), hashed);
    }

    /**
     * @return the memory in bytes
     * @since 1.5.2
     */
    public int getMemory()
    {
        return memory;
    }

    /**
     * @return the number of iterations
     * @since 1.5.2
     */
    public int getIterations()
    {
        return iterations;
    }

    /**
     * @return the degree of parallelism
     * @since 1.5.2
     */
    public int getParallelism()
    {
        return parallelism;
    }

    /**
     * @return the length of the produced hash
     * @since 1.5.2
     */
    public int getOutputLength()
    {
        return outputLength;
    }

    /**
     * @return the Argon2 variant (i, d, id)
     * @since 1.5.2
     */
    public Argon2 getVariant()
    {
        return variant;
    }

    /**
     * @return the version of the algorithm
     * @since 1.5.2
     */
    public int getVersion()
    {
        return version;
    }

    private void initialize(byte[] plainTextPassword, byte[] salt, byte[] secret, byte[] additional, long[][] blockMemory)
    {
        Blake2b blake2b = new Blake2b(ARGON2_INITIAL_DIGEST_LENGTH);

        blake2b.update(Utils.intToLittleEndianBytes(parallelism));
        blake2b.update(Utils.intToLittleEndianBytes(outputLength));
        blake2b.update(Utils.intToLittleEndianBytes(memory));
        blake2b.update(Utils.intToLittleEndianBytes(iterations));
        blake2b.update(Utils.intToLittleEndianBytes(version));
        blake2b.update(Utils.intToLittleEndianBytes(variant.ordinal()));

        updateWithLength(blake2b, plainTextPassword);

        updateWithLength(blake2b, salt);

        updateWithLength(blake2b, secret);

        updateWithLength(blake2b, additional);

        byte[] initialHash = new byte[64];
        blake2b.doFinal(initialHash, 0);

        final byte[] zeroBytes = {0, 0, 0, 0};
        final byte[] oneBytes = {1, 0, 0, 0};

        byte[] initialHashWithZeros = getInitialHashLong(initialHash, zeroBytes);
        byte[] initialHashWithOnes = getInitialHashLong(initialHash, oneBytes);

        for (int i = 0; i < parallelism; i++)
        {

            byte[] iBytes = Utils.intToLittleEndianBytes(i);

            System.arraycopy(iBytes, 0, initialHashWithZeros, ARGON2_INITIAL_DIGEST_LENGTH + 4, 4);
            System.arraycopy(iBytes, 0, initialHashWithOnes, ARGON2_INITIAL_DIGEST_LENGTH + 4, 4);

            byte[] blockHashBytes = blake2bLong(initialHashWithZeros, ARGON2_BLOCK_SIZE);
            blockMemory[i * laneLength] = Utils.fromBytesToLongs(blockHashBytes);

            blockHashBytes = blake2bLong(initialHashWithOnes, ARGON2_BLOCK_SIZE);
            blockMemory[i * laneLength + 1] = Utils.fromBytesToLongs(blockHashBytes);
        }

    }

    private byte[] blake2bLong(byte[] input, int outputLength)
    {

        byte[] result = new byte[outputLength];
        byte[] outlenBytes = Utils.intToLittleEndianBytes(outputLength);

        int blake2bLength = 64;

        if (outputLength <= blake2bLength)
        {
            result = simpleBlake2b(input, outlenBytes, outputLength);
        }
        else
        {
            byte[] outBuffer;

            outBuffer = simpleBlake2b(input, outlenBytes, blake2bLength);
            System.arraycopy(outBuffer, 0, result, 0, blake2bLength / 2);

            int r = (outputLength / 32) + (outputLength % 32 == 0 ? 0 : 1) - 2;

            int position = blake2bLength / 2;
            for (int i = 2; i <= r; i++, position += blake2bLength / 2)
            {

                outBuffer = simpleBlake2b(outBuffer, null, blake2bLength);
                System.arraycopy(outBuffer, 0, result, position, blake2bLength / 2);
            }

            int lastLength = outputLength - 32 * r;

            outBuffer = simpleBlake2b(outBuffer, null, lastLength);
            System.arraycopy(outBuffer, 0, result, position, lastLength);
        }

        return result;
    }

    private byte[] simpleBlake2b(byte[] input, byte[] outlenBytes, int outputLength)
    {
        Blake2b blake2b = new Blake2b(outputLength);

        if (outlenBytes != null)
            blake2b.update(outlenBytes);
        blake2b.update(input);

        byte[] buff = new byte[outputLength];
        blake2b.doFinal(buff, 0);
        return buff;
    }

    private void fillMemoryBlocks(long[][] blockMemory)
    {
        if (parallelism == 1)
        {
            fillMemoryBlockSingleThreaded(blockMemory);
        }
        else
        {
            fillMemoryBlockMultiThreaded(blockMemory);
        }
    }

    private void fillMemoryBlockSingleThreaded(long[][] blockMemory)
    {
        for (int pass = 0; pass < iterations; pass++)
        {
            for (int slice = 0; slice < ARGON2_SYNC_POINTS; slice++)
            {
                fillSegment(pass, 0, slice, blockMemory);
            }
        }
    }

    private void fillMemoryBlockMultiThreaded(long[][] blockMemory)
    {
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < iterations; i++)
        {
            for (int j = 0; j < ARGON2_SYNC_POINTS; j++)
            {
                for (int k = 0; k < parallelism; k++)
                {
                    int pass = i;
                    int lane = k;
                    int slice = j;

                    Future<?> future = service.submit(() -> fillSegment(pass, lane, slice, blockMemory));

                    futures.add(future);
                }

                try
                {
                    for (Future<?> f : futures)
                    {
                        f.get();
                    }
                }
                catch (InterruptedException | ExecutionException e)
                {
                    clear(blockMemory);
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    private void fillSegment(int pass, int lane, int slice, long[][] blockMemory)
    {

        long[] addressBlock = null;
        long[] inputBlock = null;
        long[] zeroBlock = null;

        boolean dataIndependentAddressing = isDataIndependentAddressing(pass, slice);
        int startingIndex = getStartingIndex(pass, slice);
        int currentOffset = lane * laneLength + slice * segmentLength + startingIndex;
        int prevOffset = getPrevOffset(currentOffset);

        if (dataIndependentAddressing)
        {
            addressBlock = new long[ARGON2_QWORDS_IN_BLOCK];
            zeroBlock = new long[ARGON2_QWORDS_IN_BLOCK];
            inputBlock = new long[ARGON2_QWORDS_IN_BLOCK];

            initAddressBlocks(pass, lane, slice, zeroBlock, inputBlock, addressBlock, blockMemory);
        }

        for (int i = startingIndex; i < segmentLength; i++, currentOffset++, prevOffset++)
        {
            prevOffset = rotatePrevOffset(currentOffset, prevOffset);

            long pseudoRandom = getPseudoRandom(i, addressBlock, inputBlock, zeroBlock, prevOffset, dataIndependentAddressing,
                    blockMemory);
            int refLane = getRefLane(pass, lane, slice, pseudoRandom);
            int refColumn = getRefColumn(pass, slice, i, pseudoRandom, refLane == lane);

            long[] prevBlock = blockMemory[prevOffset];
            long[] refBlock = blockMemory[((laneLength) * refLane + refColumn)];
            long[] currentBlock = blockMemory[currentOffset];

            boolean withXor = isWithXor(pass);
            fillBlock(prevBlock, refBlock, currentBlock, withXor);
        }
    }

    private boolean isDataIndependentAddressing(int pass, int slice)
    {
        return (variant == Argon2.I) || (variant == Argon2.ID && (pass == 0) && (slice < ARGON2_SYNC_POINTS / 2));
    }

    private int getPrevOffset(int currentOffset)
    {
        if (currentOffset % laneLength == 0)
        {

            return currentOffset + laneLength - 1;
        }
        else
        {

            return currentOffset - 1;
        }
    }

    private int rotatePrevOffset(int currentOffset, int prevOffset)
    {
        if (currentOffset % laneLength == 1)
        {
            prevOffset = currentOffset - 1;
        }
        return prevOffset;
    }

    private long getPseudoRandom(int index, long[] addressBlock, long[] inputBlock, long[] zeroBlock, int prevOffset,
                                 boolean dataIndependentAddressing, long[][] blockMemory)
    {
        if (dataIndependentAddressing)
        {
            if (index % ARGON2_ADDRESSES_IN_BLOCK == 0)
            {
                nextAddresses(zeroBlock, inputBlock, addressBlock);
            }
            return addressBlock[index % ARGON2_ADDRESSES_IN_BLOCK];
        }
        else
        {
            return blockMemory[prevOffset][0];
        }
    }

    private int getRefLane(int pass, int lane, int slice, long pseudoRandom)
    {
        int refLane = (int) ((pseudoRandom >>> 32) % parallelism);

        if (pass == 0 && slice == 0)
        {
            refLane = lane;
        }
        return refLane;
    }

    private void initAddressBlocks(int pass, int lane, int slice, long[] zeroBlock, long[] inputBlock, long[] addressBlock,
                                   long[][] blockMemory)
    {
        inputBlock[0] = Utils.intToLong(pass);
        inputBlock[1] = Utils.intToLong(lane);
        inputBlock[2] = Utils.intToLong(slice);
        inputBlock[3] = Utils.intToLong(blockMemory.length);
        inputBlock[4] = Utils.intToLong(iterations);
        inputBlock[5] = Utils.intToLong(variant.ordinal());

        if (pass == 0 && slice == 0)
        {

            nextAddresses(zeroBlock, inputBlock, addressBlock);
        }
    }

    private int getRefColumn(int pass, int slice, int index, long pseudoRandom, boolean sameLane)
    {

        int referenceAreaSize;
        int startPosition;

        if (pass == 0)
        {
            startPosition = 0;

            if (sameLane)
            {
                referenceAreaSize = slice * segmentLength + index - 1;
            }
            else
            {
                referenceAreaSize = slice * segmentLength + ((index == 0) ? (-1) : 0);
            }

        }
        else
        {
            startPosition = ((slice + 1) * segmentLength) % laneLength;

            if (sameLane)
            {
                referenceAreaSize = laneLength - segmentLength + index - 1;
            }
            else
            {
                referenceAreaSize = laneLength - segmentLength + ((index == 0) ? (-1) : 0);
            }
        }

        long relativePosition = pseudoRandom & 0xFFFFFFFFL;

        relativePosition = (relativePosition * relativePosition) >>> 32;
        relativePosition = referenceAreaSize - 1 - (referenceAreaSize * relativePosition >>> 32);

        return (int) (startPosition + relativePosition) % laneLength;
    }

    private boolean isWithXor(int pass)
    {
        return !(pass == 0 || version == ARGON2_VERSION_10);
    }

    private byte[] ending(long[][] blockMemory)
    {

        long[] finalBlock = blockMemory[laneLength - 1];

        for (int i = 1; i < parallelism; i++)
        {
            int lastBlockInLane = i * laneLength + (laneLength - 1);
            Utils.xor(finalBlock, blockMemory[lastBlockInLane]);
        }

        byte[] finalBlockBytes = new byte[ARGON2_BLOCK_SIZE];

        for (int i = 0; i < finalBlock.length; i++)
        {
            byte[] bytes = Utils.longToLittleEndianBytes(finalBlock[i]);
            System.arraycopy(bytes, 0, finalBlockBytes, i * bytes.length, bytes.length);
        }

        byte[] finalResult = blake2bLong(finalBlockBytes, outputLength);

        clear(blockMemory);

        return finalResult;
    }

    private void clear(long[][] blockMemory)
    {
        for (long[] block : blockMemory)
        {
            Arrays.fill(block, 0);
        }
    }

    private long[][] copyOf(long[][] old)
    {
        long[][] current = new long[old.length][ARGON2_QWORDS_IN_BLOCK];
        for (int i = 0; i < old.length; i++)
        {
            System.arraycopy(current[i], 0, old[i], 0, ARGON2_QWORDS_IN_BLOCK);
        }
        return current;
    }

    private String encodeHash(byte[] hash, byte[] salt)
    {
        return "$argon2" + variant.name()
                .toLowerCase() + "$v=" + version + "$m=" + memory + ",t=" + iterations + ",p=" + parallelism + "$"
                + Utils.encodeBase64(salt, false) + "$"
                + Utils.encodeBase64(hash, false);
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
            return true;
        if (!(o instanceof Argon2Function))
            return false;
        Argon2Function other = (Argon2Function) o;
        return iterations == other.iterations //
                && memory == other.memory //
                && parallelism == other.parallelism //
                && outputLength == other.outputLength //
                && version == other.version //
                && variant == other.variant;
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(iterations, memory, parallelism, outputLength, variant, version);
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + '[' + toString(memory, iterations, parallelism, outputLength, variant, version) + ']';
    }
}

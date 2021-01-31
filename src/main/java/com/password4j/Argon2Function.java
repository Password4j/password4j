package com.password4j;

import java.util.Arrays;


public class Argon2Function extends AbstractHashingFunction
{
    private static final int DEFAULT_VERSION = 0x13;

    private static final int DEFAULT_OUTPUT_LENGTH = 32;

    private static final int DEFAULT_MEMORY = 4096;

    private static final int DEFAULT_PARALLELISM = 1;

    private static final Argon2 DEFAULT_VARIANT = Argon2.I;

    private static final int PRE_HASH_LENGTH = 64;

    private static final int ARGON2_SYNC_POINTS = 4;

    public static final int ARGON2_PREHASH_DIGEST_LENGTH = 64;

    private static final int ARGON2_PREHASH_SEED_LENGTH = 72;

    private static final int ARGON2_BLOCK_SIZE = 1024;

    public static final int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

    private int iterations;

    private int memory;

    private long[][] blockMemory;

    private int parallelism;

    private int outputLength;

    private int segmentLength;

    private Argon2 variant;

    private byte[] initialHash;

    private int laneLength;

    private Argon2Function()
    {
        //
    }

    public static Argon2Function getInstance()
    {
        return new Argon2Function();
    }

    protected Argon2Function(Argon2 variant, int iterations, int memory, int parallelism, int outputLength)
    {
        this.variant = variant;
        this.iterations = iterations;
        this.memory = 1 << memory;
        this.parallelism = parallelism;
        this.outputLength = outputLength;

        int memoryBlocks = this.memory;

        if (memoryBlocks < 2 * ARGON2_SYNC_POINTS * parallelism)
        {
            memoryBlocks = 2 * ARGON2_SYNC_POINTS * parallelism;
        }

        segmentLength = memoryBlocks / (parallelism * ARGON2_SYNC_POINTS);
        this.laneLength = segmentLength * ARGON2_SYNC_POINTS;

        memoryBlocks = segmentLength * (parallelism * ARGON2_SYNC_POINTS);

        blockMemory = new long[memoryBlocks][ARGON2_QWORDS_IN_BLOCK];
        for (int i = 0; i < memoryBlocks; i++)
        {
            blockMemory[i] = new long[ARGON2_QWORDS_IN_BLOCK];
        }
    }

    protected void initialize(byte[] plainTextPassword, byte[] salt, byte[] secret, byte[] additional)
    {
        Blake2b blake2b = new Blake2b(ARGON2_PREHASH_DIGEST_LENGTH);

        blake2b.update(Utils.intToLittleEndianBytes(parallelism));
        blake2b.update(Utils.intToLittleEndianBytes(outputLength));
        blake2b.update(Utils.intToLittleEndianBytes(memory));
        blake2b.update(Utils.intToLittleEndianBytes(iterations));
        blake2b.update(Utils.intToLittleEndianBytes(DEFAULT_VERSION));
        blake2b.update(Utils.intToLittleEndianBytes(variant.ordinal()));

        updateWithLength(blake2b, plainTextPassword);

        updateWithLength(blake2b, salt);

        updateWithLength(blake2b, secret);

        updateWithLength(blake2b, additional);

        initialHash = new byte[64];
        blake2b.doFinal(initialHash, 0);

        final byte[] zeroBytes = { 0, 0, 0, 0 };
        final byte[] oneBytes = { 1, 0, 0, 0 };

        byte[] initialHashWithZeros = getInitialHashLong(initialHash, zeroBytes);
        byte[] initialHashWithOnes = getInitialHashLong(initialHash, oneBytes);

        for (int i = 0; i < parallelism; i++)
        {

            byte[] iBytes = Utils.intToLittleEndianBytes(i);

            System.arraycopy(iBytes, 0, initialHashWithZeros, ARGON2_PREHASH_DIGEST_LENGTH + 4, 4);
            System.arraycopy(iBytes, 0, initialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH + 4, 4);

            byte[] blockhashBytes = blake2bLong(initialHashWithZeros, ARGON2_BLOCK_SIZE);
            blockMemory[i * laneLength] = Utils.fromBytesToLongs(blockhashBytes);

            blockhashBytes = blake2bLong(initialHashWithOnes, ARGON2_BLOCK_SIZE);
            blockMemory[i * laneLength + 1] = Utils.fromBytesToLongs(blockhashBytes);
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

            /* Vr+1 */
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

        byte[] buff = new byte[64];
        blake2b.doFinal(buff, 0);
        return buff;
    }

    private static byte[] getInitialHashLong(byte[] initialHash, byte[] appendix)
    {
        byte[] initialHashLong = new byte[ARGON2_PREHASH_SEED_LENGTH];

        System.arraycopy(initialHash, 0, initialHashLong, 0, ARGON2_PREHASH_DIGEST_LENGTH);
        System.arraycopy(appendix, 0, initialHashLong, ARGON2_PREHASH_DIGEST_LENGTH, 4);

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

    @Override
    public Hash hash(CharSequence plainTextPassword)
    {
        return null;
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt)
    {
        return null;
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        return false;
    }

    protected byte[] getInitalHash()
    {
        return initialHash;
    }

    public long[][] getBlockMemory()
    {
        return blockMemory;
    }

    @Override
    public String toString()
    {
        return "Argon2Function{" + "iterations=" + iterations + ",\n memory=" + memory + ",\n parallelism=" + parallelism + ",\n outputLength=" + outputLength + ",\n variant=" + variant
                .ordinal() + ",\n initialHash=" + Arrays.toString(initialHash) + '}';
    }
}

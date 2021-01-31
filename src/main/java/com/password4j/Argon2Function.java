package com.password4j;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;


public class Argon2Function extends AbstractHashingFunction
{
    private boolean CLEAR_MEMORY = true;

    public static final int ARGON2_VERSION_10 = 0x10;

    public static final int ARGON2_VERSION_13 = 0x13;

    private static final int DEFAULT_VERSION = ARGON2_VERSION_13;

    private static final int DEFAULT_OUTPUT_LENGTH = 32;

    private static final int DEFAULT_MEMORY = 12;

    private static final int DEFAULT_PARALLELISM = 1;

    private static final Argon2 DEFAULT_VARIANT = Argon2.I;

    private static final int PRE_HASH_LENGTH = 64;

    private static final int ARGON2_SYNC_POINTS = 4;

    public static final int ARGON2_PREHASH_DIGEST_LENGTH = 64;

    private static final int ARGON2_PREHASH_SEED_LENGTH = 72;

    private static final int ARGON2_BLOCK_SIZE = 1024;

    public static final int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

    public static final int ARGON2_ADDRESSES_IN_BLOCK = 128;

    private int iterations;

    private int memory;

    private long[][] blockMemory;

    private int parallelism;

    private int outputLength;

    private int segmentLength;

    private Argon2 variant;

    private int version;

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

    private static byte[] getInitialHashLong(byte[] initialHash, byte[] appendix)
    {
        byte[] initialHashLong = new byte[ARGON2_PREHASH_SEED_LENGTH];

        System.arraycopy(initialHash, 0, initialHashLong, 0, ARGON2_PREHASH_DIGEST_LENGTH);
        System.arraycopy(appendix, 0, initialHashLong, ARGON2_PREHASH_DIGEST_LENGTH, 4);

        return initialHashLong;
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

    public void fillMemoryBlocks()
    {
        if (parallelism == 1)
        {
            fillMemoryBlockSingleThreaded();
        }
        else
        {
            fillMemoryBlockMultiThreaded();
        }
    }

    private void fillMemoryBlockSingleThreaded()
    {
        for (int pass = 0; pass < iterations; pass++)
        {
            for (int slice = 0; slice < ARGON2_SYNC_POINTS; slice++)
            {
                fillSegment(pass, 0, slice);
            }
        }
    }

    private void fillMemoryBlockMultiThreaded()
    {

        ExecutorService service = Executors.newFixedThreadPool(parallelism);
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

                    Future<?> future = service.submit(() -> fillSegment(pass, lane, slice));

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
                    clear();
                    Thread.currentThread().interrupt();
                }
            }
        }

        service.shutdownNow();
    }

    private void fillSegment(int pass, int lane, int slice)
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

            initAddressBlocks(pass, lane, slice, zeroBlock, inputBlock, addressBlock);
        }

        for (int i = startingIndex; i < segmentLength; i++, currentOffset++, prevOffset++)
        {
            prevOffset = rotatePrevOffset(currentOffset, prevOffset);

            long pseudoRandom = getPseudoRandom(i, addressBlock, inputBlock, zeroBlock, prevOffset, dataIndependentAddressing);
            int refLane = getRefLane(pass, lane, slice, pseudoRandom);
            int refColumn = getRefColumn(pass, lane, slice, i, pseudoRandom, refLane == lane);

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
            boolean dataIndependentAddressing)
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
        int refLane = (int) (((pseudoRandom >>> 32)) % parallelism);

        if ((pass == 0) && (slice == 0))
        {
            /* Can not reference other lanes yet */
            refLane = lane;
        }
        return refLane;
    }

    private void initAddressBlocks(int pass, int lane, int slice, long[] zeroBlock, long[] inputBlock, long[] addressBlock)
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

    private static void nextAddresses(long[] zeroBlock, long[] inputBlock, long[] addressBlock)
    {
        inputBlock[6]++;
        fillBlock(zeroBlock, inputBlock, addressBlock, false);
        fillBlock(zeroBlock, addressBlock, addressBlock, false);
    }

    private int getRefColumn(int pass, int lane, int slice, int index, long pseudoRandom, boolean sameLane)
    {

        int referenceAreaSize;
        int startPosition;

        if (pass == 0)
        {
            startPosition = 0;

            if (sameLane)
            {
                /* The same lane => add current segment */
                referenceAreaSize = slice * segmentLength + index - 1;
            }
            else
            {
                /* pass == 0 && !sameLane => position.slice > 0*/
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

    static void fillBlock(long[] X, long[] Y, long[] currentBlock, boolean withXor)
    {

        long[] R = new long[ARGON2_QWORDS_IN_BLOCK];
        long[] Z = new long[ARGON2_QWORDS_IN_BLOCK];

        Utils.xor(R, X, Y);
        System.arraycopy(R, 0, Z, 0, Z.length);

        for (int i = 0; i < 8; i++)
        {

            roundFunction(Z, 16 * i, 16 * i + 1, 16 * i + 2, 16 * i + 3, 16 * i + 4, 16 * i + 5, 16 * i + 6, 16 * i + 7,
                    16 * i + 8, 16 * i + 9, 16 * i + 10, 16 * i + 11, 16 * i + 12, 16 * i + 13, 16 * i + 14, 16 * i + 15);
        }

        for (int i = 0; i < 8; i++)
        {

            roundFunction(Z, 2 * i, 2 * i + 1, 2 * i + 16, 2 * i + 17, 2 * i + 32, 2 * i + 33, 2 * i + 48, 2 * i + 49, 2 * i + 64,
                    2 * i + 65, 2 * i + 80, 2 * i + 81, 2 * i + 96, 2 * i + 97, 2 * i + 112, 2 * i + 113);

        }

        if (withXor)
        {
            Utils.xor(currentBlock, R, Z, currentBlock);
        }
        else
        {
            Utils.xor(currentBlock, R, Z);
        }
    }

    static void roundFunction(long[] block, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9,
            int v10, int v11, int v12, int v13, int v14, int v15)
    {

        F(block, v0, v4, v8, v12);
        F(block, v1, v5, v9, v13);
        F(block, v2, v6, v10, v14);
        F(block, v3, v7, v11, v15);

        F(block, v0, v5, v10, v15);
        F(block, v1, v6, v11, v12);
        F(block, v2, v7, v8, v13);
        F(block, v3, v4, v9, v14);
    }

    private static void F(long[] block, int a, int b, int c, int d)
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

    private boolean isWithXor(int pass)
    {
        return !(pass == 0 || version == ARGON2_VERSION_10);
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

    private byte[] ending()
    {

        long[] finalBlock = blockMemory[laneLength - 1];

        /* XOR the last blocks */
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

        if (CLEAR_MEMORY)
        {
            clear();
        }

        return finalResult;
    }

    private void clear()
    {
        for (long[] block : blockMemory)
        {
            Arrays.fill(block, 0);
        }
        blockMemory = null;
    }

    @Override
    public Hash hash(CharSequence plainTextPassword)
    {
        return null;
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt)
    {
        byte[] password = Utils.fromCharSequenceToBytes(plainTextPassword);
        initialize(password, salt.getBytes(), null, null);
        fillMemoryBlocks();
        byte[] hash = ending();
        System.out.println(Arrays.toString(hash));
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

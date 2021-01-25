package com.password4j;

public class Argon2Function extends AbstractHashingFunction
{
    private static final int DEFAULT_VERSION = 0x13;

    private static final int DEFAULT_OUTPUT_LENGTH = 32;

    private static final int DEFAULT_MEMORY = 4096;

    private static final int DEFAULT_PARALLELISM = 1;

    private static final Argon2 DEFAULT_VARIANT = Argon2.I;

    private static final int PRE_HASH_LENGTH = 64;


    private int iterations;

    private int memory;

    private int parallelism;

    private int outputLength;

    private Argon2 variant;

    private byte[] initialHash;

    private Argon2Function()
    {
        //
    }

    protected Argon2Function(Argon2 variant, int iterations, int memory, int parallelism, int outputLength)
    {
        this.variant = variant;
        this.iterations = iterations;
        this.memory = memory;
        this.parallelism = parallelism;
        this.outputLength = outputLength;
    }

    private void initialize()
    {
        Blake2b blake2b = new Blake2b(PRE_HASH_LENGTH);

        blake2b.update(Utils.intToLittleEndianBytes(parallelism));
        blake2b.update(Utils.intToLittleEndianBytes(outputLength));
        blake2b.update(Utils.intToLittleEndianBytes(memory));
        blake2b.update(Utils.intToLittleEndianBytes(iterations));
        blake2b.update(Utils.intToLittleEndianBytes(DEFAULT_VERSION));
        blake2b.update(Utils.intToLittleEndianBytes(variant.ordinal()));
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
}

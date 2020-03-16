package com.password4j;

/**
 * Static representation of the commonly supported
 * Hmac variants.
 */
public enum Hmac
{

    SHA1(160, 1), //
    SHA224(224, 2), //
    SHA256(256, 3), //
    SHA384(384, 4), //
    SHA512(512, 5);

    private int bits;

    private int code;

    /**
     * @param bits length of the produced hash
     * @param code uid used by {@link CompressedPBKDF2Function}
     */
    Hmac(int bits, int code)
    {
        this.bits = bits;
        this.code = code;
    }

    /**
     * @return length of the algorithm in bits
     */
    public int bits()
    {
        return bits;
    }

    /**
     * @return the numeric uid used in {@link CompressedPBKDF2Function}
     */
    public int code()
    {
        return code;
    }

    /**
     * Finds the enum associated with the given code
     *
     * @param code a numeric uid that identifies the algorithm
     * @return a {@link Hmac} enum. Null if the code is not present in this enum
     */
    public static Hmac fromCode(int code)
    {
        for (Hmac alg : values())
        {
            if (alg.code() == code)
            {
                return alg;
            }
        }
        return null;
    }

    @Override
    public String toString()
    {
        return "PBKDF2WithHmac" + this.name();
    }
}

package com.password4j;

public enum WithHmac
{

    SHA1(160, 1), //
    SHA224(224, 2), //
    SHA256(256, 3), //
    SHA384(384, 4), //
    SHA512(512, 5);

    private int bits;

    private int code;

    WithHmac(int bits, int code)
    {
        this.bits = bits;
        this.code = code;
    }

    public int bits()
    {
        return bits;
    }

    public int code()
    {
        return code;
    }

    public static WithHmac fromCode(int code)
    {
        for (WithHmac alg : values())
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

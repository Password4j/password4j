package org.password4j;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;


public final class PBKDF2Strategy implements HashingStrategy
{
    private String algorithm = Algorithm.PBKDF2WithHmacSHA512.name();

    private int iterations = 10_000;

    private int length = Algorithm.PBKDF2WithHmacSHA512.getBits();

    public PBKDF2Strategy()
    {

    }

    public PBKDF2Strategy(int iterations, int length)
    {
        this();
        this.iterations = iterations;
        this.length = length;
    }

    public PBKDF2Strategy(String algorithm, int iterations, int length)
    {
        this(iterations, length);
        this.algorithm = algorithm;
    }


    @Override
    public Hash hash(String plain)
    {
        byte[] salt = SaltGenerator.generate();
        return hash(plain, new String(salt));
    }

    @Override
    public Hash hash(String plain, String salt)
    {
        try
        {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
            PBEKeySpec spec = new PBEKeySpec(plain.toCharArray(), salt.getBytes(), iterations, length);
            SecretKey key = secretKeyFactory.generateSecret(spec);
            String params = Long.toString((((long)iterations) << 32) | (length & 0xffffffffL));
            String hash = "$" + Algorithm.valueOf(algorithm).getCode() + "$" +params + "$" + salt + "$" + Base64.getEncoder().encodeToString(key.getEncoded());
            return new Hash(this, hash, salt);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            String message = "`" + algorithm + "` is not a valid algorithm";
            throw new UnsupportedOperationException(message, nsae);
        }
        catch (IllegalArgumentException | InvalidKeySpecException e)
        {
            String message = "Invalid specification with salt=" + salt + ", #iterations=`" + iterations + "` and length=`" + length + "`";
            throw new BadParametersException(message, e);
        }
    }

    @Override
    public boolean check(String password, String hashed)
    {
        throw new UnsupportedOperationException();
    }


    /**
     * Compares two byte arrays in length-constant time. This comparison method
     * is used so that password hashes cannot be extracted from an on-line
     * system using a timing attack and then attacked off-line.
     *
     * @param a the first byte array
     * @param b the second byte array
     * @return true if both byte arrays are the same, false if not
     */
    private static boolean slowEquals(byte[] a, byte[] b)
    {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    public PBKDF2Strategy formattedAs(String format)
    {

        return this;
    }

    public enum Algorithm
    {
        PBKDF2WithHmacSHA1(160, 1), //
        PBKDF2WithHmacSHA224(224, 2), //
        PBKDF2WithHmacSHA256(256, 3), //
        PBKDF2WithHmacSHA384(384, 4), //
        PBKDF2WithHmacSHA512(512, 5);

        private int bits;

        private int code;

        Algorithm(int bits, int code)
        {
            this.bits = bits;
            this.code = code;
        }

        public int getBits()
        {
            return bits;
        }

        public int getCode()
        {
            return code;
        }
    }
}
